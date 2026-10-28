# pgpp — client en ligne de commande de pg_pass_policy

Ce dépôt contient le client en ligne de commande de l'extension PostgreSQL
[`pg_pass_policy`](https://github.com/gliatti/pg_pass_policy), qui se trouve
dans un dépôt séparé. Version minimale de l'extension : **1.0**. Le contrat
technique de l'extension (API SQL, codes d'erreur) est décrit dans
[`docs/SPEC.md`](https://github.com/gliatti/pg_pass_policy/blob/main/docs/SPEC.md).
Les tests d'intégration ont besoin d'une copie du dépôt de l'extension,
désignée par la variable `PG_PASS_POLICY_SRC` (voir [Tests](#tests)).

> [!CAUTION]
> **À la charge de l'exploitation.** `rotate_password()` et `switch_rotation_pair()`
> renvoient le nouveau mot de passe en clair à l'appelant, une seule fois. Le
> serveur ne le stocke ni ne le journalise, mais sa protection en dehors du
> serveur dépend de votre configuration :
>
> - **Transport** : sans TLS, le mot de passe circule en clair sur le réseau.
>   Imposez `hostssl` dans `pg_hba.conf` pour les comptes d'administration, et
>   `sslmode=verify-full` côté client.
> - **Client** : le résultat peut être conservé par l'outil qui l'affiche
>   (défilement du terminal, grilles de résultats de pgAdmin ou DBeaver, logs
>   applicatifs qui écrivent les lignes renvoyées). Préférez
>   `pgpp rotate --vault-kv` ou `--exec`, qui ne passent ni par l'écran ni par une
>   variable d'environnement.
> - **Rôle `pass_policy_admin`** : un membre peut obtenir le mot de passe de tout
>   rôle non privilégié. Accordez-le avec parcimonie.
> - **Superutilisateur** : ajoutez `pg_pass_policy.exempt_roles = 'postgres'`
>   (ou votre compte d'administration) pour ne pas vous verrouiller dehors :
>   pendant la fenêtre de démarrage, tout rôle non exempté est refusé
>   (`57P03`), quelle que soit la méthode (`trust` et `peer` compris). Seule
>   exception, la voie de secours, désactivée par défaut : un
>   superutilisateur listé dans `pg_pass_policy.rescue_roles` et authentifié
>   en `peer` passe (sauf verrou déjà en mémoire partagée, mais **même s'il
>   est verrouillé dans `role_state`** : ce verrou n'est pas encore connu) ;
>   n'y listez qu'un compte d'administration lié à un compte système, avec
>   une ligne `local … peer` dans `pg_hba.conf`. `trust` n'y donne pas accès
>   et la liste est vide par défaut : le refus `57P03` porte un HINT qui
>   rappelle cette voie (« … through peer authentication as a superuser
>   listed in pg_pass_policy.rescue_roles », même texte pour tout client).
>   Un rôle exempté ne peut être ni expiré ni verrouillé par l'extension.

`pgpp` pilote l'extension PostgreSQL `pg_pass_policy` (schéma SQL
`pass_policy`) depuis le terminal : état des mots de passe, rotation,
verrouillage, profils de politique, audit, vérification d'un mot de passe
candidat, maintenance. Il est écrit en Rust (clap, sqlx, tokio, reqwest) et
n'appelle que l'API SQL de l'extension : toute valeur fournie par
l'utilisateur est transmise en paramètre lié, jamais concaténée dans une
requête.

## Installation

Rust (édition 2021, toolchain ≥ 1.80) est nécessaire. Avec rustup :

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
cargo install --path .              # depuis la racine du dépôt
# ou, sans installer :
cargo build --release              # binaire dans target/release/pgpp
```

Le binaire est autonome (TLS fourni par rustls : aucune dépendance à
OpenSSL ni à libpq).

## Connexion à PostgreSQL

`pgpp` se connecte à la base où l'extension est installée (GUC
`pg_pass_policy.database`, `postgres` par défaut) avec un rôle membre de
`pass_policy_admin` (ou superutilisateur). Les commandes de lecture
(`status`, `expiring`, `locked`, `profile list|show`, `audit`,
`failed-attempts`, `worker-status`) fonctionnent aussi avec un simple membre
de `pass_policy_viewer`.

| variable | rôle |
|---|---|
| `DATABASE_URL` | URL complète, par exemple `postgres://pgpp_admin@db.example.net:5432/postgres` |
| `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`, `PGSSLMODE`, `PGAPPNAME` | variables standard, utilisées quand `DATABASE_URL` est absente |
| `PGPASSFILE` | fichier de mots de passe (`~/.pgpass` par défaut), lu quand aucun mot de passe n'est fourni |

Recommandation : ne pas mettre le mot de passe dans l'URL (il finirait dans
l'historique du shell ou dans la liste des processus) et préférer
`PGPASSFILE` ou `~/.pgpass` en mode 0600. L'URL n'est jamais affichée dans
les messages d'erreur. Le journal des requêtes de sqlx est désactivé.

`application_name` vaut `pgpp` sauf s'il est fourni par `DATABASE_URL`
(`?application_name=…`) ou par `PGAPPNAME` : la valeur choisie est conservée
et apparaît dans `pass_policy.audit_log`.

Exemple :

```bash
export DATABASE_URL=postgres://pgpp_admin@127.0.0.1:5432/postgres
export PGPASSFILE=~/.pgpass
pgpp status
```

## Format de sortie et codes de retour

Toutes les commandes acceptent `-f table` (défaut) ou `-f json`. En JSON,
les listes sont des tableaux d'objets et les actions renvoient un objet
(`{"ok":true,...}`), ce qui facilite l'usage dans un script.

| code | signification |
|---|---|
| 0 | succès (pour `check` : mot de passe conforme) |
| 1 | erreur (base injoignable, réseau, refus de l'extension, échec de remise du mot de passe après rotation) ; aussi l'échec d'une requête de vérification Vault avant la rotation (Vault injoignable, erreur TLS, redirection, 5xx ou autre statut non 2xx, jeton refusé par 401 ou 403, y compris un jeton expiré, révoqué ou inconnu, jeton sans droit d'écriture sur le chemin), détecté avant la connexion et sans rien changer côté serveur |
| 2 | erreur d'usage : option inconnue, durée invalide ou nulle, `--set` invalide ou clé répétée, `--limit` < 1, mot de passe de `check` vide ou illisible, rotation sans option de remise, configuration Vault absente ou invalide (`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, chemin `--vault-kv`), `sh` introuvable pour `--exec` ; validation locale, toujours faite avant la connexion et avant toute rotation |
| 3 | mot de passe refusé par `check` (motif `PPP-xxx`) |

Une sortie standard fermée par son lecteur (`pgpp audit | head -1`) n'est
pas une erreur de `pgpp` : il s'arrête sans message, avec le code 0 (`check`
garde son code 0 ou 3). Seule exception, `rotate` / `switch-pair --show`
sans autre remise réussie (`--exec`, Vault) : la sortie standard est alors
le seul canal de remise, le mot de passe est perdu et `pgpp` termine avec
le code 1 en invitant à relancer la rotation.

Les durées (`--within`, `--for`, `--since`) s'écrivent `45s`, `30m`, `12h`,
`14d`, `2w`, ou combinées (`1h30m`). L'unité est obligatoire, une durée
nulle (`0s`, `0d0h`) est refusée (code 2) et le total est borné à 100 ans
(`36500d`) : au-delà, la durée est refusée (code 2) au lieu d'être tronquée
en silence.

## Commandes

### État des rôles

```bash
pgpp status                      # vue v_role_status : tous les rôles LOGIN
pgpp status --role app_user      # un seul rôle (erreur si absent)
pgpp status -f json | jq '.[] | select(.status != "ok")'
pgpp expiring                    # vue v_expiring : expiry_state warning / grace / expired, hors rôles exemptés
pgpp expiring --within 14d       # idem + rôles non exemptés qui expirent dans moins de 14 jours
pgpp locked                      # rôles verrouillés (mêmes colonnes que la vue v_locked)
pgpp failed-attempts             # compteurs d'échecs en mémoire partagée
pgpp worker-status               # pid, dernier passage et rechargement du worker, locks_loaded
```

`status` et `expiring` affichent, après `status`, la colonne
`expiry_state` : l'état du mot de passe seul (`ok`, `warning`, `grace`,
`expired`, `never_expires`, `unknown`), que `status` masque par `locked` ou
`exempt`. `expiring` lit la vue `v_expiring` de l'extension : un rôle
verrouillé dont le mot de passe expire y figure (avec `status = locked`), un
rôle exempté (`pg_pass_policy.exempt_roles`) jamais, pas plus qu'avec
`--within`. Avec `--within`, `pgpp` envoie une seule requête : les rôles
de `v_expiring`, lus dans la vue (son filtre n'est pas recopié dans `pgpp`),
ou les rôles non exemptés dont le mot de passe expire avant
`now() + durée`. Ces derniers ne figurent pas tous dans `v_expiring`
(un rôle qui n'est pas encore en `warning` n'y est pas) : la requête lit donc
`v_role_status` et évalue `v_expiring` en sous-requête, soit deux passages
sur la vue. Chaque rôle n'apparaît qu'une fois.

Version de l'extension : `pgpp` exige une version minimale de
`pg_pass_policy`, aujourd'hui `1.0`, la seule publiée (elle fournit les
colonnes `expiry_state` et `is_exempt` de `v_role_status` et la vue
`v_expiring` que lisent `status` et `expiring`). Toute commande (lecture
comme écriture : `status`, `expiring`, `locked`, `audit`, `profile`,
`lock`, `unlock`, `expire`, `rotate`, `switch-pair`, `check`,
`maintenance`, `failed-attempts`, `worker-status`) passe par le même
traitement d'erreur : sur un schéma, une relation, une colonne ou une
fonction inconnus (SQLSTATE `3F000`, `42P01`, `42703`, `42883`), `pgpp`
consulte `pg_extension`, sans analyser le texte du message (traduit selon
`lc_messages`). Si l'extension n'est pas installée, le message devient
`pg_pass_policy is not installed in this database` suivi du message du
serveur. Si elle l'est, l'erreur est affichée telle quelle, sans indice :
une construction de développement antérieure à la publication porte elle
aussi le numéro `1.0` et ne se distingue pas de la version publiée (face à
une telle construction, réinstaller l'extension depuis son dépôt
[`pg_pass_policy`](https://github.com/gliatti/pg_pass_policy), voir son README).
Le message `this pgpp
requires a newer pg_pass_policy (reinstall the extension)` est réservé à
une prochaine version de l'extension dont `pgpp` dépendrait : il ne
s'affiche que face à une version strictement inférieure à la version
minimale (comparée composante par composante comme des nombres).
Ce contrôle est une nouvelle requête, envoyée hors transaction
(celle de `check`, ou toute transaction restée ouverte, est annulée avant)
et bornée à 3 secondes ; s'il échoue
(connexion perdue, par exemple) ou ne répond pas dans ce délai, l'erreur
d'origine est conservée, précédée de `an object of pg_pass_policy is
missing; the installation of the extension could not be checked` et de la
cause.

`worker-status` affiche aussi `locks_loaded` : vrai quand le worker a chargé
les verrous de `role_state` en mémoire partagée (fenêtre de démarrage
fermée). Tant qu'il est faux, les connexions par mot de passe ou secret des
rôles non exemptés sont refusées (SQLSTATE `57P03`, voir le
[README de l'extension](https://github.com/gliatti/pg_pass_policy#readme)).
Avec une version de l'extension qui ne renvoie pas encore
cette colonne, la valeur est vide (`null` en JSON).

### Rotation d'un mot de passe

```bash
pgpp rotate app_user --show                # affiche le mot de passe une seule fois
pgpp rotate app_user --length 32 --show -f json
pgpp rotate app_user --exec 'kubectl create secret generic app-db --from-file=password=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -'
pgpp rotate app_user --vault-kv secret/db/app_user
pgpp rotate app_user --exec '...' --vault-mount kv --vault-kv app --show   # écrit kv/data/app
```

`rotate` appelle `pass_policy.rotate_password(role, length)` : le mot de passe
est généré côté serveur, renvoyé une seule fois et n'apparaît ni dans
l'audit ni dans les journaux. La sortie indique le rôle, le nouveau
`VALID UNTIL` et les canaux de remise utilisés (`delivered_to`). En JSON,
`valid_until` vaut `null` pour un rôle sans limite et `valid_until_known`
(booléen) indique si cette valeur a pu être relue : `false` signifie
« inconnue », pas « illimitée ». `failed` liste les remises échouées (`[]`
si tout a réussi) et `advice` reprend le conseil décrit plus bas (« rotate
again », « do not rotate again », « check Vault before rotating again ») : `null` si aucune remise n'a échoué, ou
si le mot de passe est imprimé (`--show`) sans être dans Vault.

```json
{"role":"app_user","valid_until":"2027-01-25 10:00:00+01","valid_until_known":true,"delivered_to":["vault"],"failed":[],"advice":null}
{"role":"app_user","valid_until":"2027-01-25 10:00:00+01","valid_until_known":true,"delivered_to":["vault"],"failed":["exec"],"advice":"delivered to vault, exec failed: the password is in Vault, do not rotate again"}
```

Politique d'affichage :

- avec `--show`, le mot de passe est imprimé sur la sortie standard
  (`password: …`, ou clé `password` en JSON) ;
- sans `--show` mais avec `--exec` ou `--vault-kv`, il n'est pas affiché :
  il a été remis au processus ou à Vault ;
- sans aucune de ces trois options, la commande est refusée avant la
  rotation, code de retour 2 : le serveur ne renvoie le mot de passe qu'une
  fois, une rotation sans remise le perdrait ;
- les options de remise sont vérifiées avant la connexion et avant la
  rotation : variables `VAULT_ADDR` / `VAULT_TOKEN` présentes, certificat
  `VAULT_CACERT` / `VAULT_CAPATH` lisible, chemin `--vault-kv` bien formé,
  `sh` disponible pour `--exec`, puis jeton accepté par Vault et autorisé à
  écrire le chemin (requêtes `lookup-self` et `capabilities-self`, voir
  « Intégration HashiCorp Vault » ; `--vault-skip-preflight` les supprime).
  Une erreur à ce stade ne change rien côté serveur : code 2 pour une
  erreur de validation locale (chemin, variables, certificats, `sh`), code 1
  pour l'échec d'une requête de vérification vers Vault ;
- si une remise (`--exec`, Vault) échoue malgré cela (Vault devenu
  injoignable, droits insuffisants sur le chemin, commande en erreur ou qui
  n'a pas lu le mot de passe), le mot de passe a déjà été changé côté serveur ; il
  n'est pas affiché sauf `--show` et le code de retour est 1. Le message
  (ligne `password:` de la sortie en table et erreur finale) dit s'il faut
  relancer la rotation :
  - « nothing delivered: rotate again » : aucune remise n'a abouti, le mot
    de passe est perdu, relancer la rotation ;
  - « delivered to vault, exec failed: the password is in Vault, do not
    rotate again » : l'écriture Vault a réussi mais `--exec` a échoué. Le
    mot de passe n'est pas perdu : le reprendre dans Vault pour terminer la
    remise à la main. Une nouvelle rotation remplacerait le secret déjà
    remis et relancerait le hook avec un autre mot de passe ;
  - « delivered to exec, vault failed: rotate again » : seul le hook a reçu
    le mot de passe, Vault ne l'a pas, relancer la rotation une fois Vault
    corrigé ;
  - « the secret may or may not have been written: check Vault before
    rotating again » (précédé de « delivered to exec, vault failed: » si le
    hook a abouti) : l'écriture Vault a échoué après l'envoi du corps de la
    requête (pas de réponse dans le délai de 30 s, connexion coupée en
    attendant ou en lisant la réponse, Ctrl-C pendant la requête). Vault a
    pu enregistrer le secret : le consulter avant de relancer la rotation.
    Une erreur survenue avant l'envoi du corps (nom introuvable, connexion
    refusée ou non établie en 10 s, échec TLS) ou une réponse d'erreur de
    Vault (code HTTP) n'a rien écrit et donne « rotate again ». `pgpp` sait
    si le corps est parti : le client HTTP ne le lit qu'une fois la
    connexion établie et la requête en cours d'envoi ; sans corps complet,
    Vault n'écrit rien. Une fois le corps remis à la connexion, `pgpp` ne
    peut pas savoir si ses octets sont arrivés : le message reste prudent ;

  en JSON, `delivered_to` donne les remises réussies (`["vault"]` dans le
  deuxième cas), `failed` les remises échouées (`["exec"]`) et `advice` le
  même conseil ;
- un Ctrl-C (`SIGINT`) ne tue plus `pgpp` à partir de l'appel SQL de
  rotation : pendant cet appel, `pgpp` l'abandonne et termine avec le code 1
  (le serveur a pu changer le mot de passe : relancer la rotation) ; pendant
  la remise (relecture de `rolvaliduntil`, écriture Vault, hook `--exec`),
  la remise en cours est abandonnée, celles qui restent ne sont pas tentées
  (message « not attempted », y compris pour une écriture Vault
  interrompue avant l'envoi du corps de la requête, pendant la connexion
  par exemple ; une écriture Vault abandonnée après cet envoi a pu, ou non,
  aboutir) et `pgpp` termine comme pour une remise
  échouée (code 1, message « rotate again », « do not rotate again » si
  l'écriture Vault avait abouti, « check Vault before rotating again » si
  elle a été abandonnée en cours de route, mot de passe affiché seulement
  avec `--show`). Un Ctrl-C reçu entre la fin de l'écriture Vault et le
  lancement du hook est lui aussi pris en compte : le hook n'est pas
  lancé ;
- avec `--show`, l'affichage compte comme une remise : s'il échoue (sortie
  standard fermée, par exemple) alors qu'il était la seule remise ou qu'une
  autre remise a échoué, le message le dit (« password could not be
  printed … rotate again ») et le code de retour est 1 ;
- si toutes les remises ont réussi mais que le résultat ne peut pas être
  imprimé (disque plein, par exemple ; une sortie standard fermée reste
  silencieuse, code 0), le code de retour est 1 et le message dit où se
  trouve le mot de passe : « password rotated and delivered to vault; the
  result could not be printed: … ». Il n'y a pas lieu de relancer la
  rotation ;
- si la réponse du serveur à la rotation ne peut pas être lue (mot de passe
  absent ou d'un type inattendu, version incompatible de l'extension), le
  mot de passe a été changé côté serveur mais `pgpp` ne l'a pas : il est
  perdu, le code de retour est 1 et le message le dit (« the password was
  changed on the server … the new password is lost, rotate again ») ;
- si la relecture de `rolvaliduntil` échoue juste après la rotation (connexion
  coupée), un avertissement est émis, `valid_until` vaut `(unknown)` en
  table (une valeur vide y signifie « illimité ») et `null` en JSON, avec
  `valid_until_known: false` pour le distinguer d'un rôle illimité, `PGPP_VALID_UNTIL` n'est pas définie pour `--exec` et la remise a
  lieu quand même : le mot de passe n'est jamais perdu de ce fait.

### Rotation sans coupure d'une paire

```bash
pgpp switch-pair app_pair --show
pgpp switch-pair app_pair --exec 'deploy-credentials.sh' -f json
```

La paire est déclarée au préalable en SQL
(`SELECT pass_policy.create_rotation_pair('app_pair', 'app_a', 'app_b', 'app_group')`,
le rôle de groupe devant exister). `switch-pair` génère un mot de passe pour
le rôle inactif, le rend actif et borne le `VALID UNTIL` de l'ancien à la
période de grâce du profil. La sortie donne `pair`, le rôle désormais actif
(`active_role` en table, `role` en JSON, comme pour `rotate`),
`previous_role`, `previous_valid_until` et `valid_until`. Les options
`--length`, `--show`, `--exec`, `--exec-timeout`, `--vault-kv`,
`--vault-mount` ont le même sens que pour `rotate` ; `--exec` reçoit en plus `PGPP_PAIR` et
`PGPP_PREVIOUS_ROLE`.

### Verrouillage et expiration

```bash
pgpp lock app_user --for 30m --reason "brute force suspected"
pgpp lock app_user                 # jusqu'à unlock explicite (locked_until = infinity)
pgpp unlock app_user               # déverrouille et remet le compteur d'échecs à zéro
pgpp expire app_user               # must_change + VALID UNTIL now()
```

`lock` affiche la fin du verrouillage renvoyée par `lock_role()`
(`infinity` pour un verrouillage manuel) et `locked` lit la vue `v_locked`,
qui joint `pass_policy.role_state` par l'OID du rôle. La colonne `role_name`
de `role_state` n'est en effet mise à jour qu'au passage suivant de la
maintenance après un `ALTER ROLE … RENAME` ; avec une version de l'extension
antérieure à cette jointure (vue jointe par nom),
`pgpp locked` laisse `locked_by` et `lock_reason` vides pour un rôle renommé
jusqu'à ce passage.

### Profils de politique

```bash
pgpp profile list
pgpp profile show default
pgpp profile create service --set min_length=20 --set "max_age=30 days" --set max_failures=3
pgpp profile alter service --set min_length=24 --set lock_duration=null
pgpp profile assign app_user service
pgpp profile unassign app_user     # retour au profil default
pgpp profile drop service          # refusé tant qu'un rôle l'utilise
```

Chaque `--set` est un couple `clé=valeur` dont la clé est une colonne de
`pass_policy.profile` (`min_length`, `max_length`, `min_lower`, `min_upper`,
`min_digit`, `min_special`, `min_classes`, `reject_username`,
`reject_dictionary`, `reject_prehashed`, `max_repeat`, `history_count`,
`history_days`, `max_age`, `min_age`, `grace_period`, `warn_before`,
`max_failures`, `failure_window`, `lock_duration`). Les entiers et les
booléens (`true/false`, `on/off`, `yes/no`) sont typés ; un entier ne l'est
que sous sa forme décimale canonique (`16`, `-1`) : `+16`, `016` ou `-0`
restent des chaînes, transmises telles quelles. `null` efface une
valeur optionnelle (`max_age`, `lock_duration`), le reste est transmis tel
quel (intervalles PostgreSQL : `"30 days"`, `"1 hour"`). Les mots-clés `true`,
`false`, `on`, `off`, `yes`, `no` et `null` sont insensibles à la casse (`TRUE`,
`Off`, `NULL` conviennent aussi) ; les autres
valeurs sont transmises sans changement de casse. Une valeur entre
guillemets doubles est toujours une chaîne, transmise sans les guillemets :
`--set 'max_age="90"'` envoie la chaîne `"90"` là où `--set max_age=90` envoie
le nombre 90, et `"null"` ou `"true"` restent des chaînes. Entre les
guillemets, `\"` donne un guillemet littéral et `\\` une barre oblique
inverse littérale (utile pour une valeur qui se termine par une barre :
`"a\\"`) ; tout le reste est conservé tel quel, blancs intérieurs, guillemet
nu et autre barre oblique inverse compris (`"a"b"` donne `a"b`, `"a\nb"`
donne `a\nb`). Changement de comportement : ces deux séquences étaient
auparavant transmises telles quelles (`"a\"b"` donnait `a\"b`, il donne
désormais `a"b`). Hors guillemets, aucune séquence n'est interprétée. Les
guillemets doivent arriver jusqu'à `pgpp` : les protéger du shell par des
apostrophes, comme dans l'exemple. L'ensemble est
envoyé en jsonb à `create_profile()` / `alter_profile()`, qui valident les
clés.

### Audit

```bash
pgpp audit                              # 100 derniers événements
pgpp audit --since 24h --role app_user
pgpp audit --type role_locked --limit 20 -f json
```

Types d'événements : `password_changed`, `password_rejected`, `auth_failed`,
`role_locked`, `role_unlocked`, `expiry_warning`, `password_expired`,
`password_rotated`, `profile_assigned`, `profile_changed`, `pair_switched`,
`valid_until_synced`, `maintenance`.

### Vérifier un mot de passe candidat

```bash
pgpp check app_user                     # invite sans écho sur un terminal
printf '%s\n' "$CANDIDATE" | pgpp check app_user -f json
pass show db/app | pgpp check app_user
```

Le mot de passe est lu sur l'entrée standard (première ligne seulement, sans
attendre la fin de l'entrée ; le `\n` ou `\r\n` final est retiré) ou demandé
sans écho sur un terminal, puis envoyé en paramètre lié à
`pass_policy.check_password(role, password)`. Code 0 si conforme, 3 avec le
motif `PPP-xxx` sinon ; le code 1 est réservé aux erreurs (base injoignable,
erreur de l'extension), ce qui permet à un script de distinguer un refus d'une
panne. Les options de connexion (`DATABASE_URL`, variables `PG*`) sont
analysées avant de demander ou de lire le mot de passe : une
`DATABASE_URL` invalide sort avec le code 1 sans rien attendre sur l'entrée
standard. Le mot de passe est lu avant la connexion : une première ligne vide,
qui n'est pas de l'UTF-8 valide ou qui dépasse 4096 octets sort avec le
code 2 sans se connecter (la lecture s'arrête à la limite, le tampon est
effacé). Il n'est jamais passé en argument de ligne de commande. Un Ctrl-C à
l'invite rétablit l'écho du terminal avant d'interrompre `pgpp`.

Limite connue de l'invite : sur un terminal, `pgpp` rouvre l'entrée standard
par `/dev/stdin` (et non `/dev/tty`, absent sans terminal de contrôle), sans
l'option `O_NOCTTY` que rpassword ne permet pas de passer. Si `pgpp` est
leader de session sans terminal de contrôle et que son entrée standard est
une tty (par exemple `setsid pgpp check app_user < /dev/pts/3`), cette tty
devient le terminal de contrôle de sa session à l'ouverture. La lecture du
mot de passe n'en est pas affectée, mais la session reçoit dès lors les
signaux de ce terminal (`SIGHUP` à sa fermeture, Ctrl-C tapé dessus). Pour
l'éviter, passer le mot de passe par un tube
(`printf '%s\n' "$CANDIDATE" | setsid pgpp check app_user`) plutôt que de
rediriger une tty.

Autre limite de l'invite : la limite de 4096 octets n'y est contrôlée
qu'après la saisie. rpassword lit le terminal caractère par caractère
jusqu'à Entrée, sans borne de longueur, et `pgpp` ne reçoit la ligne qu'une
fois complète : un texte très long collé à l'invite est donc entièrement
gardé en mémoire avant d'être refusé (code 2). Le tampon de rpassword est
effacé à sa libération, mais il grandit par réallocations pendant la
saisie et les copies laissées par chaque réallocation ne sont pas effacées.
Les entrées par tube ou par fichier n'ont pas cette limite : la lecture s'y
arrête à 4096 octets.

Journal du serveur : un paramètre lié n'apparaît pas dans le texte de la
requête, mais PostgreSQL l'écrit dans la ligne `DETAIL:  parameters: …` dès
que `log_statement = 'all'` ou `log_min_duration_statement >= 0` est actif,
selon `log_parameter_max_length` (défaut -1 : tout). Pour
l'éviter, `pgpp check` exécute `SET LOCAL log_parameter_max_length = 0` dans
sa transaction avant d'appeler `check_password` (ainsi que
`SET LOCAL log_parameter_max_length_on_error = 0`, permis à tout rôle, pour le
cas où l'appel échoue). Le premier réglage est réservé au superutilisateur par
défaut : si le serveur le refuse, `pgpp` continue, lit la valeur en vigueur
pour la session et n'affiche un avertissement sur la sortie d'erreur que si
elle n'est pas déjà 0. Deux parades côté serveur, à poser une fois par un
superutilisateur :

```sql
ALTER ROLE pgpp_admin SET log_parameter_max_length = 0;              -- toutes les sessions du rôle ; plus d'avertissement
GRANT SET ON PARAMETER log_parameter_max_length TO pgpp_admin;       -- PostgreSQL 15+ : pgpp le fait lui-même
```

Sans l'une de ces deux mesures, sur un serveur qui journalise toutes les
requêtes, le mot de passe candidat de `pgpp check` finit en clair dans le
journal PostgreSQL.

pgaudit n'est pas concerné par `log_parameter_max_length` : avec
`pgaudit.log_parameter = on`, il écrit les paramètres liés dans sa propre
ligne `AUDIT:`, quel que soit ce réglage. Sur un serveur équipé de pgaudit,
`pgaudit.log_parameter` doit donc rester à `off` pour le rôle qui lance
`pgpp check` (réglage réservé au superutilisateur, que `pgpp` ne modifie pas) :

```sql
ALTER ROLE pgpp_admin SET pgaudit.log_parameter = off;
```

### Maintenance

```bash
pgpp maintenance        # SELECT * FROM pass_policy.run_maintenance()
```

Lance un passage de maintenance (celui du worker) et liste les actions
réalisées : synchronisation des `VALID UNTIL`, alertes, expirations,
déverrouillages automatiques, purge des rôles disparus.

## Intégration `--exec`

Le mot de passe est écrit sur l'entrée standard du processus lancé par
`sh -c -- CMD` (le `--` évite qu'une commande commençant par `-` soit prise
pour une option de `sh`), suivi d'un saut de ligne, puis l'entrée est fermée. La sortie
standard du hook est renvoyée sur la sortie d'erreur de `pgpp` (sa sortie
d'erreur aussi, inchangée) : elle ne se mélange jamais au résultat de `pgpp`,
en particulier au JSON de `-f json`. Il n'est
jamais passé en argument ni en variable d'environnement. Le processus hérite
de l'environnement de `pgpp` (ce qui permet à l'exemple `vault kv put`
ci-dessous de trouver `VAULT_ADDR` / `VAULT_TOKEN`) et reçoit en plus les
variables suivantes :

| variable | contenu |
|---|---|
| `PGPP_ROLE` | rôle dont le mot de passe vient d'être changé (rôle actif pour `switch-pair`) |
| `PGPP_VALID_UNTIL` | nouveau `rolvaliduntil` (texte PostgreSQL, vide si illimité ; non définie si sa relecture a échoué après la rotation, même si `pgpp` en a hérité une) |
| `PGPP_PAIR`, `PGPP_PREVIOUS_ROLE` | uniquement pour `switch-pair` |

Sont des erreurs de remise (code 1, `delivered_to` sans `exec`) : un code de
retour non nul du processus, une erreur d'entrée-sortie en écrivant sur son
entrée (le processus n'a pas reçu le mot de passe et `pgpp` le tue s'il
tourne encore ; un tube fermé par le processus n'en est pas une : `pgpp`
garde une extrémité de lecture, l'écriture aboutit et la ligne non lue est
détectée comme ci-après), un
processus qui se termine sans avoir lu toute la ligne du mot de passe (par
exemple `--exec true`), un hook arrêté par `--exec-timeout` ou par un Ctrl-C
(voir plus bas). `pgpp` garde pour cela sa propre copie de
l'extrémité de lecture du tube et vérifie, une fois le processus terminé,
qu'il n'y reste aucun octet. Le hook doit donc consommer la ligne avant de
se terminer (`cat`, `read -r pw`, `--from-file=/dev/stdin`…). Un hook qui
délègue la lecture à un processus d'arrière-plan (`cat > fichier &`) donne
un résultat non déterministe : selon que ce processus a déjà lu la ligne ou
non quand le hook se termine, la remise est déclarée réussie ou échouée (et
le vidage décrit plus bas peut lui retirer la ligne). Ne le faites pas.

Le hook est lancé dans son propre groupe de processus : `pgpp` peut ainsi
tuer d'un coup `sh` et les sous-processus qu'il a lancés (sauf ceux qui ont
changé de groupe ou de session, avec `setsid` par exemple). Le groupe reçoit
`SIGKILL`, l'attente de sa fin est bornée à 5 s et la remise échoue dans
les cas suivants :

- l'écriture de la ligne échoue, ou ne se termine pas en 30 s. Ce délai ne
  peut être atteint que si la ligne dépasse la capacité du tube (64 Kio sous
  Linux) et que le hook ne la lit pas, ce que la longueur maximale du
  serveur exclut ; l'écriture et l'attente du processus sont menées en
  parallèle, un hook qui se termine sans lire ne bloque donc pas `pgpp` ;
- le hook dure plus que `--exec-timeout` (300 s par défaut ; durée comme
  `90s`, `5m`, `1h`, ou nombre de secondes ; `0` ou `0s` supprime la limite). C'est
  le cas d'un hook qui a fermé son entrée sans se terminer
  (`exec 0<&-; sleep 100000`) ou qui est suspendu (voir ci-dessous). Un
  hook qui a lu toute la ligne et se termine à l'instant où le délai
  expire n'est pas compté comme tué : s'il est déjà terminé quand `pgpp`
  constate le dépassement, sa remise est vérifiée comme d'habitude (code de
  retour, ligne lue) ;
- `pgpp` reçoit un Ctrl-C (`SIGINT`) pendant que le hook tourne : le
  terminal n'envoie ce signal qu'au groupe de `pgpp`, qui le relaie en tuant
  celui du hook, puis termine avec le code 1 (rotation faite, remise
  échouée, comme ci-dessus).

Quelle que soit l'issue (succès, délai dépassé, erreur d'écriture, code de
retour non nul, interruption), `pgpp` vide le tube (octets effacés) avant de
rendre la main : un sous-processus ayant hérité de l'entrée standard et qui
survit au hook n'y trouve plus ce qui restait de la ligne. Ce vidage ne
retire que les octets encore présents dans le tube à ce moment : il ne
garantit rien face à un lecteur qui a quitté le groupe (`setsid`), échappe
donc au `SIGKILL` et a pu lire la ligne avant le vidage.

Hors du groupe de premier plan du terminal, le hook ne peut pas s'en servir
librement : un programme qui lit le terminal (invite de mot de passe de
`sudo`, par exemple) est suspendu par `SIGTTIN`, et un programme qui y écrit
alors que `stty tostop` est actif, ou qui en change les réglages, est
suspendu par `SIGTTOU`. `pgpp` attend alors jusqu'à `--exec-timeout` (ou un
Ctrl-C), puis tue le groupe. Le hook doit donc s'exécuter sans interaction
(`sudo -n`, authentification par clé) ; pour ses messages, désactiver
`tostop` (`stty -tostop`) ou rediriger sa sortie vers un fichier
(`--exec './deploy-hook.sh >>/var/log/deploy-hook.log 2>&1'`).

Conséquence de l'héritage : un hook fourni par un tiers (script de
déploiement d'une autre équipe) reçoit les identifiants de l'opérateur
(`VAULT_TOKEN`, `PGPASSWORD`, `DATABASE_URL`, `PGPASSFILE`…). Pour les lui
cacher, lancer `pgpp` dans un environnement restreint ou nettoyer
l'environnement autour du hook, par exemple
`--exec 'env -u VAULT_TOKEN -u PGPASSWORD ./deploy-hook.sh'` ou
`--exec 'env -i PATH="$PATH" PGPP_ROLE="$PGPP_ROLE" ./deploy-hook.sh'`.

```bash
pgpp rotate app_user --exec 'read -r pw; printf "%s" "$pw" | vault kv put -mount=secret db/app password=-'
pgpp rotate app_user --exec 'umask 077; cat > /etc/app/db.password; systemctl reload app'
```

## Intégration HashiCorp Vault (KV v2)

```bash
export VAULT_ADDR=https://vault.example.net:8200
export VAULT_TOKEN=...                 # jamais sur la ligne de commande
export VAULT_NAMESPACE=team-a          # optionnel (Vault Enterprise)
pgpp rotate app_user --vault-kv secret/db/app_user
pgpp rotate app_user --vault-mount kv --vault-kv db/app_user   # kv/data/db/app_user
```

Sans `--vault-mount`, `--vault-kv` désigne `<mount>/<chemin>` : la première
composante est le point de montage du moteur KV v2 (`secret/db/app_user`
donne le montage `secret` et le chemin `db/app_user`). Avec
`--vault-mount M`, `--vault-kv` est le chemin sous ce montage, **sans** le
montage : `--vault-mount kv --vault-kv kv/app` écrirait dans `kv/data/kv/app`.
Ce cas (chemin qui commence par le montage) déclenche un avertissement sur la
sortie d'erreur, sans être refusé : un tel chemin peut être voulu. L'option
`--vault-mount` sert surtout pour un montage à plusieurs composantes
(`--vault-mount team/kv --vault-kv db/app`). Chaque segment du chemin est vérifié : un segment vide,
`.` ou `..`, ou contenant `?`, `#`, `%`, `\`, une espace ou un caractère de
contrôle est refusé (code 2), sans quoi le secret partirait vers un autre
endpoint que celui saisi. `pgpp` envoie
`POST {VAULT_ADDR}/v1/{mount}/data/{chemin}` avec l'en-tête `X-Vault-Token`
(et `X-Vault-Namespace` le cas échéant) et le corps :

```json
{"data": {"username": "app_user", "password": "…", "rotated_at": "2026-10-27T15:04:05Z"}}
```

Vault crée une nouvelle version du secret. Les erreurs réseau et les réponses
HTTP non 2xx sont remontées avec le statut et le message de Vault, jamais
avec le contenu envoyé.

TLS : la vérification du certificat n'est jamais désactivée (pas de
`VAULT_SKIP_VERIFY`). Les autorités reconnues sont le magasin du système, les
racines webpki embarquées et celles désignées par les variables standard du
client Vault :

| variable | contenu |
|---|---|
| `VAULT_CACERT` | un fichier PEM (un certificat ou une chaîne complète), prioritaire sur `VAULT_CAPATH` |
| `VAULT_CAPATH` | un répertoire de fichiers `*.pem` / `*.crt` / `*.cer` (extension en majuscules ou minuscules), tous chargés (contenu PEM attendu quelle que soit l'extension : un `.cer` binaire DER est refusé) |

`VAULT_ADDR` est une URL sans paramètres (`?…`), sans fragment (`#…`) et
sans identifiants (`user:pass@`), refusée sinon (code 2). Un préfixe de
chemin est conservé (`https://proxy.example.net/vault` donne
`https://proxy.example.net/vault/v1/…`) ; les URL sont construites segment
par segment, jamais par concaténation de texte.

`VAULT_ADDR` doit être en `https://` ; `http://` n'est accepté que vers un
hôte de boucle locale, par exemple un agent Vault local : une adresse IP
littérale (`127.0.0.0/8`, `[::1]`), ou un nom `localhost` (`localhost`,
`localhost.`, ou un nom en `.localhost` comme `vault.localhost`, avec ou
sans point final). Un tel nom, en `http://` comme en `https://`, n'est
jamais résolu (ni `/etc/hosts` ni DNS, qui pourraient le diriger n'importe
où) : la RFC 6761 le réserve à la boucle locale, et le client HTTP se
connecte directement à `127.0.0.1` sur le port de l'URL, en gardant le nom
dans l'en-tête `Host` (et, en `https://`, pour la vérification du
certificat). Un agent Vault qui n'écoute que sur `[::1]` se désigne donc
par `http://[::1]:8200`. Toute autre adresse en clair (y compris
`localhost.example.net` ou `[::ffff:127.0.0.1]`) est refusée (code 2) : le
jeton et le mot de passe y circuleraient sans chiffrement. Pour un cas non
couvert, le contournement reste `--exec` avec le client officiel :
`--exec 'read -r pw; printf "%s" "$pw" | vault kv put -mount=secret db/app password=-'`.

Mandataire HTTP (proxy) : vers une adresse de boucle locale (adresse IP
littérale `127.0.0.0/8` ou `[::1]`, en `http://` comme en `https://`,
ou un nom `localhost` : `localhost`, `localhost.` ou un nom en
`.localhost` comme `vault.localhost`, avec ou sans point final, réservés à
la boucle locale par la RFC 6761, épinglé comme décrit ci-dessus), le client se connecte toujours directement et ignore `HTTP_PROXY`, `HTTPS_PROXY` et `ALL_PROXY` :
un mandataire résoudrait `localhost` de son côté et verrait passer le jeton
(et, en `http://`, le mot de passe) en clair. Vers une adresse distante, les
réglages de mandataire du système s'appliquent (`HTTPS_PROXY`, `NO_PROXY`
compris), comme avec le client officiel : le mandataire relaie alors un
tunnel TLS (`CONNECT`) dont le certificat reste vérifié pour l'hôte de
`VAULT_ADDR`, il voit l'hôte et le port contactés mais pas le contenu.
Un nom qui contient seulement `localhost` (`localhost.example.net`,
`my-localhost`) est une adresse distante.

Les redirections HTTP ne sont jamais suivies : une réponse 301/302/307/308
est une erreur (code 1). Suivre une redirection rejouerait le jeton et le mot
de passe vers l'hôte indiqué par `Location`, ce qui contournerait la règle
ci-dessus. `VAULT_ADDR` doit donc pointer sur l'adresse finale de Vault.

`VAULT_TOKEN` et `VAULT_NAMESPACE`, envoyés en en-têtes HTTP, sont
débarrassés des blancs en début et en fin (un `\n` final recopié d'un fichier
de jeton, par exemple), puis
doivent ne contenir que des caractères ASCII visibles : sinon la commande est
refusée (code 2) par un message qui nomme la variable sans jamais afficher
sa valeur. De même, aucun message d'erreur sur `VAULT_ADDR` ne reprend
l'adresse saisie, qui peut contenir des identifiants.

Toute cette configuration (variables, certificats, chemin) est validée avant
la connexion à PostgreSQL, puis `pgpp` interroge Vault avec le même client
HTTP que pour l'écriture (redirections refusées) :

1. `GET {VAULT_ADDR}/v1/auth/token/lookup-self` (autorisé par la politique
   `default`) : une erreur réseau ou TLS, une redirection, un 401, un 403, un
   5xx ou tout autre statut non 2xx sortent avec le code 1. Vault répond en effet
   403 « permission denied » (jamais 401) à un jeton expiré, révoqué ou
   inconnu : un 403 est donc un refus ;
2. `POST {VAULT_ADDR}/v1/sys/capabilities-self` avec
   `{"paths": ["{mount}/data/{chemin}"]}` : un refus de cette requête (403
   compris) ou des droits sur ce chemin qui ne comprennent ni `root`, ni à
   la fois `create` et `update`, ni `update` seul sur un secret existant
   (étape 3), sortent avec le code 1. `create` écrit la première version du
   secret, `update` toutes les suivantes, donc chaque rotation après la
   première. Un jeton limité à `create` passerait la vérification puis
   serait refusé par Vault après la deuxième rotation, le mot de passe déjà
   changé : il est toujours refusé. `sudo` n'ouvre que les chemins protégés
   et ne donne aucun droit d'écriture : il ne suffit pas. Si la réponse est
   illisible, `pgpp` avertit et tente l'écriture après la rotation ;
3. seulement pour un jeton qui a `update` sans `create` (ni `root`) :
   `GET {VAULT_ADDR}/v1/{mount}/metadata/{chemin}`, qui dit si le secret
   existe déjà (`capabilities-self` ne le dit pas). Un 200 signifie que le
   secret existe : toutes les écritures suivantes sont des mises à jour,
   `update` suffit. Un 404 signifie qu'il n'existe pas encore : sa première
   écriture demande `create`, la commande sort avec le code 1. Toute autre
   réponse (403 quand le jeton n'a pas `read` sur le chemin des
   métadonnées, erreur réseau, redirection) ne permet pas de conclure : la
   règle stricte s'applique et `create` et `update` sont exigés (code 1).
   Le corps des métadonnées est lu puis ignoré, jamais analysé. Cette
   vérification précède l'action sans la garantir : si le secret est
   supprimé (métadonnées comprises) entre le préflight et l'écriture, celle-ci
   demande `create` et Vault la refuse par un 403, après la rotation. Un 403
   ne prouve pas la suppression (le jeton a pu expirer, être révoqué ou
   perdre sa politique depuis le préflight) : `pgpp` relit alors les
   métadonnées. Un 404 confirme la suppression, le message le signale par
   `secret metadata disappeared: the token needs create`. Toute autre
   réponse donne un message prudent, `permission denied since the
   preflight: the token may have expired or been revoked, or its policy may
   have changed`, suivi de ce qu'a répondu cette relecture. Dans tous les
   cas, Vault a répondu à l'écriture : le secret n'a pas été écrit, et ce
   refus est acquis dès la réponse. La relecture vient après, bornée à
   5 secondes ; un Vault qui ne répond pas dans ce délai ou un Ctrl-C
   l'abandonne et donne le même message prudent, suivi de `(no answer
   within 5s)`, de `(interrupted before the check)` (Ctrl-C déjà reçu : la
   relecture n'est pas envoyée) ou de `(interrupted)` (Ctrl-C pendant la
   relecture), jamais « may or may not have been written ».

La seconde requête refuserait à elle seule un jeton expiré ou révoqué ; la
première est gardée volontairement : elle désigne le jeton lui-même comme
cause de l'échec, au prix d'un aller-retour de plus.

Un jeton expiré, révoqué ou inconnu, un jeton sans droit d'écriture sur le
chemin, un Vault injoignable ou une redirection sortent donc avec le code 1
avant toute rotation et avant la connexion à PostgreSQL (le code 2 reste
réservé à la validation locale de la configuration, décrite plus haut). Restent possibles après la rotation : un refus
d'écriture que la vérification n'a pas pu prévoir (réponse illisible de
`capabilities-self`, politique modifiée entre-temps) ou une panne survenue
entre les requêtes (code 1, voir « Politique d'affichage »).

Un jeton créé avec `-no-default-policy` ne peut pas appeler `lookup-self` ni,
en général, `capabilities-self` : il est refusé par la vérification
ci-dessus. Pour un tel jeton, l'option `--vault-skip-preflight` (ou la
variable `PGPP_VAULT_SKIP_PREFLIGHT=1`, ou `true`, `yes`, `on` ; `0`,
`false`, `no`, `off` ou une valeur vide la désactivent ; toute autre valeur
est une erreur d'usage, code 2, signalée seulement avec `--vault-kv` : la
variable peut rester exportée pour les rotations sans Vault) supprime les deux requêtes et affiche un
avertissement. **La validité du jeton et son droit d'écriture ne sont alors
vérifiés qu'après la rotation**, par l'écriture elle-même : un jeton expiré
ou révoqué fait échouer la remise (code 1) alors que le mot de passe a déjà
changé côté serveur, et celui-ci est perdu sans `--show` ou `--exec`.
Combiner cette option avec une seconde remise (`--exec` vers un coffre de
secours) ou relancer la rotation après correction du jeton.

## Sécurité

- Les mots de passe transitent uniquement en paramètres liés
  (`check_password`) ou en résultat de fonction (`rotate_password`,
  `switch_rotation_pair`) : ils n'apparaissent jamais dans le texte des
  requêtes. Les résultats de fonction ne sont pas journalisés par le serveur.
  Le paramètre lié de `check`, lui, est écrit dans la ligne `DETAIL` du
  journal PostgreSQL quand `log_statement = 'all'` ou
  `log_min_duration_statement >= 0` est actif : `pgpp check` neutralise cela
  par `SET LOCAL log_parameter_max_length = 0` quand le rôle y est autorisé
  (voir la section « Vérifier un mot de passe candidat » pour `ALTER ROLE …
  SET` / `GRANT SET ON PARAMETER`), sinon il avertit (l'avertissement ne
  propose `GRANT SET ON PARAMETER` qu'à partir de PostgreSQL 15, version qui
  l'introduit). Ce réglage ne couvre
  pas pgaudit : `pgaudit.log_parameter` doit rester à `off` pour le rôle
  appelant.
- Aucun mot de passe n'est écrit par `pgpp` dans un journal, un message
  d'erreur, une URL ou un argument de processus. Le journal de requêtes de
  sqlx est désactivé.
- Le mot de passe n'est affiché que sur demande explicite (`--show`) ; une
  rotation sans option de remise est refusée avant d'avoir lieu, et une
  configuration de remise invalide (Vault, `--exec`) est détectée avant la
  rotation.
- Le mot de passe reçu est conservé dans un tampon `zeroize` effacé dès que
  la commande n'en a plus besoin, de même que la valeur JSON du secret Vault,
  le corps HTTP sérialisé (alloué une fois à sa taille exacte, effacé quand
  reqwest le libère), la ligne écrite vers `--exec` et la sortie de
  `--show` (texte JSON alloué lui aussi à sa taille exacte, ligne
  `password:` en table), écrite directement sur le descripteur 1 sans
  passer par le tampon de `std::io::stdout()`. Le mot de passe candidat de `check` est
  lu sur une copie du descripteur 0, sans le tampon interne de
  `std::io::stdin()` qui en garderait une copie non effacée : octet par
  octet depuis un tube ou un terminal, par blocs dans un tampon effacé depuis
  un fichier ordinaire (`pgpp check app < fichier`), la position étant alors
  ramenée juste après le premier `\n`.
- Limite de cet effacement : les copies faites par les bibliothèques ne sont
  pas sous le contrôle de `pgpp` et restent en mémoire jusqu'à leur
  réutilisation. Ce sont :
  - pour `rotate` / `switch-pair`, le tampon de réception de sqlx et la
    ligne `PgRow` qui contient le mot de passe renvoyé par le serveur
    (`PgRow` partage ce tampon en lecture seule, `pgpp` ne peut pas
    l'effacer). La colonne est lue telle quelle (`try_get_raw`) et copiée
    une seule fois, à sa taille exacte, dans un tampon effacé ;
  - pour `check`, la ligne `PgRow` ne contient que le motif de refus, mais
    le mot de passe candidat est copié par sqlx dans les arguments liés
    (`PgArguments`, tampon susceptible de grandir par réallocations) puis dans son
    tampon d'envoi, sans effacement ; sur un terminal s'y ajoute la saisie
    de rpassword ;
  - pour Vault, le tampon d'écriture de hyper et les enregistrements TLS de
    rustls (la requête chiffrée ou, en `http://` local, en clair) ; côté
    PostgreSQL, de même, les enregistrements TLS de rustls quand la
    connexion est chiffrée ;
  - pour `--show`, les tampons du terminal ou du tube qui reçoit la sortie,
    hors du processus.

  Un vidage mémoire (core dump, swap) du processus peut donc contenir le mot
  de passe : désactiver les core dumps (`ulimit -c 0`) sur les machines qui
  lancent des rotations.
- Le mot de passe d'un `--exec` passe par un tube vers l'entrée standard du
  processus enfant, jamais par `argv` ni par l'environnement. Le processus
  enfant hérite en revanche de l'environnement de `pgpp` (voir la section
  `--exec`).
- Vault n'est joint qu'en TLS vérifié (ou en clair sur la boucle locale
  uniquement, un nom `localhost` étant épinglé sur `127.0.0.1`), avec `VAULT_CACERT` /
  `VAULT_CAPATH` pour une autorité privée.
- Le rôle de connexion doit être membre de `pass_policy_admin` : les
  vérifications de droits sont faites par les fonctions `SECURITY DEFINER`
  de l'extension (un administrateur non superutilisateur ne peut pas agir sur
  un rôle `SUPERUSER`, `REPLICATION` ou `BYPASSRLS`).

## Limites connues

- Un nom `localhost` (en `http://` comme en `https://`) est épinglé sur
  `127.0.0.1` seul. C'est une décision, sans repli sur `[::1]` : une seule
  adresse, jamais de course entre IPv4 et IPv6 (happy eyeballs), et
  l'adresse jointe est celle qu'on écrit. Un agent Vault qui n'écoute que
  sur `[::1]` n'est donc pas joint (connexion refusée, avec l'indice
  correspondant) : il se désigne par `http://[::1]:PORT`, ou par
  `https://[::1]:PORT`, qui exige alors un certificat portant l'adresse IP
  `::1` dans son SAN (le nom `localhost` n'y suffit pas).
- En fin de commande, `pgpp` annule une transaction restée ouverte par un
  `ROLLBACK` brut, sans mettre à jour le compteur de transactions de sqlx :
  sans effet, la connexion étant fermée juste après.

## Tests

```bash
cargo test                        # tests unitaires + mock Vault + tests sans base ; les tests base sont marqués ignored
```

Les tests d'intégration ont besoin d'une instance PostgreSQL de test où
l'extension est installée et chargée par `shared_preload_libraries` (voir le
[README de l'extension](https://github.com/gliatti/pg_pass_policy#readme),
version 1.0 ou ultérieure). L'extension se compile depuis une copie de son
dépôt, désignée par la variable `PG_PASS_POLICY_SRC` :

```bash
git clone https://github.com/gliatti/pg_pass_policy /chemin/vers/pg_pass_policy
export PG_PASS_POLICY_SRC=/chemin/vers/pg_pass_policy
make -C "$PG_PASS_POLICY_SRC" install   # PG_CONFIG=/chemin/vers/pg_config si besoin
```

Puis, contre cette instance :

```bash
export PGPP_TEST_URL=postgres://pgpp_admin@127.0.0.1:5432/postgres   # membre de pass_policy_admin + CREATEROLE
export PGPASSFILE=/chemin/vers/pgpass
cargo test -- --include-ignored   # ajoute les tests d'intégration contre la base
cargo test --test integration -- --ignored   # seulement ceux-là
```

`PG_PASS_POLICY_SRC` ne sert qu'à installer l'extension : `pgpp` et ses
tests ne lisent que la base désignée par `PGPP_TEST_URL`.

Les tests base sont annotés `#[ignore]` et, une fois lancés avec
`--ignored` / `--include-ignored`, échouent si `PGPP_TEST_URL` est absente
ou vide : une variable mal nommée ne peut pas faire passer la suite au vert
sans rien tester.

Les tests d'intégration créent des rôles `pgpp_t_*`, un profil
`pgpp_t_profile` et une paire `pgpp_t_pair` (rôles `pgpp_t_pa`, `pgpp_t_pb`,
groupe `pgpp_t_grp`) dans la base désignée : à n'utiliser que sur une
instance de test. Le test Vault utilise un serveur HTTP simulé (`httpmock`)
qui vérifie le chemin, les en-têtes `X-Vault-Token` / `X-Vault-Namespace`, le
corps envoyé et les requêtes de vérification préalable.

Deux tests (`a_connection_timeout_is_not_a_request_vault_may_have_received`,
`a_ctrl_c_before_the_body_is_sent_means_not_attempted`) ont besoin d'une
connexion TCP de boucle locale qui reste bloquée : ils remplissent la file
d'attente d'un port qui n'accepte jamais. Ce comportement dépend de l'hôte
(`net.ipv4.tcp_abort_on_overflow = 1`, bac à sable qui refuse les
connexions) : il est vérifié d'abord et, s'il n'est pas obtenu, les deux
tests sautent leur partie réseau et le signalent sur la sortie d'erreur
(`skipped: no hanging loopback connection on this host`).

Le test `expiring_uses_the_view_and_leaves_exempt_roles_out` vérifie en
outre l'exclusion des rôles exemptés quand le serveur liste
`pgpp_t_xv_exempt` dans `pg_pass_policy.exempt_roles` (réglage `SIGHUP` du
`postgresql.conf` de l'instance de test) ; sinon, il saute cette partie et le
signale sur la sortie d'erreur.

## Choix techniques

- **sqlx 0.8** (runtime tokio, TLS rustls/ring) : paramètres liés typés,
  lecture de `PGPASSFILE`, pas de dépendance à libpq. Les horodatages et
  intervalles sont convertis en texte côté serveur pour restituer fidèlement
  les valeurs spéciales (`infinity` d'un verrou manuel).
- **reqwest** (rustls) pour Vault, **comfy-table** pour l'affichage,
  **rpassword** pour la saisie sans écho, **zeroize** pour l'effacement des
  secrets.
- Le code est organisé en bibliothèque (`src/lib.rs`, testée par
  `tests/`) et en binaire minimal (`src/main.rs`) qui ne fait que convertir
  le résultat en code de retour.
