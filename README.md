# pgpp — client en ligne de commande de pg_pass_policy

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
cargo install --path cli            # depuis la racine du dépôt
# ou, sans installer :
cargo build --release --manifest-path cli/Cargo.toml   # binaire dans cli/target/release/pgpp
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
| 1 | erreur (base injoignable, réseau, refus de l'extension, échec de remise du mot de passe après rotation) |
| 2 | erreur d'usage : option inconnue, durée ou `--set` invalide, `--limit` < 1, rotation sans option de remise, configuration Vault absente ou invalide (`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, chemin `--vault-kv`), jeton Vault refusé (401 ou 403, y compris un jeton expiré, révoqué ou inconnu) ou sans droit d'écriture sur le chemin, Vault injoignable, `sh` introuvable pour `--exec` ; toujours détectée avant la connexion et avant toute rotation (sauf la validité du jeton avec `--vault-skip-preflight`, voir « Intégration HashiCorp Vault ») |
| 3 | mot de passe refusé par `check` (motif `PPP-xxx`) |

Les durées (`--within`, `--for`, `--since`) s'écrivent `45s`, `30m`, `12h`,
`14d`, `2w`, ou combinées (`1h30m`). L'unité est obligatoire et le total est
borné à 100 ans (`36500d`) : au-delà, la durée est refusée (code 2) au lieu
d'être tronquée en silence.

## Commandes

### État des rôles

```bash
pgpp status                      # vue v_role_status : tous les rôles LOGIN
pgpp status --role app_user      # un seul rôle (erreur si absent)
pgpp status -f json | jq '.[] | select(.status != "ok")'
pgpp expiring                    # status warning / grace / expired
pgpp expiring --within 14d       # idem + expiration dans moins de 14 jours
pgpp locked                      # rôles verrouillés (mêmes colonnes que la vue v_locked)
pgpp failed-attempts             # compteurs d'échecs en mémoire partagée
pgpp worker-status               # pid, dernier passage et rechargement du worker
```

### Rotation d'un mot de passe

```bash
pgpp rotate app_user --show                # affiche le mot de passe une seule fois
pgpp rotate app_user --length 32 --show -f json
pgpp rotate app_user --exec 'kubectl create secret generic app-db --from-file=password=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -'
pgpp rotate app_user --vault-kv secret/db/app_user
pgpp rotate app_user --exec '...' --vault-kv kv/app --vault-mount kv --show
```

`rotate` appelle `pass_policy.rotate_password(role, length)` : le mot de passe
est généré côté serveur, renvoyé une seule fois et n'apparaît ni dans
l'audit ni dans les journaux. La sortie indique le rôle, le nouveau
`VALID UNTIL` et les canaux de remise utilisés (`delivered_to`).

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
  Une erreur à ce stade sort avec le code 2 sans rien changer côté serveur ;
- si une remise (`--exec`, Vault) échoue malgré cela (Vault devenu
  injoignable, droits insuffisants sur le chemin, commande en erreur ou qui
  n'a pas lu le mot de passe), le mot de passe a déjà été changé côté serveur ; il
  n'est pas affiché sauf `--show`, le code de retour est 1 et le message
  invite à relancer la rotation ;
- si la relecture de `rolvaliduntil` échoue juste après la rotation (connexion
  coupée), un avertissement est émis, `valid_until` reste vide et la remise a
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
`--length`, `--show`, `--exec`, `--vault-kv`, `--vault-mount` ont le même
sens que pour `rotate` ; `--exec` reçoit en plus `PGPP_PAIR` et
`PGPP_PREVIOUS_ROLE`.

### Verrouillage et expiration

```bash
pgpp lock app_user --for 30m --reason "brute force suspected"
pgpp lock app_user                 # jusqu'à unlock explicite (locked_until = infinity)
pgpp unlock app_user               # déverrouille et remet le compteur d'échecs à zéro
pgpp expire app_user               # must_change + VALID UNTIL now()
```

`lock` lit la fin du verrouillage dans `v_role_status` et `locked` lit la
vue `v_locked` : toutes deux joignent `pass_policy.role_state` par l'OID du
rôle. La colonne `role_name` de `role_state` n'est en effet mise à jour qu'au
passage suivant de la maintenance après un `ALTER ROLE … RENAME` ; avec une
version de l'extension antérieure à cette jointure (vue jointe par nom),
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
booléens (`true/false`, `on/off`, `yes/no`) sont typés, `null` efface une
valeur optionnelle (`max_age`, `lock_duration`), le reste est transmis tel
quel (intervalles PostgreSQL : `"30 days"`, `"1 hour"`). L'ensemble est
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
entrée vide), ce qui permet à un script de distinguer un refus d'une panne.
Il n'est jamais passé en argument de ligne de commande.

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
`sh -c CMD`, suivi d'un saut de ligne, puis l'entrée est fermée. La sortie
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
| `PGPP_VALID_UNTIL` | nouveau `rolvaliduntil` (texte PostgreSQL, vide si illimité) |
| `PGPP_PAIR`, `PGPP_PREVIOUS_ROLE` | uniquement pour `switch-pair` |

Sont des erreurs de remise (code 1, `delivered_to` sans `exec`) : un code de
retour non nul du processus, une erreur d'écriture sur son entrée, et un
processus qui se termine sans avoir lu toute la ligne du mot de passe (par
exemple `--exec true`). `pgpp` garde pour cela sa propre copie de
l'extrémité de lecture du tube et vérifie, une fois le processus terminé,
qu'il n'y reste aucun octet. Le hook doit donc consommer la ligne avant de
se terminer (`cat`, `read -r pw`, `--from-file=/dev/stdin`…) ; une lecture
confiée à un processus lancé en arrière-plan qui survit au hook n'est pas
reconnue.

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
pgpp rotate app_user --vault-kv db/app_user --vault-mount kv
```

`--vault-kv` désigne `<mount>/<chemin>` : la première composante est le point
de montage du moteur KV v2, sauf si `--vault-mount` est donné (le chemin est
alors pris en entier). Chaque segment du chemin est vérifié : un segment vide,
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
| `VAULT_CAPATH` | un répertoire de fichiers `*.pem` / `*.crt` / `*.cer`, tous chargés |

`VAULT_ADDR` est une URL sans paramètres (`?…`), sans fragment (`#…`) et
sans identifiants (`user:pass@`), refusée sinon (code 2). Un préfixe de
chemin est conservé (`https://proxy.example.net/vault` donne
`https://proxy.example.net/vault/v1/…`) ; les URL sont construites segment
par segment, jamais par concaténation de texte.

`VAULT_ADDR` doit être en `https://` ; `http://` n'est accepté que vers un
hôte de boucle locale (`127.0.0.0/8`, `::1`, `localhost`), par exemple un
agent Vault local. Toute autre adresse en clair est refusée (code 2) : le
jeton et le mot de passe y circuleraient sans chiffrement. Pour un cas non
couvert, le contournement reste `--exec` avec le client officiel :
`--exec 'read -r pw; printf "%s" "$pw" | vault kv put -mount=secret db/app password=-'`.

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
   `default`) : une erreur réseau, une redirection, un 401, un 403, un 5xx ou
   tout autre statut non 2xx sortent avec le code 2. Vault répond en effet
   403 « permission denied » (jamais 401) à un jeton expiré, révoqué ou
   inconnu : un 403 est donc un refus ;
2. `POST {VAULT_ADDR}/v1/sys/capabilities-self` avec
   `{"paths": ["{mount}/data/{chemin}"]}` : un refus de cette requête (403
   compris) ou des droits sur ce chemin qui ne comprennent ni `create`, ni
   `update`, ni `root` sortent avec le code 2. Si la réponse est illisible,
   `pgpp` avertit et tente l'écriture après la rotation.

Un jeton expiré, révoqué ou inconnu, un jeton sans droit d'écriture sur le
chemin, un Vault injoignable ou une redirection sortent donc avec le code 2
avant toute rotation. Restent possibles après la rotation : un refus
d'écriture que la vérification n'a pas pu prévoir (réponse illisible de
`capabilities-self`, politique modifiée entre-temps) ou une panne survenue
entre les requêtes (code 1, voir « Politique d'affichage »).

Un jeton créé avec `-no-default-policy` ne peut pas appeler `lookup-self` ni,
en général, `capabilities-self` : il est refusé par la vérification
ci-dessus. Pour un tel jeton, l'option `--vault-skip-preflight` (ou la
variable `PGPP_VAULT_SKIP_PREFLIGHT=1`, ou `true`, `yes`, `on` ; `0`,
`false`, `no`, `off` la désactivent, toute autre valeur, vide comprise, est
une erreur d'usage, code 2) supprime les deux requêtes et affiche un
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
  SET` / `GRANT SET ON PARAMETER`), sinon il avertit. Ce réglage ne couvre
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
  la commande n'en a plus besoin (y compris la copie du corps JSON envoyé à
  Vault et la sortie JSON formatée). Le mot de passe candidat de `check` est
  lu sur une copie du descripteur 0, sans le tampon interne de
  `std::io::stdin()` qui en garderait une copie non effacée : octet par
  octet depuis un tube ou un terminal, par blocs dans un tampon effacé depuis
  un fichier ordinaire (`pgpp check app < fichier`), la position étant alors
  ramenée juste après le premier `\n`. Les tampons
  internes des bibliothèques (réponse réseau et paramètres liés de sqlx,
  requête HTTP de reqwest, saisie sans écho de rpassword) ne sont pas sous
  contrôle de `pgpp`.
- Le mot de passe d'un `--exec` passe par un tube vers l'entrée standard du
  processus enfant, jamais par `argv` ni par l'environnement. Le processus
  enfant hérite en revanche de l'environnement de `pgpp` (voir la section
  `--exec`).
- Vault n'est joint qu'en TLS vérifié (ou en clair sur la boucle locale
  uniquement), avec `VAULT_CACERT` / `VAULT_CAPATH` pour une autorité privée.
- Le rôle de connexion doit être membre de `pass_policy_admin` : les
  vérifications de droits sont faites par les fonctions `SECURITY DEFINER`
  de l'extension (un administrateur non superutilisateur ne peut pas agir sur
  un rôle `SUPERUSER`, `REPLICATION` ou `BYPASSRLS`).

## Tests

```bash
cd cli
cargo test                        # tests unitaires + mock Vault + tests sans base ; les tests base sont marqués ignored
export PGPP_TEST_URL=postgres://pgpp_admin@127.0.0.1:5432/postgres   # membre de pass_policy_admin + CREATEROLE
export PGPASSFILE=/chemin/vers/pgpass
cargo test -- --include-ignored   # ajoute les tests d'intégration contre la base
cargo test --test integration -- --ignored   # seulement ceux-là
```

Les tests base sont annotés `#[ignore]` et, une fois lancés avec
`--ignored` / `--include-ignored`, échouent si `PGPP_TEST_URL` est absente
ou vide : une variable mal nommée ne peut pas faire passer la suite au vert
sans rien tester.

Les tests d'intégration créent des rôles `pgpp_t_*`, un profil
`pgpp_t_profile` et une paire `pgpp_t_pair` (rôles `pgpp_t_pa`, `pgpp_t_pb`,
groupe `pgpp_t_grp`) dans la base désignée : à n'utiliser que sur une
instance de test. Le test Vault utilise un serveur HTTP simulé (`httpmock`)
qui vérifie le chemin, les en-têtes `X-Vault-Token` / `X-Vault-Namespace`, le
corps envoyé et les deux requêtes de vérification préalable.

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
