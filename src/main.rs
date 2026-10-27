use clap::Parser;

#[tokio::main]
async fn main() {
    // clap exits with 2 on a usage error and 0 on --help / --version.
    let cli = match pgpp::cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };
    let code = match pgpp::run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("pgpp: error: {}", pgpp::format_error(&err));
            pgpp::EXIT_ERROR
        }
    };
    std::process::exit(code);
}
