use std::ffi::OsString;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("");
    let result = match command {
        "scan" => {
            let catalog = lokr::scan();
            println!("{}", lokr::to_json(&lokr::catalog_json(&catalog)));
            Ok(())
        }
        "list" => {
            let catalog = lokr::scan();
            let query = args.get(1).map(String::as_str);
            for entry in lokr::filter(&catalog, query) {
                println!("{}\t{}", entry.name, entry.location);
            }
            Ok(())
        }
        "mcp" => {
            let exe: OsString = std::env::current_exe()
                .map(Into::into)
                .unwrap_or_else(|_| "lokr".into());
            lokr::serve_stdio(&lokr::ServerOptions {
                daemon_command: vec![exe, "daemon".into()],
                ask_command: Vec::new(),
            })
        }
        "daemon" => lokr::run_daemon(),
        _ => {
            eprintln!("usage: lokr <scan|list [query]|mcp|daemon>");
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("lokr: {error}");
        std::process::exit(1);
    }
}
