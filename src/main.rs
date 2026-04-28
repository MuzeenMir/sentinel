// Entry point for the `sentinel` CLI.
//
// Pre-v0.1 stub. Subcommands (`install`, `doctor`, `tail`, `service`, etc.)
// land alongside the v0.1 sprint work tracked in TODOS.md. For now the
// binary recognizes `--version` / `-V` and prints a placeholder for
// everything else so packagers and CI smoke checks have something to
// shake out.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("sentinel {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }

    eprintln!("sentinel: pre-v0.1 skeleton.");
    eprintln!("subcommands (install, doctor, tail, service) land in the v0.1 sprint.");
    eprintln!("see TODOS.md and DESIGN.md for scope.");
    eprintln!();
    print_help();
    ExitCode::from(2)
}

fn print_help() {
    println!("sentinel — open-source DNS shield for Windows");
    println!();
    println!("usage: sentinel [--version | -V] [--help | -h]");
    println!();
    println!("status: pre-v0.1, no commands wired yet. see TODOS.md.");
}
