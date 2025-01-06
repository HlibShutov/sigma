use clap::{Parser, Subcommand};
use sigma::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Init {
        path: Option<String>,
    },
    CatFile {
        file: String,
    },
    HashObject {
        object: String,
        object_type: String,
        #[arg(short = 'w', long = "write")]
        write: bool,
    },
    Log {
        object: String,
    },
    LsTree {
        object: String,
        #[arg(short = 'r', long = "recursive")]
        recursive: bool,
    },
    Checkout {
        commit: String,
        path: String,
    },
    ShowRef,
    Tag {
        name: String,
        #[arg(short = 'a')]
        write: bool,
        #[arg(default_value = "HEAD")]
        object: String,
    },
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args.cmd);

    match args.cmd {
        Commands::Init { path } => cmd_init(path),
        Commands::CatFile { file } => cmd_cat_file(file),
        Commands::HashObject {
            object,
            write,
            object_type,
        } => cmd_hash_object(object, object_type, write),
        Commands::Log { object } => cmd_log(object),
        Commands::LsTree { object, recursive } => cmd_ls_tree(object, recursive),
        Commands::Checkout { commit, path } => cmd_checkout(commit, path),
        Commands::ShowRef => cmd_show_ref(),
        Commands::Tag {
            name,
            write,
            object,
        } => cmd_tag(name, write, object),
    }
}
