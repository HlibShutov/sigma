use clap::{Parser, Subcommand};
use sigma::{cmd_cat_file, cmd_init, cmd_hash_object};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Init {
        path: Option<String>
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
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args.cmd);

    match args.cmd {
        Commands::Init { path } => cmd_init(path),
        Commands::CatFile { file } => cmd_cat_file(file),
        Commands::HashObject { object, write, object_type }=> cmd_hash_object(object, object_type, write),
    }
}
