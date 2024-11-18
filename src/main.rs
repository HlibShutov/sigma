use argparse::{ArgumentParser, Collect, Store};

use sigma::cmd_init;

fn main() {
    let mut command: String = Default::default();
    let mut args: Vec<String> = Default::default();
    {
        let mut parser = ArgumentParser::new();
        parser.set_description("Simplified Implementation of Git Mechanics and Architecture");

        parser
            .refer(&mut command)
            .add_argument("command", Store, "Command to run");
        parser
            .refer(&mut args)
            .add_argument("args", Collect, "Arguments");

        parser.parse_args().unwrap();
    }
    println!("command: {command}");
    println!("args: {args:?}");

    match command.as_str() {
        "init" => cmd_init(args),
        _ => panic!("Unknown command"),
    }
}
