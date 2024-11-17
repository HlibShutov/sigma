use argparse::{ArgumentParser, Collect, Store};
use std::any::Any;

use sigma::{
    cmd_init,
    git_objects::{GitBlob, GitObject},
    utils::{object_read, object_write, repo_create, repo_find},
};

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

    let repo = repo_find("/home/hlib/workspace/python/plast_bot/".into()).unwrap();
    let obj = object_read(
        &repo,
        "051c7c8192294f47137b0e5527fbfcae5005f3e6".to_string(),
    );
    let repo1 = repo_find("/home/hlib/workspace/rust/test/".into()).unwrap();
    object_write(&repo1, obj);

    let mut obj1 = object_read(
        &repo1,
        "051c7c8192294f47137b0e5527fbfcae5005f3e6".to_string(),
    );

    // let a_ref = &mut obj1;
    // match (a_ref as &mut dyn Any).downcast_mut::<Box<dyn GitObject>>() {
    //     Some(_) => println!("found box"),
    //     None => println!("found nothing"),
    // }

    println!("{}", String::from_utf8(obj1.serialize().to_vec()).unwrap());

    // match command.as_str() {
    //     "init" => cmd_init(args),
    //     _ => panic!("Unknown command"),
    // }
}
