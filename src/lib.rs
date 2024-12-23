use std::env;
use std::fs;
use std::path::PathBuf;

pub mod git_objects;
pub mod git_repository;
pub mod utils;

use git_objects::*;
use utils::object_write;
use utils::parse_key_value;
use utils::read_raw;
use utils::write_key_value;
use utils::{object_read, repo_find};

use crate::git_repository::RepoErrors;
use crate::utils::repo_create;

pub fn cmd_init(path: Option<String>) {
    let repo_path = if let Some(path) = path {
        PathBuf::from(path.as_str())
    } else {
        env::current_dir().expect("failed to get current dir")
    };
    match repo_create(repo_path) {
        Err(RepoErrors::ConfigFileError) => panic!("Failed to read config file"),
        Err(RepoErrors::ConfigError) => panic!("Invalid config file"),
        Err(RepoErrors::FormatVersionError) => panic!("SIGMA only supports 0 format version"),
        Ok(_) => println!("Created empty repo"),
        _ => panic!("Unknown error"),
    };
}

pub fn cmd_cat_file(obj_args: String) {
    let repo_path = env::current_dir().expect("failed to get current dir");

    let repo = match repo_find(repo_path) {
        Ok(repo) => repo,
        Err(RepoErrors::NotFound) => panic!("Failed to find repo"),
        _ => panic!("Unknown error"),
    };
    let path = repo.repo_path(&format!("objects/{}/{}", &obj_args[0..2], &obj_args[2..]));
    let raw = read_raw(path);
    println!("{:?}", raw);
    let obj = object_read(raw);
    println!("{}", String::from_utf8(obj.deserialize()).unwrap());
}

pub fn cmd_hash_object(path: String, object_type: String, write: bool) {
    let current_dir = env::current_dir().expect("failed to get current dir");
    let repo = if write {
        let found_repo = match repo_find(current_dir.clone()) {
            Err(RepoErrors::NotFound) => panic!("Repo not found"),
            Ok(repo_ok) => repo_ok,
            _ => panic!("Unknown error"),
        };
        Some(found_repo)
    } else {
        None
    };

    let full_path: PathBuf = current_dir.join(&path);
    let data = fs::read(&path).expect("Failed to read object");

    let obj = match object_type.as_str() {
        "blob" => GitObject::Blob(GitBlob::new(data)),
        "commit" => GitObject::Commit(GitCommit::new(data)),
        "tree" => GitObject::Tree(GitTree::new(data)),
        "tag" => GitObject::Tag(GitTag::new(data)),
        _ => panic!("Failed to recognize object"),
    };

    let sha = object_write(repo, obj);
    println!("{}", sha);
}

pub fn cmd_log(object: String) {
    let repo_path = env::current_dir().expect("failed to get current dir");

    let repo = match repo_find(repo_path) {
        Ok(repo) => repo,
        Err(RepoErrors::NotFound) => panic!("Failed to find repo"),
        _ => panic!("Unknown error"),
    };

    let mut current_object = object;

    loop {
        let path = repo.repo_path(&format!("objects/{}/{}", &current_object[0..2], &current_object[2..]));
        let raw = read_raw(path);
        let obj = object_read(raw);

        let parsed_data = parse_key_value(obj.deserialize(), None);
        obj.serialize();
        println!("{}", String::from_utf8(obj.serialize()).unwrap());
        println!("^^^^^^^^^^^");

        if let Some(parent) = parsed_data.get("parent") {
            current_object = parent.clone();
        } else {
            break;
        }
    }
}
