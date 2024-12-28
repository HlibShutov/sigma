use std::env;
use std::fs;
use std::path::PathBuf;

pub mod git_objects;
pub mod git_repository;
pub mod utils;

use git_objects::*;
use git_repository::GitRepository;
use utils::*;

use crate::git_repository::RepoErrors;
use crate::utils::repo_create;

fn get_repo() -> GitRepository {
    let repo_path = env::current_dir().expect("failed to get current dir");

    let repo = match repo_find(repo_path) {
        Ok(repo) => repo,
        Err(RepoErrors::NotFound) => panic!("Failed to find repo"),
        _ => panic!("Unknown error"),
    };

    repo
}
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
    let repo = get_repo();
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

    // let full_path: PathBuf = current_dir.join(&path);
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
    let repo = get_repo();
    let mut current_object = object;

    loop {
        let path = repo.repo_path(&format!(
            "objects/{}/{}",
            &current_object[0..2],
            &current_object[2..]
        ));
        let raw = read_raw(path);
        let obj = object_read(raw);

        let parsed_data = parse_key_value(obj.deserialize(), None);
        println!("{}", String::from_utf8(obj.serialize()).unwrap());
        println!("^^^^^^^^^^^");

        if let Some(parent) = parsed_data.get("parent") {
            current_object = parent.clone();
        } else {
            break;
        }
    }
}

pub fn cmd_ls_tree(object: String, recursive: bool) {
    let repo = get_repo();

    let path = repo.repo_path(&format!("objects/{}/{}", &object[0..2], &object[2..]));
    let raw = read_raw(path);
    let obj = object_read(raw.clone());
    let leafs = parse_tree(obj.deserialize());

    leafs.iter().for_each(|leaf| {
        let leaf_type = match leaf.mode[0..2] {
            [48, 52] => "tree",
            [49, 48] => "blob",
            [49, 50] => "blob",
            [49, 54] => "commit",
            _ => panic!("Unknown object type"),
        };
        if leaf.mode[0..2] == [48, 52] && recursive {
            cmd_ls_tree(leaf.sha.clone(), recursive)
        } else {
            println!(
                "{} {} {} {}",
                String::from_utf8(leaf.mode.clone()).unwrap(),
                leaf_type,
                leaf.sha,
                leaf.path
            )
        }
    });
}

pub fn cmd_checkout(commit: String, path: String) {
    let repo = get_repo();
    let commit_path = repo.repo_path(&format!("objects/{}/{}", &commit[0..2], &commit[2..]));
    let raw = read_raw(commit_path);
    let obj = object_read(raw);
    let commit_obj = match obj {
        GitObject::Commit(commit) => commit,
        _ => panic!("Not a commit"),
    };

    let tree_path = repo.repo_path(&format!(
        "objects/{}/{}",
        &commit_obj.kv["tree"][0..2],
        &commit_obj.kv["tree"][2..]
    ));
    let tree_raw = read_raw(tree_path);
    let tree = match object_read(tree_raw) {
        GitObject::Tree(tree) => tree,
        _ => panic!("corrupted commit"),
    };

    tree_checkout(repo, tree, PathBuf::from(path));
}

pub fn cmd_show_ref() {
    let repo = get_repo();
    let path = repo.repo_path("refs");
    let refs = list_refs(repo, path);
    refs.iter()
        .for_each(|entry| println!("{} {}", entry.1, entry.0))
}
