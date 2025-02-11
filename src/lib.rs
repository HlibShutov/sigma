use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

pub mod git_index;
pub mod git_objects;
pub mod git_repository;
pub mod utils;

use chrono::DateTime;
use chrono::Local;
use git_index::IndexEntry;
use git_objects::*;
use git_repository::GitRepository;
use indexmap::IndexMap;
use ini::Ini;
use utils::*;

use crate::git_repository::RepoErrors;

use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

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
    let hash = find_object(obj_args);
    let path = repo.repo_path(&format!("objects/{}/{}", &hash[0..2], &hash[2..]));
    let raw = read_raw(path);
    println!("{:?}", raw);
    let obj = object_read(raw);
    match obj {
        GitObject::Tree(tree) => print_tree(tree),
        _ => println!("{}", String::from_utf8(obj.serialize()).unwrap()),
    }
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
    let mut current_object = find_object(object);

    loop {
        let path = repo.repo_path(&format!(
            "objects/{}/{}",
            &current_object[0..2],
            &current_object[2..]
        ));
        let raw = read_raw(path);
        let obj = object_read(raw);

        let mut index_map = IndexMap::new();
        let parsed_data = parse_key_value(obj.deserialize(), &mut index_map);
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
    let object = find_object(object);

    println!("{}", object);
    let path = repo.repo_path(&format!("objects/{}/{}", &object[0..2], &object[2..]));
    let raw = read_raw(path);
    let obj = object_read(raw.clone());
    println!("{:?}", obj);
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
    let commit = find_object(commit);
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

    tree_checkout(&repo, tree, PathBuf::from(path));
}

pub fn cmd_show_ref() {
    let repo = get_repo();
    let path = repo.repo_path("refs");
    let refs = list_refs(&repo, path);
    refs.iter()
        .for_each(|entry| println!("{} {}", entry.1, entry.0))
}

pub fn cmd_tag(name: String, write_object: bool, sha: String) {
    let repo = get_repo();
    if write_object {
        create_tag_object(&repo, name, sha);
    } else {
        create_ref(&repo, name, sha);
    };
}

pub fn cmd_rev_parse(name: String) {
    println!("{}", find_object(name));
}

pub fn cmd_ls_files() {
    let repo = get_repo();
    let mut index_buf = BufReader::new(File::open(repo.repo_path("index")).unwrap());
    let mut index = Vec::new();
    index_buf.read_to_end(&mut index).unwrap();
    let parsed_index = index_parse(index.to_vec());

    parsed_index
        .iter()
        .for_each(|entry| println!("{:?}", entry));
}

pub fn cmd_check_ignore(names: Vec<String>) {
    let repo = get_repo();
    let (absolute, scope) = read_gitignores(&repo);
    names.iter().for_each(|name| {
        let result_scope = check_ignore_scoped(scope.clone(), PathBuf::from(name));
        let result_absolute = check_ignore_absolute(absolute.clone(), PathBuf::from("/test/test"));
        if result_scope.is_some() || result_absolute.is_some() {
            println!("{}", name);
        }
    })
}

pub fn cmd_status() {
    let repo = get_repo();
    let mut index_buf = BufReader::new(File::open(repo.repo_path("index")).unwrap());
    let mut index = Vec::new();
    index_buf.read_to_end(&mut index).unwrap();
    let parsed_index = index_parse(index.to_vec());

    let head = find_object("HEAD".to_string());
    let head_path = repo.repo_path(&format!("objects/{}/{}", &head[0..2], &head[2..]));
    let raw = read_raw(head_path);
    let head_tree = match object_read(raw) {
        GitObject::Commit(commit) => commit.kv.get("tree").unwrap().clone(),
        _ => panic!("Broken HEAD"),
    };

    let flat_tree = flat_tree(&repo, &head_tree, "".to_string());

    parsed_index
        .iter()
        .for_each(|entry| match flat_tree.get(&entry.path) {
            Some(entry_name) => {
                if *entry_name != entry.sha {
                    println!("Modified {}", entry.path);
                }
            }
            None => println!("Added {}", entry.path),
        });

    println!("HEAD and index");
    let (absolute, scope) = read_gitignores(&repo);
    let mut all_files = Vec::new();
    for entry in WalkDir::new(".") {
        let entry = entry.unwrap();
        let mut path = entry.path().to_str().unwrap().chars();
        path.next();
        let path = path.as_str();
        let ignore_scoped = check_ignore_scoped(scope.clone(), path.into());
        let ignore_absolute = check_ignore_absolute(absolute.clone(), path.into());
        let ignore = ignore_scoped.unwrap_or(false) || ignore_absolute.unwrap_or(false);
        if !ignore && !path.starts_with("/.git/") && path != "/.git" && !entry.path().is_dir() {
            all_files.push(path.to_string());

            println!("{}", entry.path().display());
        }
    }
    println!("kts");

    println!("HEAD and index");

    parsed_index.iter().for_each(|entry| {
        let full_path = repo.worktree.join(&entry.path);
        if !full_path.is_file() {
            println!("deleted {}", entry.path);
        } else {
            let metadata = fs::metadata(&full_path).unwrap();
            let created = metadata.ctime();
            let modified = metadata.mtime();

            if created != entry.ctime as i64 && modified != entry.mtime as i64 {
                let data = fs::read(&full_path).expect("Failed to read object");

                let obj = GitObject::Blob(GitBlob::new(data));

                let sha = object_write(None, obj);
                if sha != entry.sha {
                    println!("modified {}", entry.path);
                }
            }
        }
        let index = all_files
            .iter()
            .position(|x| *x == "/".to_string() + &entry.path)
            .unwrap();
        all_files.remove(index);
    });

    println!("not in index");
    all_files.iter().for_each(|file| {
        println!("{}", file);
    });
}

pub fn cmd_rm(names: Vec<String>, delete: bool) {
    let repo = get_repo();
    let mut index_buf = BufReader::new(File::open(repo.repo_path("index")).unwrap());
    let mut index = Vec::new();
    index_buf.read_to_end(&mut index).unwrap();
    let mut parsed_index = index_parse(index.to_vec());
    parsed_index.retain(|entry| !names.contains(&entry.path));

    let new_index = write_index(parsed_index.clone());
    let _ = File::create(repo.repo_path("index"))
        .unwrap()
        .write_all(&new_index);

    if delete {
        names.iter().for_each(|name| {
            let _ = fs::remove_file(repo.worktree.join(name));
        });
    }
}

pub fn cmd_add(names: Vec<String>) {
    cmd_rm(names.clone(), false);
    let repo = get_repo();
    let mut index_buf = BufReader::new(File::open(repo.repo_path("index")).unwrap());
    let mut index = Vec::new();
    index_buf.read_to_end(&mut index).unwrap();
    let mut parsed_index = index_parse(index.to_vec());
    names.iter().for_each(|entry| {
        let data = fs::read(entry).expect("Failed to read object");
        let obj = GitObject::Blob(GitBlob::new(data));
        let sha = object_write(Some(repo.clone()), obj);
        println!("{:?}", sha);
        let metadata = fs::metadata(entry).expect("Failed to read file metadata");

        let index_entry = IndexEntry {
            ctime: (metadata.ctime() as u32),
            ctime_n: (metadata.ctime_nsec() % 1_000_000_000) as u32,
            mtime: (metadata.mtime() as u32),
            mtime_n: (metadata.mtime_nsec() % 1_000_000_000) as u32,
            device: metadata.dev() as u32,
            ino: metadata.ino() as u32,
            mode_type: 0b1000,
            mode_perms: 0o644,
            uid: metadata.uid() as u32,
            gid: metadata.gid() as u32,
            size: metadata.size() as u32,
            sha,
            path: entry.to_string(),
            assume_valid: false,
            stage: 0,
            name_length: entry.len() as u16,
        };
        parsed_index.push(index_entry);
    });
    let new_index = write_index(parsed_index);
    let _ = File::create(repo.repo_path("index"))
        .unwrap()
        .write_all(&new_index);
}

pub fn cmd_commit(message: String) {
    let repo = get_repo();
    let mut index_buf = BufReader::new(File::open(repo.repo_path("index")).unwrap());
    let mut index = Vec::new();
    index_buf.read_to_end(&mut index).unwrap();
    let parsed_index = index_parse(index.to_vec());

    let sha = index_to_tree(&repo, parsed_index);
    println!("{:?}", sha);

    let config_path = format!("{}/.gitconfig", env::var("HOME").unwrap());
    let config_file = Ini::load_from_file(config_path).unwrap();
    let user = config_file.section(Some("user")).unwrap();
    let user_info = format!(
        "{} <{}>",
        user.get("name").unwrap(),
        user.get("email").unwrap()
    );

    let mut commit: IndexMap<String, String> = IndexMap::new();
    commit.insert("tree".to_string(), sha);

    if !find_object("HEAD".to_string()).is_empty() {
        commit.insert("parent".to_string(), find_object("HEAD".to_string()));
    }

    let timestamp: DateTime<Local> = Local::now();

    let offset = timestamp.offset().utc_minus_local();
    let hours = offset / 3600;
    let minutes = (offset % 3600) / 60;

    let tz = format!(
        "{}{:02}{:02}",
        if offset >= 0 { "-" } else { "+" },
        hours.abs(),
        minutes.abs()
    );

    let user_time_info = format!("{} {} {}", user_info, timestamp.timestamp(), tz);
    commit.insert("author".to_string(), format!("{}", user_time_info));
    commit.insert("committer".to_string(), format!("{}", user_time_info));
    commit.insert("message".to_string(), message);

    let commit_serialized = write_key_value(commit);
    let commit = GitCommit::new(commit_serialized.into_bytes());
    println!("{:?}", commit.kv);
    let commit_sha = object_write(Some(repo.clone()), GitObject::Commit(commit));
    println!("{:?}", commit_sha);
    let content = fs::read(repo.repo_path("HEAD")).unwrap();
    let active_branch = String::from_utf8(content[5..].to_vec()).unwrap();
    let active_branch_path = repo.repo_path(active_branch.trim());
    let _ = File::create(active_branch_path)
        .unwrap()
        .write_all(commit_sha.as_bytes());
}
