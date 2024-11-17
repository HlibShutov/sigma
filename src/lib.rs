use std::env;
use std::path::PathBuf;

pub mod git_objects;
pub mod git_repository;
pub mod utils;

use crate::git_repository::RepoErrors;
use crate::utils::repo_create;

pub fn cmd_init(path: Vec<String>) {
    let repo_path = if path.len() != 1 {
        env::current_dir().expect("failed to get current dir")
    } else {
        PathBuf::from(path[0].as_str())
    };
    match repo_create(repo_path) {
        Err(RepoErrors::ConfigFileError) => panic!("Failed to read config file"),
        Err(RepoErrors::ConfigError) => panic!("Invalid config file"),
        Err(RepoErrors::FormatVersionError) => panic!("SIGMA only supports 0 format version"),
        Ok(_) => println!("Created empty repo"),
    };
}
