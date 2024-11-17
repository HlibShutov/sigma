use crate::git_objects::*;
use crate::git_repository::{GitRepository, RepoErrors};
use ini::Ini;
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use sha1::{Digest, Sha1};
use std::fs::{self, exists, File};
use std::io::Write;
use std::path::PathBuf;

// TODO: error handling

pub fn repo_create(path: PathBuf) -> Result<(), RepoErrors> {
    let repo = GitRepository::new(path, true)?;

    fs::create_dir_all(repo.repo_path("objects/")).expect("Failed to creacte objects dir");
    fs::create_dir_all(repo.repo_path("refs/tags/")).expect("Failed to creacte refs/tags dir");
    fs::create_dir_all(repo.repo_path("refs/heads/")).expect("Failed to creacte refs/heads dir");

    let mut head_file =
        File::create_new(repo.repo_path("HEAD")).expect("Failed to create config file");
    head_file
        .write_all("ref: refs/heads/master\n".as_bytes())
        .expect("Failed to wrtie default HEAD");

    let mut description_file =
        File::create_new(repo.repo_path("description")).expect("Failed to create description file");
    description_file
        .write_all(
            "Unnamed repository; edit this file 'description' to name the repository.\n".as_bytes(),
        )
        .expect("Failed to wrtie default description");

    File::create_new(repo.repo_path("config")).expect("Failed to create config file");
    let mut config = Ini::new();
    config
        .with_section(Some("core"))
        .set("repositoryformatversion", "0")
        .set("filemode", "false")
        .set("bare", "false");

    config
        .write_to_file(repo.repo_path("config"))
        .expect("Failed to write settings");

    Ok(())
}

pub fn repo_find(path: PathBuf) -> Result<GitRepository, RepoErrors> {
    let git_dir = path.join(".git/");
    if exists(git_dir).expect("Failed to find repo") {
        Ok(GitRepository::new(path, false)?)
    } else {
        if path.parent() == Some(&path) {
            Err(RepoErrors::FormatVersionError)
        } else {
            repo_find(path.parent().expect("There is no repo").to_path_buf())
        }
    }
}

pub fn object_read(repo: &GitRepository, sha: String) -> Box<dyn GitObject> {
    let path = repo.repo_path(&format!("objects/{}/{}", &sha[0..2], &sha[2..]));
    let compressed = fs::read(path).expect("Failed to read object");
    let decompressed =
        decompress_to_vec_zlib(compressed.as_slice()).expect("Failed to decompress!");

    let type_index = decompressed
        .iter()
        .position(|&r| r == 32)
        .expect("failed to read object");
    let object_type =
        String::from_utf8(decompressed[..type_index].to_vec()).expect("failed to read object");

    let size_index = decompressed
        .iter()
        .position(|&r| r == 0)
        .expect("failed to read object");

    let data = decompressed[size_index + 1..].to_vec();

    match object_type.as_str() {
        "blob" => Box::new(GitBlob::new(data)),
        "commit" => Box::new(GitCommit::new(data)),
        "tree" => Box::new(GitTree::new(data)),
        "tag" => Box::new(GitTag::new(data)),
        _ => panic!("Failed to recognize object"),
    }
}

pub fn object_write(repo: &GitRepository, obj: Box<dyn GitObject>) {
    let data = obj.serialize();
    let header = [
        obj.fmt().as_bytes(),              // object type (e.g., "blob", "commit")
        b" ",                              // space separator
        data.len().to_string().as_bytes(), // object size
        &[0],                              // null byte separating the header from the object data
    ]
    .concat();
    let result = [header, data.to_vec()].concat();
    let mut hasher = Sha1::new();
    hasher.update(&result);
    let hash = hasher.finalize();
    let hex_result = hex::encode(hash);
    let compressed = compress_to_vec_zlib(&result, 6);

    let path = repo.repo_path(
        format!("objects/{}/{}", &hex_result[0..2], &hex_result[2..])
            .as_str()
            .into(),
    );
    fs::create_dir_all(path.parent().unwrap()).expect("Failded to create object file parents");
    let mut file = File::create(path).expect("Failed to create object file");
    file.write_all(&compressed).expect("Failed to write object");
}
