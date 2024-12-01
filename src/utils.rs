use crate::git_objects::*;
use crate::git_repository::{GitRepository, RepoErrors};
use ini::Ini;
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use sha1::{Digest, Sha1};
use indexmap::IndexMap;
use std::collections::hash_map;
use std::fs::{self, exists, File};
use std::io::Write;
use std::ops::Index;
use std::path::PathBuf;

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
            Err(RepoErrors::NotFound)
        } else {
            repo_find(path.parent().expect("There is no repo").to_path_buf())
        }
    }
}

pub fn read_raw(path: PathBuf) -> Vec<u8> {
    let compressed = fs::read(path).expect("Failed to read");
    decompress_to_vec_zlib(compressed.as_slice()).expect("Failed to decompress!")
}

pub fn object_read(raw: Vec<u8>) -> GitObject {
    let type_index = raw
        .iter()
        .position(|&r| r == 32)
        .expect("failed to read object");
    let object_type =
        String::from_utf8(raw[..type_index].to_vec()).expect("failed to read object");

    let size_index = raw
        .iter()
        .position(|&r| r == 0)
        .expect("failed to read object");

    let data = raw[size_index + 1..].to_vec();

    match object_type.as_str() {
        "blob" => GitObject::Blob(GitBlob::new(data)),
        "commit" => GitObject::Commit(GitCommit::new(data)),
        "tree" => GitObject::Tree(GitTree::new(data)),
        "tag" => GitObject::Tag(GitTag::new(data)),
        _ => panic!("Failed to recognize object"),
    }
}

pub fn object_write(repo: Option<GitRepository>, obj: GitObject) -> String {
    let data = obj.serialize();
    let fmt = match obj {
        GitObject::Blob(_) => "blob",
        GitObject::Commit(_) => "commit",
        GitObject::Tree(_) => "tree",
        GitObject::Tag(_) => "tag",
    };
    let header = [
        fmt.as_bytes(),              // object type (e.g., "blob", "commit")
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

    if let Some(repo) = repo {
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

    hex_result
}

pub fn parse_key_value(raw: Vec<u8>, hash_map: Option<IndexMap<String, String>>) -> IndexMap<String, String> {
     let mut hash_map: IndexMap<String, String> = hash_map.unwrap_or(IndexMap::new());

     let space = raw.iter().position(|&r| r == 32);
     let new_line = raw.iter().position(|&r| r == 10);

     if let (Some(space), Some(new_line)) = (space, new_line) {
         if space < new_line {
             let key = String::from_utf8(raw[..space].to_vec()).expect("Failed to parse");
             let value = String::from_utf8(raw[space+1..new_line].to_vec()).expect("Failed to parse");
             hash_map.insert(key, value);
             hash_map = parse_key_value(raw[new_line+1..].to_vec(), Some(hash_map.clone()));
         } else if new_line+1 == space {
             let keys = hash_map.keys();
             let last_key = keys[keys.len()-1].clone();
             let nl = raw[space..].iter().position(|&r| r == 10).unwrap();
             hash_map[last_key.as_str()].push_str("\n");
             hash_map[last_key.as_str()].push_str(String::from_utf8(raw[space+1..nl+1].to_vec()).unwrap().as_str());
             hash_map = parse_key_value(raw[nl+1..].to_vec(), Some(hash_map.clone()));
         } else {
             let nl = raw.iter().rposition(|&r| r == 10).unwrap();
             hash_map.insert("message".to_string(), String::from_utf8(raw[nl+1..].to_vec()).unwrap());
         }
     }

     hash_map

}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_hash() {
        let obj = GitObject::Blob(GitBlob::new(vec![116, 101, 115, 116]));
        let hash = object_write(None, obj);
        assert_eq!(hash, "30d74d258442c7c65512eafab474568dd706c430".to_string());
    }
    #[test]
    fn read_raw_object() {
        let obj = object_read(vec![98, 108, 111, 98, 32, 52, 00, 116, 101, 115, 116]); // blob 4.test
        println!("{:?}", obj.deserialize());
        assert_eq!(obj.deserialize(), vec![116, 101, 115, 116]); //test
    }

    #[test]
    fn parses_commit_with_pgp_signature() {
        let raw = vec![116, 114, 101, 101, 32, 50, 57, 102, 102, 49, 54, 99, 57, 99, 49, 52, 101, 50, 54, 53, 50, 98, 50, 50, 102, 56, 98, 55, 56, 98, 98, 48, 56, 97, 53, 97, 48, 55, 57, 51, 48, 99, 49, 52, 55, 10, 112, 97, 114, 101, 110, 116, 32, 50, 48, 54, 57, 52, 49, 51, 48, 54, 101, 56, 97, 56, 97, 102, 54, 53, 98, 54, 54, 101, 97, 97, 97, 101, 97, 51, 56, 56, 97, 55, 97, 101, 50, 52, 100, 52, 57, 97, 48, 10, 97, 117, 116, 104, 111, 114, 32, 84, 104, 105, 98, 97, 117, 108, 116, 32, 80, 111, 108, 103, 101, 32, 60, 116, 104, 105, 98, 97, 117, 108, 116, 64, 116, 104, 98, 46, 108, 116, 62, 32, 49, 53, 50, 55, 48, 50, 53, 48, 50, 51, 32, 43, 48, 50, 48, 48, 10, 99, 111, 109, 109, 105, 116, 116, 101, 114, 32, 84, 104, 105, 98, 97, 117, 108, 116, 32, 80, 111, 108, 103, 101, 32, 60, 116, 104, 105, 98, 97, 117, 108, 116, 64, 116, 104, 98, 46, 108, 116, 62, 32, 49, 53, 50, 55, 48, 50, 53, 48, 52, 52, 32, 43, 48, 50, 48, 48, 10, 103, 112, 103, 115, 105, 103, 32, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 71, 80, 32, 83, 73, 71, 78, 65, 84, 85, 82, 69, 45, 45, 45, 45, 45, 10, 10, 32, 105, 81, 73, 122, 66, 65, 65, 66, 67, 65, 65, 100, 70, 105, 69, 69, 120, 119, 88, 113, 117, 79, 77, 56, 98, 87, 98, 52, 81, 50, 122, 86, 71, 120, 77, 50, 70, 120, 111, 76, 107, 71, 81, 70, 65, 108, 115, 69, 106, 90, 81, 65, 67, 103, 107, 81, 71, 120, 77, 50, 70, 120, 111, 76, 10, 32, 107, 71, 81, 100, 99, 66, 65, 65, 113, 80, 80, 43, 108, 110, 52, 110, 71, 68, 100, 50, 103, 69, 84, 88, 106, 118, 79, 112, 79, 120, 76, 122, 73, 77, 69, 119, 52, 65, 57, 103, 85, 54, 67, 122, 87, 122, 109, 43, 111, 66, 56, 109, 69, 73, 75, 121, 97, 72, 48, 85, 70, 73, 80, 104, 10, 32, 114, 78, 85, 90, 49, 106, 55, 47, 90, 71, 70, 78, 101, 66, 68, 116, 84, 53, 53, 76, 80, 100, 80, 73, 81, 119, 52, 75, 75, 108, 99, 102, 54, 107, 67, 56, 77, 80, 87, 80, 51, 113, 83, 117, 51, 120, 72, 113, 120, 49, 50, 67, 53, 122, 121, 97, 105, 50, 100, 117, 70, 90, 85, 85, 10, 32, 119, 113, 79, 116, 57, 105, 67, 70, 67, 115, 99, 70, 81, 89, 113, 75, 115, 51, 120, 115, 72, 73, 43, 110, 99, 81, 98, 43, 80, 71, 106, 86, 90, 65, 56, 43, 106, 80, 119, 55, 110, 114, 80, 73, 107, 101, 83, 88, 81, 86, 50, 97, 90, 98, 49, 69, 54, 56, 119, 97, 50, 89, 73, 76, 10, 32, 51, 101, 89, 103, 84, 85, 75, 122, 51, 52, 99, 66, 54, 116, 65, 113, 57, 89, 119, 72, 110, 90, 112, 121, 80, 120, 56, 85, 74, 67, 90, 71, 107, 115, 104, 112, 74, 109, 103, 116, 90, 51, 109, 67, 98, 116, 81, 97, 79, 49, 55, 76, 111, 105, 104, 110, 113, 80, 110, 52, 85, 79, 77, 114, 10, 32, 86, 55, 53, 82, 47, 55, 70, 106, 83, 117, 80, 76, 83, 56, 78, 97, 90, 70, 52, 119, 102, 105, 53, 50, 98, 116, 88, 77, 83, 120, 79, 47, 117, 55, 71, 117, 111, 74, 107, 122, 74, 115, 99, 80, 51, 112, 52, 113, 116, 119, 101, 54, 82, 108, 57, 100, 99, 49, 88, 67, 56, 80, 55, 107, 10, 32, 78, 73, 98, 71, 90, 53, 89, 103, 53, 99, 69, 80, 99, 102, 109, 104, 103, 88, 70, 79, 104, 81, 90, 107, 68, 48, 121, 120, 99, 74, 113, 66, 85, 99, 111, 70, 112, 110, 112, 50, 118, 117, 53, 88, 74, 108, 50, 69, 53, 73, 47, 113, 117, 73, 121, 86, 120, 85, 88, 105, 54, 79, 54, 99, 10, 32, 47, 111, 98, 115, 112, 99, 118, 97, 99, 101, 52, 119, 121, 56, 117, 79, 48, 98, 100, 86, 104, 99, 52, 110, 74, 43, 82, 108, 97, 52, 73, 110, 86, 83, 74, 97, 85, 97, 66, 101, 105, 72, 84, 87, 56, 107, 82, 101, 83, 70, 89, 121, 77, 109, 68, 67, 122, 76, 106, 71, 73, 117, 49, 113, 10, 32, 100, 111, 85, 54, 49, 79, 77, 51, 90, 118, 49, 112, 116, 115, 76, 117, 51, 103, 85, 69, 54, 71, 85, 50, 55, 105, 87, 89, 106, 50, 82, 87, 78, 51, 101, 51, 72, 69, 52, 83, 98, 100, 56, 57, 73, 70, 119, 76, 88, 78, 100, 83, 117, 77, 48, 105, 102, 68, 76, 90, 107, 55, 65, 81, 10, 32, 87, 66, 104, 82, 104, 105, 112, 67, 67, 103, 90, 104, 107, 106, 57, 103, 50, 78, 69, 107, 55, 106, 82, 86, 115, 108, 116, 105, 49, 78, 100, 78, 53, 122, 111, 81, 76, 97, 74, 78, 113, 83, 119, 79, 49, 77, 116, 120, 84, 109, 74, 49, 53, 75, 115, 107, 51, 81, 80, 54, 107, 102, 76, 66, 10, 32, 81, 53, 50, 85, 87, 121, 98, 66, 122, 112, 97, 80, 57, 72, 69, 100, 52, 88, 110, 82, 43, 72, 117, 81, 52, 107, 50, 75, 48, 110, 115, 50, 75, 103, 78, 73, 109, 115, 78, 118, 73, 121, 70, 119, 98, 112, 77, 85, 121, 85, 87, 76, 77, 80, 105, 109, 97, 86, 49, 68, 87, 85, 88, 111, 10, 32, 53, 83, 66, 106, 68, 66, 47, 86, 47, 87, 50, 74, 66, 70, 82, 43, 88, 75, 72, 70, 74, 101, 70, 119, 89, 104, 106, 55, 68, 68, 47, 111, 99, 115, 71, 114, 52, 90, 77, 120, 47, 108, 103, 99, 56, 114, 106, 73, 66, 107, 73, 61, 10, 32, 61, 108, 103, 84, 88, 10, 32, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 71, 80, 32, 83, 73, 71, 78, 65, 84, 85, 82, 69, 45, 45, 45, 45, 45, 10, 10, 67, 114, 101, 97, 116, 101, 32, 102, 105, 114, 115, 116, 32, 100, 114, 97, 102, 116];
        let mut expected: IndexMap<String, String> = IndexMap::new();
        expected.insert("tree".to_string(), "29ff16c9c14e2652b22f8b78bb08a5a07930c147".to_string());
        expected.insert("parent".to_string(), "206941306e8a8af65b66eaaaea388a7ae24d49a0".to_string());
        expected.insert("author".to_string(), "Thibault Polge <thibault@thb.lt> 1527025023 +0200".to_string());
        expected.insert("committer".to_string(), "Thibault Polge <thibault@thb.lt> 1527025044 +0200".to_string());
        expected.insert("gpgsig".to_string(), "-----BEGIN PGP SIGNATURE-----\niQIzBAABCAAdFiEExwXquOM8bWb4Q2zVGxM2FxoLkGQFAlsEjZQACgkQGxM2FxoL\nkGQdcBAAqPP+ln4nGDd2gETXjvOpOxLzIMEw4A9gU6CzWzm+oB8mEIKyaH0UFIPh\nrNUZ1j7/ZGFNeBDtT55LPdPIQw4KKlcf6kC8MPWP3qSu3xHqx12C5zyai2duFZUU\nwqOt9iCFCscFQYqKs3xsHI+ncQb+PGjVZA8+jPw7nrPIkeSXQV2aZb1E68wa2YIL\n3eYgTUKz34cB6tAq9YwHnZpyPx8UJCZGkshpJmgtZ3mCbtQaO17LoihnqPn4UOMr\nV75R/7FjSuPLS8NaZF4wfi52btXMSxO/u7GuoJkzJscP3p4qtwe6Rl9dc1XC8P7k\nNIbGZ5Yg5cEPcfmhgXFOhQZkD0yxcJqBUcoFpnp2vu5XJl2E5I/quIyVxUXi6O6c\n/obspcvace4wy8uO0bdVhc4nJ+Rla4InVSJaUaBeiHTW8kReSFYyMmDCzLjGIu1q\ndoU61OM3Zv1ptsLu3gUE6GU27iWYj2RWN3e3HE4Sbd89IFwLXNdSuM0ifDLZk7AQ\nWBhRhipCCgZhkj9g2NEk7jRVslti1NdN5zoQLaJNqSwO1MtxTmJ15Ksk3QP6kfLB\nQ52UWybBzpaP9HEd4XnR+HuQ4k2K0ns2KgNImsNvIyFwbpMUyUWLMPimaV1DWUXo\n5SBjDB/V/W2JBFR+XKHFJeFwYhj7DD/ocsGr4ZMx/lgc8rjIBkI=\n=lgTX\n-----END PGP SIGNATURE-----".to_string());
        expected.insert("message".to_string(), "Create first draft".to_string());

        let result = parse_key_value(raw, None);

        assert_eq!(expected["tree"], result["tree"]);
        assert_eq!(expected["parent"], result["parent"]);
        assert_eq!(expected["author"], result["author"]);
        assert_eq!(expected["committer"], result["committer"]);
        assert_eq!(expected["gpgsig"], result["gpgsig"]);
        assert_eq!(expected["message"], result["message"]);
        assert_eq!(expected, result);
    }

    #[test]
    fn parses_commit_without_pgp_signature() {
        let raw = vec![116, 114, 101, 101, 32, 50, 57, 102, 102, 49, 54, 99, 57, 99, 49, 52, 101, 50, 54, 53, 50, 98, 50, 50, 102, 56, 98, 55, 56, 98, 98, 48, 56, 97, 53, 97, 48, 55, 57, 51, 48, 99, 49, 52, 55, 10, 112, 97, 114, 101, 110, 116, 32, 50, 48, 54, 57, 52, 49, 51, 48, 54, 101, 56, 97, 56, 97, 102, 54, 53, 98, 54, 54, 101, 97, 97, 97, 101, 97, 51, 56, 56, 97, 55, 97, 101, 50, 52, 100, 52, 57, 97, 48, 10, 97, 117, 116, 104, 111, 114, 32, 84, 104, 105, 98, 97, 117, 108, 116, 32, 80, 111, 108, 103, 101, 32, 60, 116, 104, 105, 98, 97, 117, 108, 116, 64, 116, 104, 98, 46, 108, 116, 62, 32, 49, 53, 50, 55, 48, 50, 53, 48, 50, 51, 32, 43, 48, 50, 48, 48, 10, 99, 111, 109, 109, 105, 116, 116, 101, 114, 32, 84, 104, 105, 98, 97, 117, 108, 116, 32, 80, 111, 108, 103, 101, 32, 60, 116, 104, 105, 98, 97, 117, 108, 116, 64, 116, 104, 98, 46, 108, 116, 62, 32, 49, 53, 50, 55, 48, 50, 53, 48, 52, 52, 32, 43, 48, 50, 48, 48, 10, 10, 67, 114, 101, 97, 116, 101, 32, 102, 105, 114, 115, 116, 32, 100, 114, 97, 102, 116,];
        let mut expected: IndexMap<String, String> = IndexMap::new();
        expected.insert("tree".to_string(), "29ff16c9c14e2652b22f8b78bb08a5a07930c147".to_string());
        expected.insert("parent".to_string(), "206941306e8a8af65b66eaaaea388a7ae24d49a0".to_string());
        expected.insert("author".to_string(), "Thibault Polge <thibault@thb.lt> 1527025023 +0200".to_string());
        expected.insert("committer".to_string(), "Thibault Polge <thibault@thb.lt> 1527025044 +0200".to_string());
        expected.insert("message".to_string(), "Create first draft".to_string());

        let result = parse_key_value(raw, None);

        assert_eq!(expected["tree"], result["tree"]);
        assert_eq!(expected["parent"], result["parent"]);
        assert_eq!(expected["author"], result["author"]);
        assert_eq!(expected["committer"], result["committer"]);
        assert_eq!(expected["message"], result["message"]);
        assert_eq!(expected, result);
    }
}
