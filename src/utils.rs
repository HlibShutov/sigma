use crate::git_repository::{GitRepository, RepoErrors};
use crate::{get_repo, git_objects::*};
use indexmap::IndexMap;
use ini::Ini;
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use sha1::{Digest, Sha1};
use std::fs::{self, exists, File};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug)]
pub enum FindObjectErrors {
    NotFound,
    ManyResults,
}

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
    let object_type = String::from_utf8(raw[..type_index].to_vec()).expect("failed to read object");

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
        fmt.as_bytes(),                    // object type (e.g., "blob", "commit")
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

pub fn parse_key_value(
    raw: Vec<u8>,
    hash_map: Option<IndexMap<String, String>>,
) -> IndexMap<String, String> {
    let mut hash_map: IndexMap<String, String> = hash_map.unwrap_or(IndexMap::new());

    let space = raw.iter().position(|&r| r == 32);
    let new_line = raw.iter().position(|&r| r == 10);

    if let (Some(space), Some(new_line)) = (space, new_line) {
        if space < new_line {
            let key = String::from_utf8(raw[..space].to_vec()).expect("Failed to parse");
            let value =
                String::from_utf8(raw[space + 1..new_line].to_vec()).expect("Failed to parse");
            hash_map.insert(key, value);
            hash_map = parse_key_value(raw[new_line + 1..].to_vec(), Some(hash_map.clone()));
        } else if new_line + 1 == space {
            let keys = hash_map.keys();
            let last_key = keys[keys.len() - 1].clone();
            let nl = raw[space..].iter().position(|&r| r == 10).unwrap();
            if !hash_map[last_key.as_str()].contains("\n") && last_key.as_str() == "gpgsig" {
                hash_map[last_key.as_str()].push_str("\n");
            }
            hash_map[last_key.as_str()].push_str("\n");
            hash_map[last_key.as_str()].push_str(
                String::from_utf8(raw[space + 1..nl + 1].to_vec())
                    .unwrap()
                    .as_str(),
            );
            hash_map = parse_key_value(raw[nl + 1..].to_vec(), Some(hash_map.clone()));
        } else {
            let nl = raw.iter().rposition(|&r| r == 10).unwrap();
            hash_map.insert(
                "message".to_string(),
                String::from_utf8(raw[nl + 1..].to_vec()).unwrap(),
            );
        }
    }

    hash_map
}

pub fn write_key_value(hash_map: IndexMap<String, String>) -> String {
    let mut result = String::new();
    hash_map.iter().for_each(|(key, value)| match key.as_str() {
        "message" => {
            result.push_str("\n");
            result.push_str(value);
        }
        _ => {
            let mut replaced_nl = String::new();
            let mut chars = value.chars().peekable();

            while let Some(c) = chars.next() {
                if c == '\n' {
                    if let Some(&next) = chars.peek() {
                        if next == '\n' {
                            replaced_nl.push(c);
                        } else {
                            replaced_nl.push(c);
                            replaced_nl.push(' ');
                        }
                    } else {
                        replaced_nl.push(c);
                    }
                } else {
                    replaced_nl.push(c);
                }
            }
            result.push_str(&format!("{} {}", key, replaced_nl));
            result.push_str("\n");
        }
    });

    result
}

fn parse_tree_leaf(raw: Vec<u8>) -> (usize, TreeLeaf) {
    let space = raw
        .iter()
        .position(|&r| r == b' ')
        .expect("failed to find space in object");

    let null = raw
        .iter()
        .position(|&r| r == b'\x00')
        .expect("failed to find null byte in object");

    let mut mode = raw[..space].to_vec();
    if mode.len() == 5 {
        mode.insert(0, 48);
    }

    let path =
        String::from_utf8(raw[space + 1..null].to_vec()).expect("failed to parse path as UTF-8");

    let sha = hex::encode(&raw[null + 1..null + 21]);
    (null + 21, TreeLeaf { mode, path, sha })
}

pub fn parse_tree(raw: Vec<u8>) -> Vec<TreeLeaf> {
    let mut current = 0;
    let mut leafs = Vec::new();
    while current < raw.len() {
        let (end, leaf) = parse_tree_leaf(raw[current..].to_vec());
        leafs.push(leaf);
        current += end;
    }

    leafs
}

pub fn write_tree(mut leafs: Vec<TreeLeaf>) -> Vec<u8> {
    let mut result = Vec::new();
    leafs.sort_by(|a, b| {
        let a_path = if a.mode[0..2] == [49, 48] {
            a.path.clone()
        } else {
            a.path.clone() + "/"
        };

        let b_path = if b.mode[0..2] == [49, 48] {
            b.path.clone()
        } else {
            b.path.clone() + "/"
        };
        a_path.cmp(&b_path)
    });

    leafs.iter().for_each(|leaf| {
        let mut mode = leaf.mode.clone();
        while mode.starts_with(&[48]) {
            mode.remove(0); // Remove the first element
        }
        result.extend(mode);
        result.push(32);
        result.extend(leaf.path.bytes());
        result.push(0);
        let hex_hash = hex::decode(leaf.sha.clone());
        result.extend(hex_hash.unwrap());
    });

    result
}

pub fn tree_checkout(repo: GitRepository, tree: GitTree, path: PathBuf) {
    tree.leafs.iter().for_each(|leaf| {
        let leaf_path = repo.repo_path(&format!("objects/{}/{}", &leaf.sha[0..2], &leaf.sha[2..]));
        let raw = read_raw(leaf_path);
        let obj = object_read(raw);
        let new_path = path.join(&leaf.path);
        println!("{:?}", new_path);
        match obj {
            GitObject::Tree(tree_obj) => {
                fs::create_dir(&new_path).expect("Failed to create dir");
                tree_checkout(repo.clone(), tree_obj, new_path);
            }
            GitObject::Blob(blob_obj) => {
                fs::write(new_path, blob_obj.serialize()).expect("Failed to write file");
            }
            _ => panic!("Invalid tree"),
        }
    })
}

pub fn read_reference(repo: GitRepository, path: &str) -> String {
    let content = if let Ok(ref_content) = fs::read(repo.repo_path(path.trim())) {
        ref_content.trim_ascii().to_vec()
    } else {
        return "".to_string();
    };
    match content[0..5] {
        [114, 101, 102, 58, 32] => read_reference(
            repo,
            String::from_utf8(content[5..].to_vec())
                .expect("Invalid ref")
                .as_str(),
        ),
        _ => String::from_utf8(content.to_vec()).unwrap(),
    }
}

pub fn list_refs(repo: GitRepository, path: PathBuf) -> Vec<(String, String)> {
    let mut result = Vec::new();

    fs::read_dir(path).unwrap().for_each(|entry| {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            result.append(&mut list_refs(repo.clone(), entry.path()));
        } else {
            let entry_path = entry
                .path()
                .to_str()
                .unwrap()
                .split(".git/")
                .nth(1)
                .unwrap()
                .to_string();

            result.push((
                entry_path.clone(),
                read_reference(repo.clone(), entry_path.as_str())
                    .trim()
                    .to_string(),
            ))
        }
    });

    result
}

pub fn create_tag_object(repo: GitRepository, name: String, sha: String) {
    let sha = find_object(sha);
    let kv = IndexMap::from([
        ("object".to_string(), sha.clone()),
        ("type".to_string(), "commit".to_string()),
        ("tag".to_string(), name.clone()),
        ("tagger".to_string(), "Tagger".to_string()),
        ("message".to_string(), "Message".to_string()),
    ]);
    let tag_object = GitObject::Tag(GitTag::new(write_key_value(kv).as_bytes().to_vec()));
    let tag_sha = object_write(None, tag_object.clone());

    object_write(Some(repo.clone()), tag_object);
    create_ref(repo, format!("tags/{}", name), tag_sha);
}

pub fn create_ref(repo: GitRepository, name: String, sha: String) {
    let path = repo.repo_path(("refs/".to_string() + name.as_str()).as_str());
    println!("{:?}", path);
    let mut file = File::create(path).expect("Failed to create object file");
    file.write_all(sha.as_bytes())
        .expect("Failed to write object");
}

pub fn find_object(name: String) -> String {
    let repo = get_repo();
    let mut results = Vec::new();
    if name == "HEAD".to_string() {
        results.push(read_reference(repo.clone(), "HEAD"));
    };
    if name.len() > 3 && name.len() < 41 && name.chars().all(|c| c.is_digit(16)) {
        let path = repo.repo_path(format!("objects/{}/", &name[0..2]).as_str().into());
        fs::read_dir(path).unwrap().for_each(|entry| {
            let entry_name = entry.unwrap().file_name();
            if entry_name.to_str().unwrap().starts_with(&name[2..]) {
                results.push(name[0..2].to_string() + entry_name.to_str().unwrap());
            }
        })
    }

    let tag_sha = read_reference(repo.clone(), &format!("refs/tags/{}", name));
    if tag_sha != "".to_string() {
        let path = repo.repo_path(&format!("objects/{}/{}", &tag_sha[0..2], &tag_sha[2..]));
        let raw = read_raw(path);
        let tag = object_read(raw);
        match tag {
            GitObject::Tag(tag_obj) => results.push(tag_obj.kv.get("object").unwrap().to_string()),
            _ => panic!("Not a tag"),
        };
    }
    let branch_sha = read_reference(repo.clone(), &format!("refs/heads/{}", name));
    if branch_sha != "".to_string() {
        let path = repo.repo_path(&format!(
            "objects/{}/{}",
            &branch_sha[0..2],
            &branch_sha[2..]
        ));
        let raw = read_raw(path);
        let tag = object_read(raw);
        match tag {
            GitObject::Commit(commit_obj) => {
                results.push(commit_obj.kv.get("tree").unwrap().to_string())
            }
            _ => panic!("Not a branch"),
        };
    }
    results.get(0).expect("Not found").to_string()
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
        let raw = String::from(
            "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147
parent 206941306e8a8af65b66eaaaea388a7ae24d49a0
author Thibault Polge <thibault@thb.lt> 1527025023 +0200
committer Thibault Polge <thibault@thb.lt> 1527025044 +0200
gpgsig -----BEGIN PGP SIGNATURE-----

 iQIzBAABCAAdFiEExwXquOM8bWb4Q2zVGxM2FxoLkGQFAlsEjZQACgkQGxM2FxoL
 kGQdcBAAqPP+ln4nGDd2gETXjvOpOxLzIMEw4A9gU6CzWzm+oB8mEIKyaH0UFIPh
 rNUZ1j7/ZGFNeBDtT55LPdPIQw4KKlcf6kC8MPWP3qSu3xHqx12C5zyai2duFZUU
 wqOt9iCFCscFQYqKs3xsHI+ncQb+PGjVZA8+jPw7nrPIkeSXQV2aZb1E68wa2YIL
 3eYgTUKz34cB6tAq9YwHnZpyPx8UJCZGkshpJmgtZ3mCbtQaO17LoihnqPn4UOMr
 V75R/7FjSuPLS8NaZF4wfi52btXMSxO/u7GuoJkzJscP3p4qtwe6Rl9dc1XC8P7k
 NIbGZ5Yg5cEPcfmhgXFOhQZkD0yxcJqBUcoFpnp2vu5XJl2E5I/quIyVxUXi6O6c
 /obspcvace4wy8uO0bdVhc4nJ+Rla4InVSJaUaBeiHTW8kReSFYyMmDCzLjGIu1q
 doU61OM3Zv1ptsLu3gUE6GU27iWYj2RWN3e3HE4Sbd89IFwLXNdSuM0ifDLZk7AQ
 WBhRhipCCgZhkj9g2NEk7jRVslti1NdN5zoQLaJNqSwO1MtxTmJ15Ksk3QP6kfLB
 Q52UWybBzpaP9HEd4XnR+HuQ4k2K0ns2KgNImsNvIyFwbpMUyUWLMPimaV1DWUXo
 5SBjDB/V/W2JBFR+XKHFJeFwYhj7DD/ocsGr4ZMx/lgc8rjIBkI=
 =lgTX
 -----END PGP SIGNATURE-----

Create first draft",
        )
        .as_bytes()
        .to_vec();

        let mut expected: IndexMap<String, String> = IndexMap::new();
        expected.insert(
            "tree".to_string(),
            "29ff16c9c14e2652b22f8b78bb08a5a07930c147".to_string(),
        );
        expected.insert(
            "parent".to_string(),
            "206941306e8a8af65b66eaaaea388a7ae24d49a0".to_string(),
        );
        expected.insert(
            "author".to_string(),
            "Thibault Polge <thibault@thb.lt> 1527025023 +0200".to_string(),
        );
        expected.insert(
            "committer".to_string(),
            "Thibault Polge <thibault@thb.lt> 1527025044 +0200".to_string(),
        );
        expected.insert("gpgsig".to_string(), "-----BEGIN PGP SIGNATURE-----\n\niQIzBAABCAAdFiEExwXquOM8bWb4Q2zVGxM2FxoLkGQFAlsEjZQACgkQGxM2FxoL\nkGQdcBAAqPP+ln4nGDd2gETXjvOpOxLzIMEw4A9gU6CzWzm+oB8mEIKyaH0UFIPh\nrNUZ1j7/ZGFNeBDtT55LPdPIQw4KKlcf6kC8MPWP3qSu3xHqx12C5zyai2duFZUU\nwqOt9iCFCscFQYqKs3xsHI+ncQb+PGjVZA8+jPw7nrPIkeSXQV2aZb1E68wa2YIL\n3eYgTUKz34cB6tAq9YwHnZpyPx8UJCZGkshpJmgtZ3mCbtQaO17LoihnqPn4UOMr\nV75R/7FjSuPLS8NaZF4wfi52btXMSxO/u7GuoJkzJscP3p4qtwe6Rl9dc1XC8P7k\nNIbGZ5Yg5cEPcfmhgXFOhQZkD0yxcJqBUcoFpnp2vu5XJl2E5I/quIyVxUXi6O6c\n/obspcvace4wy8uO0bdVhc4nJ+Rla4InVSJaUaBeiHTW8kReSFYyMmDCzLjGIu1q\ndoU61OM3Zv1ptsLu3gUE6GU27iWYj2RWN3e3HE4Sbd89IFwLXNdSuM0ifDLZk7AQ\nWBhRhipCCgZhkj9g2NEk7jRVslti1NdN5zoQLaJNqSwO1MtxTmJ15Ksk3QP6kfLB\nQ52UWybBzpaP9HEd4XnR+HuQ4k2K0ns2KgNImsNvIyFwbpMUyUWLMPimaV1DWUXo\n5SBjDB/V/W2JBFR+XKHFJeFwYhj7DD/ocsGr4ZMx/lgc8rjIBkI=\n=lgTX\n-----END PGP SIGNATURE-----".to_string());
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
        let raw = String::from(
            "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147
parent 206941306e8a8af65b66eaaaea388a7ae24d49a0
author Thibault Polge <thibault@thb.lt> 1527025023 +0200
committer Thibault Polge <thibault@thb.lt> 1527025044 +0200

Create first draft",
        )
        .as_bytes()
        .to_vec();

        let mut expected: IndexMap<String, String> = IndexMap::new();
        expected.insert(
            "tree".to_string(),
            "29ff16c9c14e2652b22f8b78bb08a5a07930c147".to_string(),
        );
        expected.insert(
            "parent".to_string(),
            "206941306e8a8af65b66eaaaea388a7ae24d49a0".to_string(),
        );
        expected.insert(
            "author".to_string(),
            "Thibault Polge <thibault@thb.lt> 1527025023 +0200".to_string(),
        );
        expected.insert(
            "committer".to_string(),
            "Thibault Polge <thibault@thb.lt> 1527025044 +0200".to_string(),
        );
        expected.insert("message".to_string(), "Create first draft".to_string());

        let result = parse_key_value(raw, None);

        assert_eq!(expected["tree"], result["tree"]);
        assert_eq!(expected["parent"], result["parent"]);
        assert_eq!(expected["author"], result["author"]);
        assert_eq!(expected["committer"], result["committer"]);
        assert_eq!(expected["message"], result["message"]);
        assert_eq!(expected, result);
    }

    #[test]
    fn writes_key_value_object() {
        let mut input: IndexMap<String, String> = IndexMap::new();
        input.insert(
            "tree".to_string(),
            "29ff16c9c14e2652b22f8b78bb08a5a07930c147".to_string(),
        );
        input.insert(
            "parent".to_string(),
            "206941306e8a8af65b66eaaaea388a7ae24d49a0".to_string(),
        );
        input.insert(
            "author".to_string(),
            "Thibault Polge <thibault@thb.lt> 1527025023 +0200".to_string(),
        );
        input.insert(
            "committer".to_string(),
            "Thibault Polge <thibault@thb.lt> 1527025044 +0200".to_string(),
        );
        input.insert("gpgsig".to_string(), "-----BEGIN PGP SIGNATURE-----\n\niQIzBAABCAAdFiEExwXquOM8bWb4Q2zVGxM2FxoLkGQFAlsEjZQACgkQGxM2FxoL\nkGQdcBAAqPP+ln4nGDd2gETXjvOpOxLzIMEw4A9gU6CzWzm+oB8mEIKyaH0UFIPh\nrNUZ1j7/ZGFNeBDtT55LPdPIQw4KKlcf6kC8MPWP3qSu3xHqx12C5zyai2duFZUU\nwqOt9iCFCscFQYqKs3xsHI+ncQb+PGjVZA8+jPw7nrPIkeSXQV2aZb1E68wa2YIL\n3eYgTUKz34cB6tAq9YwHnZpyPx8UJCZGkshpJmgtZ3mCbtQaO17LoihnqPn4UOMr\nV75R/7FjSuPLS8NaZF4wfi52btXMSxO/u7GuoJkzJscP3p4qtwe6Rl9dc1XC8P7k\nNIbGZ5Yg5cEPcfmhgXFOhQZkD0yxcJqBUcoFpnp2vu5XJl2E5I/quIyVxUXi6O6c\n/obspcvace4wy8uO0bdVhc4nJ+Rla4InVSJaUaBeiHTW8kReSFYyMmDCzLjGIu1q\ndoU61OM3Zv1ptsLu3gUE6GU27iWYj2RWN3e3HE4Sbd89IFwLXNdSuM0ifDLZk7AQ\nWBhRhipCCgZhkj9g2NEk7jRVslti1NdN5zoQLaJNqSwO1MtxTmJ15Ksk3QP6kfLB\nQ52UWybBzpaP9HEd4XnR+HuQ4k2K0ns2KgNImsNvIyFwbpMUyUWLMPimaV1DWUXo\n5SBjDB/V/W2JBFR+XKHFJeFwYhj7DD/ocsGr4ZMx/lgc8rjIBkI=\n=lgTX\n-----END PGP SIGNATURE-----".to_string());
        input.insert("message".to_string(), "Create first draft".to_string());

        let result = write_key_value(input.clone());
        let expected = String::from(
            "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147
parent 206941306e8a8af65b66eaaaea388a7ae24d49a0
author Thibault Polge <thibault@thb.lt> 1527025023 +0200
committer Thibault Polge <thibault@thb.lt> 1527025044 +0200
gpgsig -----BEGIN PGP SIGNATURE-----

 iQIzBAABCAAdFiEExwXquOM8bWb4Q2zVGxM2FxoLkGQFAlsEjZQACgkQGxM2FxoL
 kGQdcBAAqPP+ln4nGDd2gETXjvOpOxLzIMEw4A9gU6CzWzm+oB8mEIKyaH0UFIPh
 rNUZ1j7/ZGFNeBDtT55LPdPIQw4KKlcf6kC8MPWP3qSu3xHqx12C5zyai2duFZUU
 wqOt9iCFCscFQYqKs3xsHI+ncQb+PGjVZA8+jPw7nrPIkeSXQV2aZb1E68wa2YIL
 3eYgTUKz34cB6tAq9YwHnZpyPx8UJCZGkshpJmgtZ3mCbtQaO17LoihnqPn4UOMr
 V75R/7FjSuPLS8NaZF4wfi52btXMSxO/u7GuoJkzJscP3p4qtwe6Rl9dc1XC8P7k
 NIbGZ5Yg5cEPcfmhgXFOhQZkD0yxcJqBUcoFpnp2vu5XJl2E5I/quIyVxUXi6O6c
 /obspcvace4wy8uO0bdVhc4nJ+Rla4InVSJaUaBeiHTW8kReSFYyMmDCzLjGIu1q
 doU61OM3Zv1ptsLu3gUE6GU27iWYj2RWN3e3HE4Sbd89IFwLXNdSuM0ifDLZk7AQ
 WBhRhipCCgZhkj9g2NEk7jRVslti1NdN5zoQLaJNqSwO1MtxTmJ15Ksk3QP6kfLB
 Q52UWybBzpaP9HEd4XnR+HuQ4k2K0ns2KgNImsNvIyFwbpMUyUWLMPimaV1DWUXo
 5SBjDB/V/W2JBFR+XKHFJeFwYhj7DD/ocsGr4ZMx/lgc8rjIBkI=
 =lgTX
 -----END PGP SIGNATURE-----

Create first draft",
        );
        println!("{}", result);
        println!("{}", expected);
        assert_eq!(expected, result);
    }

    #[test]
    fn parses_tree_leaf() {
        let raw = vec![
            49, 48, 48, 54, 52, 52, 32, 46, 103, 105, 116, 105, 103, 110, 111, 114, 101, 0, 234,
            140, 75, 247, 243, 95, 111, 119, 247, 93, 146, 173, 140, 232, 52, 159, 110, 129, 221,
            186,
        ];
        let (pos, result) = parse_tree_leaf(raw.clone());
        let expected = TreeLeaf {
            mode: vec![49, 48, 48, 54, 52, 52],
            path: ".gitignore".to_string(),
            sha: "ea8c4bf7f35f6f77f75d92ad8ce8349f6e81ddba".to_string(),
        };
        assert_eq!(expected, result);
        assert_eq!(raw.len(), pos);
    }

    #[test]
    fn parses_tree() {
        let raw = vec![
            49, 48, 48, 54, 52, 52, 32, 46, 103, 105, 116, 105, 103, 110, 111, 114, 101, 0, 234,
            140, 75, 247, 243, 95, 111, 119, 247, 93, 146, 173, 140, 232, 52, 159, 110, 129, 221,
            186, 49, 48, 48, 54, 52, 52, 32, 67, 97, 114, 103, 111, 46, 108, 111, 99, 107, 0, 243,
            100, 243, 179, 113, 104, 107, 102, 32, 143, 87, 114, 225, 165, 0, 96, 70, 26, 219, 139,
            49, 48, 48, 54, 52, 52, 32, 67, 97, 114, 103, 111, 46, 116, 111, 109, 108, 0, 223, 232,
            90, 134, 224, 230, 147, 79, 207, 188, 65, 197, 93, 245, 33, 236, 191, 249, 215, 111,
            52, 48, 48, 48, 48, 32, 115, 114, 99, 0, 160, 54, 249, 54, 81, 75, 136, 212, 255, 203,
            151, 175, 117, 184, 187, 77, 86, 177, 133, 50,
        ];
        let result = parse_tree(raw);
        let expected = TreeLeaf {
            mode: vec![49, 48, 48, 54, 52, 52],
            path: ".gitignore".to_string(),
            sha: "ea8c4bf7f35f6f77f75d92ad8ce8349f6e81ddba".to_string(),
        };
        let expected1 = TreeLeaf {
            mode: vec![49, 48, 48, 54, 52, 52],
            path: "Cargo.lock".to_string(),
            sha: "f364f3b371686b66208f5772e1a50060461adb8b".to_string(),
        };
        let expected2 = TreeLeaf {
            mode: vec![49, 48, 48, 54, 52, 52],
            path: "Cargo.toml".to_string(),
            sha: "dfe85a86e0e6934fcfbc41c55df521ecbff9d76f".to_string(),
        };
        let expected3 = TreeLeaf {
            mode: vec![48, 52, 48, 48, 48, 48],
            path: "src".to_string(),
            sha: "a036f936514b88d4ffcb97af75b8bb4d56b18532".to_string(),
        };
        assert_eq!(vec![expected, expected1, expected2, expected3], result);
    }

    #[test]
    fn writes_tree() {
        let raw = vec![
            49, 48, 48, 54, 52, 52, 32, 46, 103, 105, 116, 105, 103, 110, 111, 114, 101, 0, 234,
            140, 75, 247, 243, 95, 111, 119, 247, 93, 146, 173, 140, 232, 52, 159, 110, 129, 221,
            186, 49, 48, 48, 54, 52, 52, 32, 67, 97, 114, 103, 111, 46, 108, 111, 99, 107, 0, 243,
            100, 243, 179, 113, 104, 107, 102, 32, 143, 87, 114, 225, 165, 0, 96, 70, 26, 219, 139,
            49, 48, 48, 54, 52, 52, 32, 67, 97, 114, 103, 111, 46, 116, 111, 109, 108, 0, 223, 232,
            90, 134, 224, 230, 147, 79, 207, 188, 65, 197, 93, 245, 33, 236, 191, 249, 215, 111,
            52, 48, 48, 48, 48, 32, 115, 114, 99, 0, 160, 54, 249, 54, 81, 75, 136, 212, 255, 203,
            151, 175, 117, 184, 187, 77, 86, 177, 133, 50,
        ];
        let leaf = TreeLeaf {
            mode: vec![49, 48, 48, 54, 52, 52],
            path: ".gitignore".to_string(),
            sha: "ea8c4bf7f35f6f77f75d92ad8ce8349f6e81ddba".to_string(),
        };
        let leaf1 = TreeLeaf {
            mode: vec![49, 48, 48, 54, 52, 52],
            path: "Cargo.lock".to_string(),
            sha: "f364f3b371686b66208f5772e1a50060461adb8b".to_string(),
        };
        let leaf2 = TreeLeaf {
            mode: vec![49, 48, 48, 54, 52, 52],
            path: "Cargo.toml".to_string(),
            sha: "dfe85a86e0e6934fcfbc41c55df521ecbff9d76f".to_string(),
        };
        let leaf3 = TreeLeaf {
            mode: vec![48, 52, 48, 48, 48, 48],
            path: "src".to_string(),
            sha: "a036f936514b88d4ffcb97af75b8bb4d56b18532".to_string(),
        };
        let result = write_tree(vec![
            leaf.clone(),
            leaf1.clone(),
            leaf2.clone(),
            leaf3.clone(),
        ]);
        // String::from_utf8(raw.clone()).unwrap();
        // println!("{}", String::from_utf8_lossy(&result));

        assert_eq!(raw, result);
        assert_eq!(parse_tree(result.clone()), vec![leaf, leaf1, leaf2, leaf3]);
    }

    // #[test]
    // fn resolves_diferent_naming() {
    //     let result = find_object("HEAD".to_string());
    //     assert_eq!("92574eb72578916c79798565d73258ea66aa99e8", result);
    //     let result = find_object("92574eb".to_string());
    //     assert_eq!("92574eb72578916c79798565d73258ea66aa99e8", result);
    //     let result = find_object("main".to_string());
    //     assert_eq!("c1ac769cc58752966e3fb50d601bccf7d81561b4", result);
    // }
}
