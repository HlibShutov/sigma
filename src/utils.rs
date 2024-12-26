use crate::git_objects::*;
use crate::git_repository::{GitRepository, RepoErrors};
use indexmap::IndexMap;
use ini::Ini;
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use sha1::{Digest, Sha1};
use std::fs::{self, exists, File};
use std::io::Write;
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

    let sha = raw[null + 1..null + 21]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
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
        // println!("{:?}", String::from_utf8(result.clone()).unwrap());
        // println!("{:?}", raw);
        // println!("{}", String::from_utf8(raw.clone()).unwrap());
        assert_eq!(raw, result);
        assert_eq!(parse_tree(result), vec![leaf, leaf1, leaf2, leaf3]);
    }
}
