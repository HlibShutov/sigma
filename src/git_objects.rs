use indexmap::IndexMap;

use crate::utils::{parse_key_value, write_key_value};

pub enum GitObject {
    Blob(GitBlob),
    Commit(GitCommit),
    Tree(GitTree),
    Tag(GitTag),
}

impl GitObject {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            GitObject::Blob(blob) => blob.serialize(),
            GitObject::Commit(commit) => commit.serialize(),
            GitObject::Tree(tree) => tree.serialize(),
            GitObject::Tag(tag) => tag.serialize(),
        }
    }
    pub fn deserialize(&self) -> Vec<u8> {
        match self {
            GitObject::Blob(blob) => GitBlob::deserialize(blob.data.clone()),
            GitObject::Commit(commit) => GitCommit::deserialize(commit.data.clone()),
            GitObject::Tree(tree) => GitTree::deserialize(tree.data.clone()),
            GitObject::Tag(tag) => GitTag::deserialize(tag.data.clone()),
        }
    }
}

pub struct GitBlob {
    data: Vec<u8>,
}

pub struct GitCommit {
    data: Vec<u8>,
    kv: IndexMap<String, String>,
}

// not implemented
pub struct GitTree {
    data: Vec<u8>,
}

// not implemented
pub struct GitTag {
    data: Vec<u8>,
}

impl GitBlob {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: GitBlob::deserialize(data),
        }
    }
    fn serialize(&self) -> Vec<u8> {
        self.data.clone()
    }
    fn deserialize(data: Vec<u8>) -> Vec<u8> {
        data
    }
}

impl GitCommit {
    pub fn new(data: Vec<u8>) -> Self {
        let data = String::from_utf8(data).unwrap().trim_end().to_string().into_bytes();
        Self {
            data: GitCommit::deserialize(data.clone()),
            kv: parse_key_value(data, None),
        }
    }
    fn serialize(&self) -> Vec<u8> {
        write_key_value(self.kv.clone()).into_bytes()
    }
    pub fn deserialize(raw: Vec<u8>) -> Vec<u8> {
        let raw = String::from_utf8(raw).unwrap().trim_end().to_string().into_bytes();
        write_key_value(parse_key_value(raw, None)).into_bytes()
    }
}

// not implemented
impl GitTree {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: GitTree::deserialize(data),
        }
    }
    fn serialize(&self) -> Vec<u8> {
        self.data.clone()
    }
    fn deserialize(data: Vec<u8>) -> Vec<u8> {
        data
    }
}

// not implemented
impl GitTag {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: GitTag::deserialize(data),
        }
    }
    fn serialize(&self) -> Vec<u8> {
        self.data.clone()
    }
    fn deserialize(data: Vec<u8>) -> Vec<u8> {
        data
    }
}
