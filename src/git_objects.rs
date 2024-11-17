pub trait GitObject {
    fn fmt(&self) -> String;
    fn serialize(&self) -> &[u8];
    fn deserialize(&mut self, data: Vec<u8>);
}

pub struct GitBlob {
    pub fmt: String,
    data: Vec<u8>,
}

pub struct GitCommit {
    pub fmt: String,
    data: Vec<u8>,
}

pub struct GitTree {
    pub fmt: String,
    data: Vec<u8>,
}

pub struct GitTag {
    pub fmt: String,
    data: Vec<u8>,
}

impl GitBlob {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            fmt: "blob".to_string(),
            data,
        }
    }
}
impl GitObject for GitBlob {
    fn fmt(&self) -> String {
        self.fmt.clone()
    }
    fn serialize(&self) -> &[u8] {
        &self.data
    }
    fn deserialize(&mut self, data: Vec<u8>) {
        self.data = data;
    }
}

// not implemented
impl GitCommit {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            fmt: "commit".to_string(),
            data,
        }
    }
}
impl GitObject for GitCommit {
    fn fmt(&self) -> String {
        self.fmt.clone()
    }
    fn serialize(&self) -> &[u8] {
        &self.data
    }
    fn deserialize(&mut self, data: Vec<u8>) {
        self.data = data;
    }
}

// not implemented
impl GitTree {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            fmt: "commit".to_string(),
            data,
        }
    }
}
impl GitObject for GitTree {
    fn fmt(&self) -> String {
        self.fmt.clone()
    }
    fn serialize(&self) -> &[u8] {
        &self.data
    }
    fn deserialize(&mut self, data: Vec<u8>) {
        self.data = data;
    }
}

// not implemented
impl GitTag {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            fmt: "commit".to_string(),
            data,
        }
    }
}
impl GitObject for GitTag {
    fn fmt(&self) -> String {
        self.fmt.clone()
    }
    fn serialize(&self) -> &[u8] {
        &self.data
    }
    fn deserialize(&mut self, data: Vec<u8>) {
        self.data = data;
    }
}
