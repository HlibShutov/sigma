#[derive(Debug, PartialEq)]
pub struct IndexEntry {
    pub ctime: u32,
    pub ctime_n: u32,
    pub mtime: u32,
    pub mtime_n: u32,
    pub device: u32,
    pub ino: u32,
    pub mode_type: u32,
    pub mode_perms: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u32,
    pub sha: String,
    pub path: String,
}
