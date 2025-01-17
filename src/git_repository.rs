use ini::Ini;
use std::path::PathBuf;

#[derive(Debug)]
pub enum RepoErrors {
    ConfigFileError,
    ConfigError,
    FormatVersionError,
    NotFound,
}

#[derive(Clone)]
pub struct GitRepository {
    pub worktree: PathBuf,
    gitdir: PathBuf,
    config: Option<Ini>,
}

impl GitRepository {
    pub fn new(path: PathBuf, force: bool) -> Result<Self, RepoErrors> {
        let gitdir = path.join(".git/");

        let config_file_path = gitdir.join("config");
        let config = if !force {
            let config_file =
                Ini::load_from_file(config_file_path).map_err(|_| RepoErrors::ConfigFileError)?;
            let section = config_file.section(Some("core")).unwrap();
            let repositoryformatversion = section.get("repositoryformatversion").unwrap();
            if repositoryformatversion
                .parse::<u8>()
                .map_err(|_| RepoErrors::ConfigError)?
                != 0
            {
                return Err(RepoErrors::FormatVersionError);
            };
            Some(config_file)
        } else {
            None
        };

        Ok(Self {
            worktree: path,
            gitdir,
            config,
        })
    }
    pub fn repo_path(&self, path: &str) -> PathBuf {
        self.gitdir.join(path)
    }
}
