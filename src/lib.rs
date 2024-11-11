use std::path::PathBuf;
use ini::Ini;
use std::fs;
use std::fs::File;
use std::io::Write;

pub fn cmd_init(path: Vec<String>) {
    let repo_path = if path.len() != 1 { "." } else { path[0].as_str() };
    match repo_create(repo_path.into()) {
        Err(RepoErrors::ConfigFileError) => panic!("Failed to read config file"),
        Err(RepoErrors::ConfigError) => panic!("Invalid config file"),
        Err(RepoErrors::FormatVersionError) => panic!("SIGMA only supports 0 format version"),
        Ok(_) => println!("Created empty repo"),
    };
}

#[derive(Debug)]
enum RepoErrors {
    ConfigFileError,
    ConfigError,
    FormatVersionError,
}

struct GitRepository {
    worktree: PathBuf,
    gitdir: PathBuf,
    config: Option<Ini>,
}

impl GitRepository {
    fn new(path: PathBuf, force: bool) -> Result<Self, RepoErrors> {
        let mut gitdir = path.clone();
        gitdir.push(".git/");

        let mut config_file_path = gitdir.clone();
        config_file_path.push("config");
        let config = if !force {
            let config_file = Ini::load_from_file(config_file_path).map_err(|_| RepoErrors::ConfigFileError)?;
            let section = config_file.section(Some("core")).unwrap();
            let repositoryformatversion = section.get("repositoryformatversion").unwrap();
            if repositoryformatversion.parse::<u8>().map_err(|_| RepoErrors::ConfigError)? != 0 {
                return Err(RepoErrors::FormatVersionError);
            };
            Some(config_file)
        } else {
            None
        };

        Ok(Self { worktree: path, gitdir, config })
    }
    fn repo_path(&self, path: &str) -> PathBuf {
        let mut repo_gitdir = self.gitdir.clone();
        repo_gitdir.push(path);
        repo_gitdir
    }
}

fn repo_create(path: PathBuf) -> Result<(), RepoErrors> {
    let repo = GitRepository::new(path, true)?;

    fs::create_dir_all(repo.repo_path("objects/")).expect("Failed to creacte objects dir");
    fs::create_dir_all(repo.repo_path("refs/tags/")).expect("Failed to creacte refs/tags dir");
    fs::create_dir_all(repo.repo_path("refs/heads/")).expect("Failed to creacte refs/heads dir");

    let mut head_file = File::create_new(repo.repo_path("HEAD")).expect("Failed to create config file");
    head_file.write_all("ref: refs/heads/master\n".as_bytes()).expect("Failed to wrtie default HEAD");

    let mut description_file = File::create_new(repo.repo_path("description")).expect("Failed to create description file");
    description_file.write_all("Unnamed repository; edit this file 'description' to name the repository.\n".as_bytes()).expect("Failed to wrtie default description");

    File::create_new(repo.repo_path("config")).expect("Failed to create config file");
    let mut config = Ini::new();
    config.with_section(Some("core"))
        .set("repositoryformatversion", "0")
        .set("filemode", "false")
        .set("bare", "false");

    config.write_to_file(repo.repo_path("config")).expect("Failed to write settings");

    Ok(())
}
