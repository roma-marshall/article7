use crate::contact::{Contact, validate_alias};
use crate::entropy::random_array;
use crate::error::{Error, Result};
use crate::identity::{
    IdentitySecrets, PublicProfile, decrypt_private_identity, encode_unlock_key,
    encrypt_private_identity, parse_unlock_key,
};
use crate::protocol::MAX_BLOB_LEN;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct StatePaths {
    pub root: PathBuf,
    pub identity_public: PathBuf,
    pub identity_encrypted: PathBuf,
    pub contacts: PathBuf,
}

impl StatePaths {
    pub fn discover() -> Result<Self> {
        let root = match env::var_os("SEALED_HOME") {
            Some(path) => PathBuf::from(path),
            None => {
                let base = env::var_os("HOME")
                    .or_else(|| env::var_os("USERPROFILE"))
                    .ok_or(Error::NotFound(
                        "home directory is unavailable; set SEALED_HOME",
                    ))?;
                PathBuf::from(base).join(".sealed")
            }
        };
        Ok(Self::from_root(root))
    }

    pub fn from_root(root: PathBuf) -> Self {
        Self {
            identity_public: root.join("identity").join("identity.pub"),
            identity_encrypted: root.join("identity").join("identity.key.enc"),
            contacts: root.join("contacts"),
            root,
        }
    }

    pub fn initialize(&self, unlock_path: &Path) -> Result<PublicProfile> {
        reject_existing(&self.identity_public, "identity already exists")?;
        reject_existing(&self.identity_encrypted, "identity already exists")?;
        reject_existing(unlock_path, "unlock key destination already exists")?;
        let unlock_parent = unlock_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ensure_real_directory(unlock_parent)?;

        create_private_directory(&self.root)?;
        create_private_directory(
            self.identity_public
                .parent()
                .ok_or(Error::InvalidInput("identity path has no parent"))?,
        )?;
        create_private_directory(&self.contacts)?;

        let unlock_key = Zeroizing::new(random_array::<32>()?);
        let (secrets, profile) = IdentitySecrets::generate()?;
        let encrypted = encrypt_private_identity(&secrets, &unlock_key)?;

        write_new_private(unlock_path, &encode_unlock_key(&unlock_key))?;
        write_new_private(&self.identity_public, &profile.encode())?;
        if let Err(error) = write_new_private(&self.identity_encrypted, &encrypted) {
            let _ = fs::remove_file(&self.identity_public);
            return Err(error);
        }
        Ok(profile)
    }

    pub fn export_profile(&self) -> Result<PublicProfile> {
        let bytes = read_regular_limited(&self.identity_public, 512)?;
        PublicProfile::parse(&bytes)
    }

    pub fn load_identity(&self, unlock_path: &Path) -> Result<(IdentitySecrets, PublicProfile)> {
        let unlock_bytes = Zeroizing::new(read_regular_limited(unlock_path, 128)?);
        let unlock_key = parse_unlock_key(&unlock_bytes)?;
        let encrypted = read_regular_limited(&self.identity_encrypted, 512)?;
        let profile = self.export_profile()?;
        let secrets = decrypt_private_identity(&encrypted, &unlock_key)
            .map_err(|_| Error::InvalidInput("cannot unlock identity"))?;
        if secrets.public_profile() != profile {
            return Err(Error::InvalidInput(
                "encrypted identity does not match public identity",
            ));
        }
        Ok((secrets, profile))
    }

    pub fn trust_profile(&self, source: &Path, alias: &str) -> Result<PublicProfile> {
        if !validate_alias(alias) {
            return Err(Error::InvalidInput(
                "contact name must contain only ASCII letters, digits, '-' or '_'",
            ));
        }
        let bytes = read_regular_limited(source, 512)?;
        let profile = PublicProfile::parse(&bytes)?;
        create_private_directory(&self.contacts)?;
        let destination = self.contacts.join(format!("{alias}.contact"));
        if destination.exists() {
            let pinned = PublicProfile::parse(&read_regular_limited(&destination, 512)?)?;
            if pinned == profile {
                return Ok(profile);
            }
            return Err(Error::IdentityMismatch);
        }
        write_new_private(&destination, &profile.encode())?;
        Ok(profile)
    }

    pub fn contact(&self, alias: &str) -> Result<Contact> {
        if !validate_alias(alias) {
            return Err(Error::InvalidInput("invalid contact name"));
        }
        let path = self.contacts.join(format!("{alias}.contact"));
        let bytes = read_regular_limited(&path, 512)
            .map_err(|error| map_not_found(error, "contact is not pinned"))?;
        Ok(Contact {
            alias: alias.to_owned(),
            profile: PublicProfile::parse(&bytes)?,
        })
    }

    pub fn all_contacts(&self) -> Result<Vec<Contact>> {
        if !self.contacts.exists() {
            return Ok(Vec::new());
        }
        ensure_real_directory(&self.contacts)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.contacts)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) == Some("contact") {
                paths.push(path);
            }
        }
        paths.sort();
        let mut contacts = Vec::with_capacity(paths.len());
        for path in paths {
            let alias = path
                .file_stem()
                .and_then(|value| value.to_str())
                .filter(|value| validate_alias(value))
                .ok_or(Error::InvalidInput("invalid contact filename"))?
                .to_owned();
            let profile = PublicProfile::parse(&read_regular_limited(&path, 512)?)?;
            contacts.push(Contact { alias, profile });
        }
        Ok(contacts)
    }
}

pub fn read_blob(path: &Path) -> Result<Vec<u8>> {
    read_regular_limited(path, MAX_BLOB_LEN)
}

pub fn consume_blob(path: &Path) -> Result<()> {
    ensure_regular_file(path)?;
    fs::remove_file(path)?;
    Ok(())
}

pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_real_directory(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_create_mode(&mut options);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_private_permissions(path)?;
    Ok(())
}

fn read_regular_limited(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    ensure_regular_file(path)?;
    let file = File::open(path)?;
    let declared = usize::try_from(file.metadata()?.len())
        .map_err(|_| Error::InvalidInput("file is too large"))?;
    if declared > maximum {
        return Err(Error::InvalidInput("file is too large"));
    }
    let mut bytes = Vec::with_capacity(declared);
    file.take((maximum as u64) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::InvalidInput("file is too large"));
    }
    Ok(bytes)
}

fn reject_existing(path: &Path, message: &'static str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::InvalidInput(message)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn ensure_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::InvalidInput("path is not a regular file"));
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::InvalidInput("path is not a real directory"));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        ensure_real_directory(path)?;
        set_private_permissions(path)?;
        return Ok(());
    }
    fs::create_dir(path)?;
    set_private_permissions(path)?;
    Ok(())
}

fn map_not_found(error: Error, message: &'static str) -> Error {
    match error {
        Error::Io(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
            Error::NotFound(message)
        }
        other => other,
    }
}

#[cfg(unix)]
fn set_private_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_create_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

