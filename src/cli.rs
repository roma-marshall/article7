use sealed::contact::validate_alias;
use sealed::error::{Error, Result};
use sealed::message::{self, SenderTrust};
use sealed::protocol::MAX_BODY_LEN;
use sealed::storage::{StatePaths, consume_blob, read_blob, write_new_private};
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

const USAGE: &str = "Usage:\n  sealed init [--unlock-key PATH]\n  sealed identity export\n  sealed trust PROFILE [--name NAME]\n  sealed seal CONTACT [--unlock-key PATH] [--output BLOB]\n  sealed open BLOB [--unlock-key PATH] [--keep]";

pub fn run() -> Result<()> {
    let mut args = env::args_os();
    let _program = args.next();
    let command = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| Error::Usage(USAGE.to_owned()))?;
    let remaining: Vec<OsString> = args.collect();
    let paths = StatePaths::discover()?;

    match command.as_str() {
        "init" => command_init(&paths, &remaining),
        "identity" => command_identity(&paths, &remaining),
        "trust" => command_trust(&paths, &remaining),
        "seal" => command_seal(&paths, &remaining),
        "open" => command_open(&paths, &remaining),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(Error::Usage(USAGE.to_owned())),
    }
}

fn command_init(paths: &StatePaths, args: &[OsString]) -> Result<()> {
    let (positionals, unlock_path, _, _) = parse_options(args, false, false)?;
    if !positionals.is_empty() {
        return Err(Error::Usage(USAGE.to_owned()));
    }
    let unlock_path = resolve_unlock_path(unlock_path, true)?;
    eprintln!("Generating identity using the operating-system CSPRNG...");
    let profile = paths.initialize(&unlock_path)?;
    eprintln!("Identity initialized.");
    eprintln!("Fingerprint: {}", profile.formatted_fingerprint());
    eprintln!("Encrypted identity: {}", paths.identity_encrypted.display());
    eprintln!("Unlock key: {}", unlock_path.display());
    eprintln!("Keep the unlock key separate. Losing it makes the identity unrecoverable.");
    Ok(())
}

fn command_identity(paths: &StatePaths, args: &[OsString]) -> Result<()> {
    if args.len() != 1 || args[0] != "export" {
        return Err(Error::Usage(USAGE.to_owned()));
    }
    let profile = paths.export_profile()?;
    io::stdout().write_all(&profile.encode())?;
    Ok(())
}

fn command_trust(paths: &StatePaths, args: &[OsString]) -> Result<()> {
    let (positionals, _, alias_option, _) = parse_options(args, true, false)?;
    if positionals.len() != 1 {
        return Err(Error::Usage(USAGE.to_owned()));
    }
    let source = PathBuf::from(&positionals[0]);
    let alias = match alias_option {
        Some(alias) => alias,
        None => source
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| validate_alias(value))
            .ok_or(Error::InvalidInput(
                "cannot derive a safe contact name; use --name NAME",
            ))?
            .to_owned(),
    };
    let profile = paths.trust_profile(&source, &alias)?;
    eprintln!("Pinned contact: {alias}");
    eprintln!("Fingerprint: {}", profile.formatted_fingerprint());
    eprintln!("Verify this fingerprint through an independent trusted channel.");
    Ok(())
}

fn command_seal(paths: &StatePaths, args: &[OsString]) -> Result<()> {
    let (positionals, unlock_path, _, output_path) = parse_options(args, false, true)?;
    if positionals.len() != 1 {
        return Err(Error::Usage(USAGE.to_owned()));
    }
    let alias = positionals[0]
        .to_str()
        .ok_or(Error::InvalidInput("contact name is not valid UTF-8"))?;
    let contact = paths.contact(alias)?;
    let unlock_path = resolve_unlock_path(unlock_path, false)?;
    let (secrets, profile) = paths.load_identity(&unlock_path)?;
    if io::stdin().is_terminal() {
        eprintln!("Enter the letter body, then send EOF (Ctrl-D on Unix, Ctrl-Z then Enter on Windows):");
    }
    let mut body = zeroize::Zeroizing::new(Vec::new());
    io::stdin()
        .take((MAX_BODY_LEN as u64) + 1)
        .read_to_end(&mut body)?;
    if body.len() > MAX_BODY_LEN {
        return Err(Error::InvalidInput("message body exceeds the 1 MiB limit"));
    }
    let blob = message::seal(&secrets, &profile, &contact.profile, &body)?;
    match output_path {
        Some(path) => {
            write_new_private(&path, &blob)?;
            eprintln!("Sealed {} bytes to {}.", blob.len(), path.display());
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(&blob)?;
            stdout.flush()?;
            eprintln!("Sealed {} bytes.", blob.len());
        }
    }
    Ok(())
}

fn command_open(paths: &StatePaths, args: &[OsString]) -> Result<()> {
    let (positionals, unlock_path, _, keep) = parse_open_options(args)?;
    if positionals.len() != 1 {
        return Err(Error::Usage(USAGE.to_owned()));
    }
    let blob_path = PathBuf::from(&positionals[0]);
    let unlock_path = resolve_unlock_path(unlock_path, false)?;
    let (secrets, profile) = paths.load_identity(&unlock_path)?;
    let contacts = paths.all_contacts()?;
    let blob = read_blob(&blob_path).map_err(|_| Error::CannotOpen)?;
    let letter = message::open(&secrets, &profile, &contacts, &blob)?;

    eprintln!("INTEGRITY: VALID");
    eprintln!("SIGNATURE: VALID");
    eprintln!("RECIPIENT: VALID");
    match &letter.sender_trust {
        SenderTrust::Pinned { alias } => eprintln!("SENDER: PINNED ({alias})"),
        SenderTrust::Unknown => eprintln!("SENDER: UNKNOWN — signature is valid but identity is not pinned"),
    }
    eprintln!(
        "SENDER FINGERPRINT: {}",
        letter.sender.formatted_fingerprint()
    );

    let mut stdout = io::stdout().lock();
    stdout.write_all(&letter.body)?;
    stdout.flush()?;
    drop(stdout);
    if !keep {
        consume_blob(&blob_path)?;
        eprintln!("CIPHERTEXT: CONSUMED (logical deletion only)");
    }
    Ok(())
}

fn parse_options(
    args: &[OsString],
    allow_name: bool,
    allow_output: bool,
) -> Result<(Vec<OsString>, Option<PathBuf>, Option<String>, Option<PathBuf>)> {
    let mut positionals = Vec::new();
    let mut unlock_path = None;
    let mut alias = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str() {
            Some("--unlock-key") => {
                index += 1;
                unlock_path = Some(PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| Error::Usage(USAGE.to_owned()))?,
                ));
            }
            Some("--name") if allow_name => {
                index += 1;
                alias = Some(
                    args.get(index)
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| Error::Usage(USAGE.to_owned()))?
                        .to_owned(),
                );
            }
            Some("--output") if allow_output => {
                index += 1;
                output = Some(PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| Error::Usage(USAGE.to_owned()))?,
                ));
            }
            Some(value) if value.starts_with('-') => {
                return Err(Error::Usage(USAGE.to_owned()));
            }
            _ => positionals.push(args[index].clone()),
        }
        index += 1;
    }
    Ok((positionals, unlock_path, alias, output))
}

fn parse_open_options(
    args: &[OsString],
) -> Result<(Vec<OsString>, Option<PathBuf>, Option<String>, bool)> {
    let mut filtered = Vec::new();
    let mut keep = false;
    for arg in args {
        if arg == "--keep" {
            if keep {
                return Err(Error::Usage(USAGE.to_owned()));
            }
            keep = true;
        } else {
            filtered.push(arg.clone());
        }
    }
    let (positionals, unlock, name, output) = parse_options(&filtered, false, false)?;
    if output.is_some() {
        return Err(Error::Usage(USAGE.to_owned()));
    }
    Ok((positionals, unlock, name, keep))
}

fn resolve_unlock_path(supplied: Option<PathBuf>, initializing: bool) -> Result<PathBuf> {
    if let Some(path) = supplied {
        return Ok(path);
    }
    if let Some(path) = env::var_os("SEALED_UNLOCK_KEY") {
        return Ok(PathBuf::from(path));
    }
    let prompt = if initializing {
        "Choose a new location for the unlock key (prefer removable/offline media): "
    } else {
        "Unlock key path: "
    };
    read_path_from_terminal(prompt)
}

fn read_path_from_terminal(prompt: &str) -> Result<PathBuf> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let file = terminal_input()?;
    let mut reader = BufReader::new(file);
    let mut input = String::new();
    reader.read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidInput("unlock key path cannot be empty"));
    }
    Ok(Path::new(trimmed).to_path_buf())
}

#[cfg(unix)]
fn terminal_input() -> Result<File> {
    File::open("/dev/tty").map_err(Error::from)
}

#[cfg(windows)]
fn terminal_input() -> Result<File> {
    File::open("CONIN$").map_err(Error::from)
}

#[cfg(not(any(unix, windows)))]
fn terminal_input() -> Result<File> {
    Err(Error::InvalidInput(
        "supply --unlock-key PATH on this platform",
    ))
}

