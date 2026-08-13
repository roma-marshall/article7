use sealed::contact::validate_alias;
use sealed::error::{Error, Result};
use sealed::identity::PublicProfile;
use sealed::message::{self, OpenedLetter, SenderTrust};
use sealed::protocol::MAX_BODY_LEN;
use sealed::storage::{StatePaths, consume_blob, read_blob, write_new_private};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const USAGE: &str = "Usage:\n  sealed                         Interactive terminal\n  sealed init [--unlock-key PATH]\n  sealed identity export\n  sealed trust PROFILE [--name NAME]\n  sealed seal CONTACT [--unlock-key PATH] [--output BLOB]\n  sealed open BLOB [--unlock-key PATH] [--keep]";

const MENU: &str = "  1  Create identity\n  2  Export public profile\n  3  Add or verify contact\n  4  Seal a letter\n  5  Open a letter\n  6  Show identity and contacts\n  0  Exit";

pub fn run() -> Result<()> {
    let mut args = env::args_os();
    let _program = args.next();
    let command = match args.next() {
        Some(value) => value
            .into_string()
            .map_err(|_| Error::Usage(USAGE.to_owned()))?,
        None if io::stdin().is_terminal() && io::stdout().is_terminal() => {
            return interactive();
        }
        None => return Err(Error::Usage(USAGE.to_owned())),
    };
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

fn interactive() -> Result<()> {
    let paths = StatePaths::discover()?;
    let style = TerminalStyle::detect();
    print_banner(&style);

    loop {
        print_state_summary(&paths, &style);
        eprintln!("\n{MENU}\n");
        let choice = prompt("Choose an action", Some("0"))?;
        let action = match choice.trim() {
            "1" => wizard_init(&paths, &style),
            "2" => wizard_export(&paths, &style),
            "3" => wizard_trust(&paths, &style),
            "4" => wizard_seal(&paths, &style),
            "5" => wizard_open(&paths, &style),
            "6" => wizard_show(&paths, &style),
            "0" | "q" | "quit" | "exit" => {
                eprintln!("\n{} Goodbye.\n", style.dim("•"));
                return Ok(());
            }
            _ => {
                eprintln!("\n{} Enter a number from 0 to 6.\n", style.warning());
                continue;
            }
        };

        match action {
            Ok(()) => eprintln!("\n{} Done.\n", style.success()),
            Err(error) => eprintln!("\n{} {error}\n", style.failure()),
        }
        wait_for_enter("Press Enter to return to the menu")?;
    }
}

fn print_banner(style: &TerminalStyle) {
    eprintln!(
        "\n{}\n{}\n{}\n",
        style.bold("╭────────────────────────────────────────╮"),
        style.bold("│  SEALED  ·  private one-time letters  │"),
        style.bold("╰────────────────────────────────────────╯")
    );
    eprintln!(
        "{} Experimental and unaudited. The transport is untrusted.",
        style.warning()
    );
}

fn print_state_summary(paths: &StatePaths, style: &TerminalStyle) {
    eprintln!("\n{}", style.bold("Status"));
    match paths.export_profile() {
        Ok(profile) => {
            eprintln!("  {} Identity ready", style.success());
            eprintln!("     {}", profile.formatted_fingerprint());
        }
        Err(_) => eprintln!("  {} No identity yet — start with option 1", style.dim("○")),
    }
    match paths.all_contacts() {
        Ok(contacts) => eprintln!("  {} {} pinned contact(s)", style.dim("•"), contacts.len()),
        Err(_) => eprintln!("  {} Contact store needs attention", style.warning()),
    }
}

fn wizard_init(paths: &StatePaths, style: &TerminalStyle) -> Result<()> {
    eprintln!("\n{}", style.bold("Create identity"));
    eprintln!("The encrypted identity stays in: {}", paths.root.display());
    eprintln!("Store the unlock key separately. Losing it is permanent.");
    let unlock_path = prompt_path("Unlock-key file path", None)?;
    let parent = unlock_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        let create = prompt_yes_no(
            &format!("Directory {} does not exist. Create it?", parent.display()),
            true,
        )?;
        if !create {
            return Err(Error::InvalidInput("identity creation cancelled"));
        }
        fs::create_dir_all(parent)?;
    }
    eprintln!(
        "{} Generating keys from the operating-system CSPRNG...",
        style.dim("→")
    );
    let profile = paths.initialize(&unlock_path)?;
    eprintln!("{} Identity created", style.success());
    eprintln!("Fingerprint: {}", profile.formatted_fingerprint());
    eprintln!("Unlock key: {}", unlock_path.display());
    Ok(())
}

fn wizard_export(paths: &StatePaths, style: &TerminalStyle) -> Result<()> {
    eprintln!("\n{}", style.bold("Export public profile"));
    let profile = paths
        .export_profile()
        .map_err(|_| Error::NotFound("identity is not initialized; choose option 1 first"))?;
    let destination = prompt_path("Save public profile as", Some("sealed-profile.pub"))?;
    write_new_private(&destination, &profile.encode())?;
    eprintln!("{} Saved: {}", style.success(), destination.display());
    eprintln!("Fingerprint: {}", profile.formatted_fingerprint());
    eprintln!("This file is public. Verify the fingerprint out of band.");
    Ok(())
}

fn wizard_trust(paths: &StatePaths, style: &TerminalStyle) -> Result<()> {
    eprintln!("\n{}", style.bold("Add or verify contact"));
    let profile_path = prompt_path("Received .pub file", None)?;
    let default_alias = profile_path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| validate_alias(value));
    let alias = prompt("Contact name", default_alias)?;
    if !validate_alias(&alias) {
        return Err(Error::InvalidInput(
            "contact name may contain only letters, digits, '-' or '_'",
        ));
    }
    let profile = paths.trust_profile(&profile_path, &alias)?;
    eprintln!("{} Contact pinned: {alias}", style.success());
    eprintln!("Fingerprint: {}", profile.formatted_fingerprint());
    eprintln!(
        "{} Compare the full fingerprint in person or by voice before sending.",
        style.warning()
    );
    Ok(())
}

fn wizard_seal(paths: &StatePaths, style: &TerminalStyle) -> Result<()> {
    eprintln!("\n{}", style.bold("Seal a letter"));
    let contacts = paths.all_contacts()?;
    if contacts.is_empty() {
        return Err(Error::NotFound(
            "no pinned contacts; import a public profile with option 3",
        ));
    }
    for (index, contact) in contacts.iter().enumerate() {
        eprintln!(
            "  {}  {}  {}",
            index + 1,
            contact.alias,
            style.dim(&short_fingerprint(&contact.profile))
        );
    }
    let selected = prompt("Recipient number", None)?;
    let selected = selected
        .parse::<usize>()
        .ok()
        .and_then(|number| number.checked_sub(1))
        .and_then(|index| contacts.get(index))
        .ok_or(Error::InvalidInput("invalid recipient number"))?;
    let unlock_path = prompt_unlock_path(false)?;
    let output_default = format!("letter-for-{}.bin", selected.alias);
    let output_path = prompt_path("Save encrypted letter as", Some(&output_default))?;

    eprintln!("\nWrite the letter. Finish with a single dot on a new line:");
    eprintln!(
        "{}",
        style.dim("──────────────────────────────────────────")
    );
    let body = read_multiline_letter()?;
    if body.is_empty() {
        return Err(Error::InvalidInput("letter body cannot be empty"));
    }
    let (secrets, profile) = paths.load_identity(&unlock_path)?;
    let blob = message::seal(&secrets, &profile, &selected.profile, &body)?;
    write_new_private(&output_path, &blob)?;
    eprintln!("{} Letter sealed for {}", style.success(), selected.alias);
    eprintln!("File: {} ({} bytes)", output_path.display(), blob.len());
    eprintln!("Send this file through any byte-preserving transport.");
    Ok(())
}

fn wizard_open(paths: &StatePaths, style: &TerminalStyle) -> Result<()> {
    eprintln!("\n{}", style.bold("Open a letter"));
    let blob_path = prompt_path("Encrypted letter file", None)?;
    let unlock_path = prompt_unlock_path(false)?;
    let consume = prompt_yes_no("Delete the ciphertext after a successful open?", true)?;
    let (secrets, profile) = paths.load_identity(&unlock_path)?;
    let contacts = paths.all_contacts()?;
    let blob = read_blob(&blob_path).map_err(|_| Error::CannotOpen)?;
    let letter = message::open(&secrets, &profile, &contacts, &blob)?;

    eprintln!("\n{}", style.bold("Verification"));
    print_letter_status(&letter, style);
    eprintln!("\n{}", style.bold("Letter"));
    eprintln!(
        "{}",
        style.dim("──────────────────────────────────────────")
    );
    let mut stdout = io::stdout().lock();
    stdout.write_all(&letter.body)?;
    if !letter.body.ends_with(b"\n") {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    drop(stdout);
    eprintln!(
        "{}",
        style.dim("──────────────────────────────────────────")
    );

    if consume {
        consume_blob(&blob_path)?;
        eprintln!(
            "{} Ciphertext consumed (logical deletion only)",
            style.success()
        );
    } else {
        eprintln!(
            "{} Ciphertext retained: {}",
            style.warning(),
            blob_path.display()
        );
    }
    Ok(())
}

fn wizard_show(paths: &StatePaths, style: &TerminalStyle) -> Result<()> {
    eprintln!("\n{}", style.bold("Identity"));
    let profile = paths
        .export_profile()
        .map_err(|_| Error::NotFound("identity is not initialized; choose option 1 first"))?;
    eprintln!("Fingerprint: {}", profile.formatted_fingerprint());
    eprintln!("State: {}", paths.root.display());
    eprintln!("\n{}", style.bold("Pinned contacts"));
    let contacts = paths.all_contacts()?;
    if contacts.is_empty() {
        eprintln!("  {} None", style.dim("○"));
    } else {
        for contact in contacts {
            eprintln!("  {} {}", style.success(), contact.alias);
            eprintln!("     {}", contact.profile.formatted_fingerprint());
        }
    }
    Ok(())
}

fn print_letter_status(letter: &OpenedLetter, style: &TerminalStyle) {
    eprintln!("  {} Integrity valid", style.success());
    eprintln!("  {} Signature valid", style.success());
    eprintln!("  {} Recipient valid", style.success());
    match &letter.sender_trust {
        SenderTrust::Pinned { alias } => {
            eprintln!("  {} Sender pinned: {alias}", style.success())
        }
        SenderTrust::Mismatch { alias } => {
            eprintln!(
                "  {} Sender mismatch: {alias} — POSSIBLE MITM",
                style.failure()
            )
        }
        SenderTrust::Unknown => {
            eprintln!("  {} Sender is valid but not pinned", style.warning())
        }
    }
    eprintln!("     {}", letter.sender.formatted_fingerprint());
}

fn short_fingerprint(profile: &PublicProfile) -> String {
    let full = profile.formatted_fingerprint();
    format!("{}…", full.chars().take(19).collect::<String>())
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    match default {
        Some(value) => eprint!("{label} [{value}]: "),
        None => eprint!("{label}: "),
    }
    io::stderr().flush()?;
    let input = read_terminal_line()?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return default
            .map(str::to_owned)
            .ok_or(Error::InvalidInput("input cannot be empty"));
    }
    Ok(trimmed.to_owned())
}

fn prompt_path(label: &str, default: Option<&str>) -> Result<PathBuf> {
    let entered = prompt(label, default)?;
    expand_home_path(&entered)
}

fn prompt_unlock_path(initializing: bool) -> Result<PathBuf> {
    if let Some(path) = env::var_os("SEALED_UNLOCK_KEY") {
        return Ok(PathBuf::from(path));
    }
    let label = if initializing {
        "New unlock-key file path"
    } else {
        "Unlock-key file path"
    };
    prompt_path(label, None)
}

fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "Y/n" } else { "y/N" };
    let answer = prompt(label, Some(default))?;
    if answer == default {
        return Ok(default_yes);
    }
    match answer.to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Err(Error::InvalidInput("answer with y or n")),
    }
}

fn wait_for_enter(label: &str) -> Result<()> {
    eprint!("{label}...");
    io::stderr().flush()?;
    let _ = read_terminal_line()?;
    Ok(())
}

fn read_terminal_line() -> Result<String> {
    let file = terminal_input()?;
    let mut reader = BufReader::new(file);
    let mut input = String::new();
    reader.read_line(&mut input)?;
    Ok(input)
}

fn read_multiline_letter() -> Result<Zeroizing<Vec<u8>>> {
    let file = terminal_input()?;
    let mut reader = BufReader::new(file);
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(Error::InvalidInput(
                "terminal input ended before the final dot",
            ));
        }
        if line.trim_end_matches(['\r', '\n']) == "." {
            break;
        }
        if body.len().saturating_add(line.len()) > MAX_BODY_LEN {
            return Err(Error::InvalidInput("message body exceeds the 1 MiB limit"));
        }
        body.extend_from_slice(line.as_bytes());
    }
    Ok(body)
}

fn expand_home_path(input: &str) -> Result<PathBuf> {
    if input == "~" {
        return home_directory();
    }
    if let Some(remainder) = input.strip_prefix("~/") {
        return Ok(home_directory()?.join(remainder));
    }
    Ok(PathBuf::from(input))
}

fn home_directory() -> Result<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or(Error::NotFound("home directory is unavailable"))
}

struct TerminalStyle {
    color: bool,
}

impl TerminalStyle {
    fn detect() -> Self {
        Self {
            color: io::stderr().is_terminal() && env::var_os("NO_COLOR").is_none(),
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    fn success(&self) -> String {
        self.paint("32", "✓")
    }

    fn warning(&self) -> String {
        self.paint("33", "!")
    }

    fn failure(&self) -> String {
        self.paint("31", "×")
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
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
        eprintln!(
            "Enter the letter body, then send EOF (Ctrl-D on Unix, Ctrl-Z then Enter on Windows):"
        );
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
        SenderTrust::Mismatch { alias } => {
            eprintln!("SENDER: MISMATCH ({alias}) — POSSIBLE MITM")
        }
        SenderTrust::Unknown => {
            eprintln!("SENDER: UNKNOWN — signature is valid but identity is not pinned")
        }
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
) -> Result<(
    Vec<OsString>,
    Option<PathBuf>,
    Option<String>,
    Option<PathBuf>,
)> {
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
