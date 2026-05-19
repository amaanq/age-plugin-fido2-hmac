//! `age-plugin-fido2-hmac` CLI.

use core::mem::zeroed;
use std::{
   fs::File,
   io::{
      self,
      BufRead as _,
      BufReader,
      Read,
      Write as _,
      stderr,
   },
   process::ExitCode,
   time::Duration,
};

use age_plugin_fido2_hmac::{
   device::{
      self,
      Algorithm,
      DiscoveryUi,
      find,
   },
   error::Error,
   format::IDENTITY_HRP,
   identity::Identity,
   plugin,
};
use clap::{
   Parser,
   builder::styling::{
      AnsiColor,
      Color,
      Style,
      Styles,
   },
   crate_authors,
};
use rand::Rng as _;
use time::{
   OffsetDateTime,
   format_description::well_known::Rfc3339,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
   name = "age-plugin-fido2-hmac",
   version,
   author = crate_authors!("\n"),
   about = "Encrypt files with age and FIDO2 security keys via the hmac-secret extension",
   styles = cli_styles(),
   help_template = "\n{before-help}{name} {version}\n{author-with-newline}{about-with-newline}\n{usage-heading} {usage}\n\n{all-args}{after-help}\n",
   arg_required_else_help = true,
)]
struct Cli {
   /// Generate new credentials interactively.
   #[arg(short = 'g', long)]
   generate: bool,

   /// List eligible FIDO2 authenticators with the selectors you can hand
   /// back via `FIDO2_SERIAL`, then exit.
   #[arg(short = 'L', long = "list-devices")]
   list_devices: bool,

   /// Convert an identity file to its recipient line(s).
   /// Pass `-` (or omit FILE) to read stdin.
   #[arg(
      short = 'y',
      value_name = "FILE",
      num_args = 0..=1,
      default_missing_value = "-",
   )]
   identity_to_recipient: Option<String>,

   /// COSE algorithm for credential creation.
   #[arg(short = 'a', long, default_value = "es256")]
   algorithm: String,

   /// Internal flag invoked by the age host.
   #[arg(long = "age-plugin", value_name = "STATE")]
   age_plugin: Option<String>,
}

fn main() -> ExitCode {
   let cli = Cli::parse();
   match run(cli) {
      Ok(()) => ExitCode::SUCCESS,
      Err(err) => {
         eprintln!("age-plugin-fido2-hmac: {err}");
         ExitCode::FAILURE
      },
   }
}

fn run(cli: Cli) -> Result<(), Error> {
   if let Some(state) = cli.age_plugin {
      return plugin_protocol(&state);
   }
   if cli.list_devices {
      return list_devices();
   }
   if cli.generate {
      return generate(&cli.algorithm);
   }
   if let Some(path) = cli.identity_to_recipient.as_deref() {
      return identity_to_recipient(path);
   }
   Ok(())
}

fn list_devices() -> Result<(), Error> {
   device::list_devices_to(&mut stderr())
}

struct TerminalUi;

impl DiscoveryUi for TerminalUi {
   fn message(&mut self, msg: &str) {
      let _ = writeln!(stderr(), "[*] {msg}");
   }

   fn pick_device(&mut self, paths: &[String]) -> Result<usize, Error> {
      for (idx, path) in paths.iter().enumerate() {
         let _ = writeln!(stderr(), "  [{idx}] {path}");
      }
      let _ = write!(stderr(), "Choose [0..{}]: ", paths.len() - 1);
      let _ = stderr().flush();
      let mut line = String::new();
      io::stdin().read_line(&mut line)?;
      line
         .trim()
         .parse::<usize>()
         .map_err(|err| Error::InvalidFormat(format!("device choice: {err}")))
   }
}

/// Restore cooked-tty input flags on stdin.
#[cfg(unix)]
fn ensure_stdin_cooked() {
   let fd = libc::STDIN_FILENO;
   // SAFETY: `tcgetattr` initializes this placeholder.
   let mut tio = unsafe { zeroed::<libc::termios>() };

   // SAFETY: `tcgetattr` only writes into `tio`.
   if unsafe { libc::tcgetattr(fd, &raw mut tio) } != 0 {
      return;
   }

   let wanted = libc::ECHO | libc::ICANON;
   if tio.c_lflag & wanted != wanted {
      tio.c_lflag |= wanted;
      // SAFETY: `tio` was initialized by `tcgetattr`.
      let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const tio) };
   }
}

#[cfg(not(unix))]
fn ensure_stdin_cooked() {}

/// Prompt for a visible yes/no answer on stderr.
fn prompt_yn(question: &str) -> Result<bool, Error> {
   loop {
      ensure_stdin_cooked();
      let _ = write!(stderr(), "{question}");
      let _ = stderr().flush();
      let mut line = String::new();
      io::stdin().lock().read_line(&mut line).map_err(Error::Io)?;
      match line.trim().to_ascii_lowercase().as_str() {
         "y" | "yes" => return Ok(true),
         "n" | "no" => return Ok(false),
         "" => {
            let _ = writeln!(stderr(), "Please answer y or n.");
         },
         other => {
            let _ = writeln!(
               stderr(),
               "Unrecognized answer {other:?}; please type y or n."
            );
         },
      }
   }
}

fn generate(alg_str: &str) -> Result<(), Error> {
   let alg = alg_str.parse::<Algorithm>()?;
   let mut ui = TerminalUi;

   let device = find(Duration::from_secs(50), &mut ui)?;

   let has_pin = device.has_pin_set()?;
   let pin = if has_pin {
      Some(Zeroizing::new(
         rpassword::prompt_password("Please enter your PIN: ").map_err(Error::Io)?,
      ))
   } else {
      None
   };

   eprintln!("[*] Please touch your security key to register a new credential...");
   let credential = device.generate_credential(pin.as_deref().map(String::as_str), alg)?;

   let require_pin = if has_pin {
      eprintln!();
      eprintln!("Require a PIN to decrypt?");
      eprintln!("If yes, you'll type your PIN and tap the key each time.");
      eprintln!("If no, just a tap is enough.");
      prompt_yn("[y/n]: ")?
   } else {
      false
   };

   let mut salt = [0_u8; 32];
   rand::rng().fill_bytes(&mut salt);

   let mut id = Identity::record(require_pin, salt, credential.id, credential.public_key)
      .map_err(|err| Error::Fido2(format!("identity: {err}")))?;

   eprintln!("[*] Please touch your security key to derive the public key...");
   let recipient = {
      let mut loaded = id.load_secret(
         device.as_ref(),
         if require_pin {
            pin.as_deref().map(String::as_str)
         } else {
            None
         },
      )?;
      if let Some(warning) = loaded.take_mlock_warning() {
         eprintln!("[*] {warning}");
      }
      loaded.to_recipient()?
   };

   eprintln!();
   eprintln!("Save an identity file?");
   eprintln!();
   eprintln!("An identity file gives you a reusable recipient. Anyone can encrypt to your");
   eprintln!("public key, and you decrypt with `age -d -i id.txt`. Back it up. If you lose");
   eprintln!("the file you lose access, even with the key in hand.");
   eprintln!();
   eprintln!("Without a file you decrypt with `age -d -j fido2-hmac` instead. The credential");
   eprintln!("id and salt ride along inside each encrypted file. No file to manage, but no");
   eprintln!("shareable recipient either.");
   eprintln!();
   let want_identity = prompt_yn("[y/n]: ")?;

   let now = OffsetDateTime::now_utc()
      .format(&Rfc3339)
      .unwrap_or_else(|_| "unknown".into());

   if let Some(serial) = device.serial() {
      println!("#     Serial: {serial}");
   }
   println!("#    Created: {now}");
   println!(
      "# PIN policy: {}",
      if require_pin {
         "required"
      } else {
         "not required"
      }
   );
   println!("# public key: {recipient}");
   if want_identity {
      println!("{}", id.encode()?);
   } else {
      println!("# for decryption, use `age -d -j fido2-hmac` without an identity file.");
   }
   Ok(())
}

struct StderrOnlyUi;

impl DiscoveryUi for StderrOnlyUi {
   fn message(&mut self, msg: &str) {
      eprintln!("[*] {msg}");
   }

   fn pick_device(&mut self, _paths: &[String]) -> Result<usize, Error> {
      Err(Error::InvalidFormat(
         "multiple devices; set FIDO2_SERIAL to disambiguate".into(),
      ))
   }
}

fn identity_to_recipient(path: &str) -> Result<(), Error> {
   let reader: Box<dyn Read> = if path == "-" {
      Box::new(io::stdin())
   } else {
      Box::new(File::open(path)?)
   };
   let buf = BufReader::new(reader);

   let mut identities = Vec::<Identity>::new();
   let identity_prefix = IDENTITY_HRP.to_ascii_uppercase();
   for line in buf.lines() {
      let line = line?;
      let trimmed = line.trim();
      if trimmed.is_empty() || trimmed.starts_with('#') {
         continue;
      }
      if !trimmed.to_ascii_uppercase().starts_with(&identity_prefix) {
         return Err(Error::InvalidFormat(format!(
            "unrecognized identity line: {}",
            trimmed.chars().take(32).collect::<String>()
         )));
      }
      identities.push(trimmed.parse::<Identity>()?);
   }
   if identities.is_empty() {
      return Err(Error::InvalidFormat("no identities found".into()));
   }

   let device = find(Duration::from_secs(50), &mut StderrOnlyUi)?;

   let pin = if identities.iter().any(Identity::require_pin) {
      Some(Zeroizing::new(
         rpassword::prompt_password("Please enter your PIN: ").map_err(Error::Io)?,
      ))
   } else {
      None
   };

   for mut id in identities {
      eprintln!("[*] Please touch your security key to derive the public key...");
      let mut loaded = id.load_secret(device.as_ref(), pin.as_deref().map(String::as_str))?;
      if let Some(warning) = loaded.take_mlock_warning() {
         eprintln!("[*] {warning}");
      }
      let rcpt = loaded.to_recipient()?;
      println!("{rcpt}");
   }
   Ok(())
}

/// Dispatch `--age-plugin=<state>`.
fn plugin_protocol(state: &str) -> Result<(), Error> {
   plugin::run(state).map_err(Error::Io)
}

const fn cli_styles() -> Styles {
   Styles::styled()
      .usage(
         Style::new()
            .bold()
            .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
      )
      .header(
         Style::new()
            .bold()
            .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
      )
      .literal(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))))
      .invalid(
         Style::new()
            .bold()
            .fg_color(Some(Color::Ansi(AnsiColor::Red))),
      )
      .error(
         Style::new()
            .bold()
            .fg_color(Some(Color::Ansi(AnsiColor::Red))),
      )
      .valid(
         Style::new()
            .bold()
            .fg_color(Some(Color::Ansi(AnsiColor::Green))),
      )
      .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::White))))
}
