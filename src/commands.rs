use std::sync::{Arc, Mutex};

use clap::{clap_derive::ArgEnum, Parser};
use clap_complete::Shell;
use std::str::FromStr;
use steamguard::SteamGuardAccount;

use crate::AccountManager;

pub mod code;
pub mod completions;
pub mod debug;
pub mod decrypt;
pub mod encrypt;
pub mod import;
#[cfg(feature = "qr")]
pub mod qr;
pub mod remove;
pub mod setup;
pub mod trade;

pub use code::CodeCommand;
pub use completions::CompletionsCommand;
pub use debug::DebugCommand;
pub use decrypt::DecryptCommand;
pub use encrypt::EncryptCommand;
pub use import::ImportCommand;
#[cfg(feature = "qr")]
pub use qr::QrCommand;
pub use remove::RemoveCommand;
pub use setup::SetupCommand;
pub use trade::TradeCommand;

/// A command that does not operate on the manifest or individual accounts.
pub(crate) trait ConstCommand {
	fn execute(&self) -> anyhow::Result<()>;
}

/// A command that operates the manifest as a whole
pub(crate) trait ManifestCommand {
	fn execute(&self, manager: &mut AccountManager) -> anyhow::Result<()>;
}

/// A command that operates on individual accounts.
pub(crate) trait AccountCommand {
	fn execute(
		&self,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	) -> anyhow::Result<()>;
}

pub(crate) enum CommandType {
	Const(Box<dyn ConstCommand>),
	Manifest(Box<dyn ManifestCommand>),
	Account(Box<dyn AccountCommand>),
}

#[derive(Debug, Clone, Parser)]
#[clap(name="steamguard-cli", bin_name="steamguard", author, version, about = "Generate Steam 2FA codes and confirm Steam trades from the command line.", long_about = None)]
pub(crate) struct Args {
	#[clap(flatten)]
	pub global: GlobalArgs,

	#[clap(subcommand)]
	pub sub: Option<Subcommands>,

	#[clap(flatten)]
	pub code: CodeCommand,
}

#[derive(Debug, Clone, Parser)]
pub(crate) struct GlobalArgs {
	#[clap(
		short,
		long,
		conflicts_with = "all",
		help = "Steam username, case-sensitive.",
		long_help = "Select the account you want by steam username. Case-sensitive. By default, the first account in the manifest is selected."
	)]
	pub username: Option<String>,
	#[clap(
		short,
		long,
		conflicts_with = "username",
		help = "Select all accounts in the manifest."
	)]
	pub all: bool,
	/// The path to the maFiles directory.
	#[clap(
		short,
		long,
		help = "Specify which folder your maFiles are in. This should be a path to a folder that contains manifest.json. Default: ~/.config/steamguard-cli/maFiles"
	)]
	pub mafiles_path: Option<String>,
	#[clap(
		short,
		long,
		env = "STEAMGUARD_CLI_PASSKEY",
		help = "Specify your encryption passkey."
	)]
	pub passkey: Option<String>,
	#[clap(short, long, arg_enum, default_value_t=Verbosity::Info, help = "Set the log level. Be warned, trace is capable of printing sensitive data.")]
	pub verbosity: Verbosity,
}

#[derive(Debug, Clone, Parser)]
pub(crate) enum Subcommands {
	Debug(DebugCommand),
	Completion(CompletionsCommand),
	Setup(SetupCommand),
	Import(ImportCommand),
	Trade(TradeCommand),
	Remove(RemoveCommand),
	Encrypt(EncryptCommand),
	Decrypt(DecryptCommand),
	Code(CodeCommand),
	#[cfg(feature = "qr")]
	Qr(QrCommand),
}

#[derive(Debug, Clone, Copy, ArgEnum)]
pub(crate) enum Verbosity {
	Error = 0,
	Warn = 1,
	Info = 2,
	Debug = 3,
	Trace = 4,
}

impl std::fmt::Display for Verbosity {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!(
			"{}",
			match self {
				Verbosity::Error => "error",
				Verbosity::Warn => "warn",
				Verbosity::Info => "info",
				Verbosity::Debug => "debug",
				Verbosity::Trace => "trace",
			}
		))
	}
}

impl FromStr for Verbosity {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"error" => Ok(Verbosity::Error),
			"warn" => Ok(Verbosity::Warn),
			"info" => Ok(Verbosity::Info),
			"debug" => Ok(Verbosity::Debug),
			"trace" => Ok(Verbosity::Trace),
			_ => Err(anyhow!("Invalid verbosity level: {}", s)),
		}
	}
}

// HACK: the derive API doesn't support default subcommands, so we are going to make it so that it'll be easier to switch over when it's implemented.
// See: https://github.com/clap-rs/clap/issues/3857
impl From<Args> for CodeCommand {
	fn from(args: Args) -> Self {
		args.code
	}
}
