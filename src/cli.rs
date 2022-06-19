use std::str::FromStr;
use clap::{Parser, clap_derive::ArgEnum};
use clap_complete::Shell;

#[derive(Debug, Clone, Parser)]
#[clap(name="steamguard-cli", bin_name="steamguard", author, version, about = "Generate Steam 2FA codes and confirm Steam trades from the command line.", long_about = None)]
pub(crate) struct Args {
	#[clap(short, long, help = "Steam username, case-sensitive.", long_help = "Select the account you want by steam username. Case-sensitive. By default, the first account in the manifest is selected.")]
	pub username: Option<String>,
	#[clap(short, long, help = "Select all accounts in the manifest.")]
	pub all: bool,
	/// The path to the maFiles directory.
	#[clap(short, long, help = "Specify which folder your maFiles are in. This should be a path to a folder that contains manifest.json. Default: ~/.config/steamguard-cli/maFiles")]
	pub mafiles_path: Option<String>,
	#[clap(short, long, help = "Specify your encryption passkey.")]
	pub passkey: Option<String>,
	#[clap(short, long, arg_enum, default_value_t=Verbosity::Info, help = "Set the log level. Be warned, trace is capable of printing sensitive data.")]
	pub verbosity: Verbosity,

	#[clap(subcommand)]
	pub sub: Option<Subcommands>,
}

#[derive(Debug, Clone, Parser)]
pub(crate) enum Subcommands {
	Debug(ArgsDebug),
	Completion(ArgsCompletions),
	Setup(ArgsSetup),
	Import(ArgsImport),
	Trade(ArgsTrade),
	Remove(ArgsRemove),
	Encrypt(ArgsEncrypt),
	Decrypt(ArgsDecrypt),
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
		f.write_fmt(format_args!("{}", match self {
			Verbosity::Error => "error",
			Verbosity::Warn => "warn",
			Verbosity::Info => "info",
			Verbosity::Debug => "debug",
			Verbosity::Trace => "trace",
		}))
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


#[derive(Debug, Clone, Parser)]
#[clap(about="Debug stuff, not useful for most users.")]
pub(crate) struct ArgsDebug {
	#[clap(long, help = "Show an example confirmation menu using dummy data.")]
	pub demo_conf_menu: bool
}

#[derive(Debug, Clone, Parser)]
#[clap(about="Generate shell completions")]
pub(crate) struct ArgsCompletions {
	#[clap(short, long, arg_enum, help = "The shell to generate completions for.")]
	pub shell: Shell,
}

#[derive(Debug, Clone, Parser)]
#[clap(about = "Set up a new account with steamguard-cli")]
pub(crate) struct ArgsSetup {
	#[clap(short, long, from_global, help = "Steam username, case-sensitive.")]
	pub username: Option<String>,
}

#[derive(Debug, Clone, Parser)]
#[clap(about = "Import an account with steamguard already set up")]
pub(crate) struct ArgsImport {
	#[clap(long, help = "Paths to one or more maFiles, eg. \"./gaben.maFile\"")]
	pub files: Vec<String>,
}

#[derive(Debug, Clone, Parser)]
#[clap(about = "Interactive interface for trade confirmations")]
pub(crate) struct ArgsTrade {
	#[clap(short, long, help = "Accept all open trade confirmations. Does not open interactive interface.")]
	pub accept_all: bool,
	#[clap(short, long, help = "If submitting a confirmation response fails, exit immediately.")]
	pub fail_fast: bool,
}

#[derive(Debug, Clone, Parser)]
#[clap(about = "Remove the authenticator from an account.")]
pub(crate) struct ArgsRemove;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Encrypt all maFiles")]
pub(crate) struct ArgsEncrypt;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Decrypt all maFiles")]
pub(crate) struct ArgsDecrypt;
