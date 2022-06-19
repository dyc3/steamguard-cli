use std::str::FromStr;
use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[clap(author, version, about = "Generate Steam 2FA codes and confirm Steam trades from the command line.", long_about = None)]
pub(crate) struct Args {
	#[clap(short, long, help = "Steam username, case-sensitive.", long_help = "Select the account you want by steam username. Case-sensitive. By default, the first account in the manifest is selected.")]
	pub username: Option<String>,
	#[clap(short, long, help = "Select all accounts in the manifest.")]
	pub all: bool,
	/// The path to the maFiles directory.
	#[clap(short, long, default_value = "~/.config/steamguard-cli/maFiles", help = "Specify which folder your maFiles are in. This should be a path to a folder that contains manifest.json.")]
	pub mafiles_path: String,
	#[clap(short, long, help = "Specify your encryption passkey.")]
	pub passkey: Option<String>,
	#[clap(short, long, default_value_t=Verbosity::Info, help = "Set the log level.")]
	pub verbosity: Verbosity,

	#[clap(subcommand)]
	pub sub: Option<Subcommands>,
}

#[derive(Debug, Clone, Parser)]
pub(crate) enum Subcommands {
	Debug {
		#[clap(long)]
		demo_conf_menu: bool
	},
	// Completions {
		// TODO: Add completions
	// },
	#[clap(about = "Interactive interface for trade confirmations")]
	Trade {
		#[clap(short, long, help = "Accept all open trade confirmations. Does not open interactive interface.")]
		accept_all: bool,
		#[clap(short, long, help = "If submitting a confirmation response fails, exit immediately.")]
		fail_fast: bool,
	},
	#[clap(about = "Set up a new account with steamguard-cli")]
	Setup {
		#[clap(short, long, from_global, help = "Steam username, case-sensitive.")]
		username: Option<String>,
	},
	#[clap(about = "Import an account with steamguard already set up")]
	Import {
		#[clap(long, help = "Paths to one or more maFiles, eg. \"./gaben.maFile\"")]
		files: Vec<String>,
	},
	#[clap(about = "Remove the authenticator from an account.")]
	Remove {
		#[clap(short, long, from_global, help = "Steam username, case-sensitive.")]
		username: String,
	},
	#[clap(about = "Encrypt all maFiles")]
	Encrypt,
	#[clap(about = "Decrypt all maFiles")]
	Decrypt,
}

#[derive(Debug, Clone, Copy)]
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

pub(crate) struct ArgsSetup {
	pub username: Option<String>,
}

impl From<Subcommands> for ArgsSetup {
	fn from(sub: Subcommands) -> Self {
		match sub {
			Subcommands::Setup { username } => Self { username },
			_ => panic!("ArgsSetup::from() called with non-Setup subcommand"),
		}
	}
}

pub(crate) struct ArgsImport {
	pub files: Vec<String>,
}

impl From<Subcommands> for ArgsImport {
	fn from(sub: Subcommands) -> Self {
		match sub {
			Subcommands::Import { files } => Self { files },
			_ => panic!("ArgsImport::from() called with non-Import subcommand"),
		}
	}
}

pub(crate) struct ArgsTrade {
	pub accept_all: bool,
	pub fail_fast: bool,
}

impl From<Subcommands> for ArgsTrade {
	fn from(sub: Subcommands) -> Self {
		match sub {
			Subcommands::Trade { accept_all, fail_fast } => Self { accept_all, fail_fast },
			_ => panic!("ArgsTrade::from() called with non-Trade subcommand"),
		}
	}
}