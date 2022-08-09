use anyhow;
use clap::{clap_derive::ArgEnum, Parser};
use std::str::FromStr;

#[derive(Debug, Clone, Parser)]
#[clap(name="metalmann-cli", bin_name="metalmann", author, version, about = "TODO", long_about = None)]
pub(crate) struct Args {
	#[clap(short, long, arg_enum, default_value_t=Verbosity::Info, help = "Set the log level. Be warned, trace is capable of printing sensitive data.")]
	pub verbosity: Verbosity,

	#[clap(short, long, env = "STEAM_WEB_API_KEY")]
	pub web_api_key: String,
}

// FIXME: copied from steamguard-cli::cli::Verbosity, move to common lib instead
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
			_ => Err(anyhow::anyhow!("Invalid verbosity level: {}", s)),
		}
	}
}
