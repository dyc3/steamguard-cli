extern crate rpassword;
use borrow::BorrowMut;
use io::Write;
use steamguard_cli::*;
use ::std::*;
use text_io::read;
use std::path::Path;
use clap::{App, Arg, crate_version};
use log::*;

mod steamapi;
mod accountmanager;

fn main() {
	let matches = App::new("steamguard-cli")
		.version(crate_version!())
		.bin_name("steamguard")
		.author("dyc3 (Carson McManus)")
		.about("Generate Steam 2FA codes and confirm Steam trades from the command line.")
		.arg(
			Arg::with_name("username")
				.long("username")
				.short("u")
				.help("Select the account you want by steam username. By default, the first account in the manifest is selected.")
		)
		.arg(
			Arg::with_name("all")
				.long("all")
				.short("a")
				.takes_value(false)
				.help("Select all accounts in the manifest.")
		)
		.arg(
			Arg::with_name("mafiles-path")
				.long("mafiles-path")
				.short("m")
				.default_value("~/maFiles")
				.help("Specify which folder your maFiles are in.")
		)
		.arg(
			Arg::with_name("passkey")
				.long("passkey")
				.short("p")
				.help("Specify your encryption passkey.")
		)
		.arg(
			Arg::with_name("verbosity")
				.short("v")
				.help("Log what is going on verbosely.")
				.takes_value(false)
				.multiple(true)
		)
		.subcommand(
			App::new("trade")
				.about("Interactive interface for trade confirmations")
				.arg(
					Arg::with_name("accept-all")
					.short("a")
					.long("accept-all")
					.takes_value(false)
					.help("Accept all open trade confirmations. Does not open interactive interface.")
				)
		)
		.get_matches();


	let verbosity = matches.occurrences_of("verbosity") as usize + 2;
	stderrlog::new()
		.verbosity(verbosity)
		.module(module_path!()).init().unwrap();

	let path = Path::new(matches.value_of("mafiles-path").unwrap()).join("manifest.json");
	let mut manifest: accountmanager::Manifest;
	match accountmanager::Manifest::load(path.as_path()) {
		Ok(m) => {
			manifest = m;
		}
		Err(e) => {
			error!("Could not load manifest: {}", e);
			return;
		}
	}

	manifest.load_accounts();
	let mut selected_accounts: Vec<SteamGuardAccount> = vec![];
	if matches.is_present("all") {
		// manifest.accounts.iter().map(|a| selected_accounts.push(a.b));
		for account in manifest.accounts {
			selected_accounts.push(account.clone());
		}
	} else {
		for account in manifest.accounts {
			if !matches.is_present("username") {
				selected_accounts.push(account.clone());
				break;
			}
			if matches.value_of("username").unwrap() == account.account_name {
				selected_accounts.push(account.clone());
				break;
			}
		}
	}

	debug!("selected accounts: {:?}", selected_accounts.iter().map(|a| a.account_name.clone()).collect::<Vec<String>>());

	let server_time = steamapi::get_server_time();
	for account in selected_accounts {
		trace!("{:?}", account);
		let code = account.generate_code(server_time);
		println!("{}", code);
	}
}
