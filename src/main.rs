extern crate rpassword;
use borrow::BorrowMut;
use io::Write;
use steamapi::Session;
use steamguard_cli::*;
use ::std::*;
use text_io::read;
use std::{io::stdin, path::Path};
use clap::{App, Arg, crate_version};
use log::*;
use regex::Regex;

#[macro_use]
extern crate lazy_static;
mod accountmanager;
mod accountlinker;

lazy_static! {
	static ref CAPTCHA_VALID_CHARS: Regex = Regex::new("^([A-H]|[J-N]|[P-R]|[T-Z]|[2-4]|[7-9]|[@%&])+$").unwrap();
}

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
		.subcommand(
			App::new("setup")
			.about("Set up a new account with steamguard-cli")
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

	if matches.is_present("setup") {
		info!("setup");
		let mut linker = accountlinker::AccountLinker::new();
		do_login(&mut linker.account);
		// linker.link(linker.account.session.expect("no login session"));
		return;
	}

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

	if matches.is_present("trade") {
		info!("trade");
		for a in selected_accounts.iter_mut() {
			let mut account = a; // why is this necessary?

			info!("Checking for trade confirmations");
			loop {
				match account.get_trade_confirmations() {
					Ok(confs) => {
						for conf in confs {
							println!("{:?}", conf);
						}
						break;
					}
					Err(_) => {
						info!("failed to get trade confirmations, asking user to log in");
						do_login(&mut account);
					}
				}
			}
		}
	} else {
		let server_time = steamapi::get_server_time();
		for account in selected_accounts {
			trace!("{:?}", account);
			let code = account.generate_code(server_time);
			println!("{}", code);
		}
	}
}

fn validate_captcha_text(text: &String) -> bool {
	return CAPTCHA_VALID_CHARS.is_match(text);
}

#[test]
fn test_validate_captcha_text() {
	assert!(validate_captcha_text(&String::from("2WWUA@")));
	assert!(validate_captcha_text(&String::from("3G8HT2")));
	assert!(validate_captcha_text(&String::from("3J%@X3")));
	assert!(validate_captcha_text(&String::from("2GCZ4A")));
	assert!(validate_captcha_text(&String::from("3G8HT2")));
	assert!(!validate_captcha_text(&String::from("asd823")));
	assert!(!validate_captcha_text(&String::from("!PQ4RD")));
	assert!(!validate_captcha_text(&String::from("1GQ4XZ")));
	assert!(!validate_captcha_text(&String::from("8GO4XZ")));
	assert!(!validate_captcha_text(&String::from("IPQ4RD")));
	assert!(!validate_captcha_text(&String::from("0PT4RD")));
	assert!(!validate_captcha_text(&String::from("APTSRD")));
	assert!(!validate_captcha_text(&String::from("AP5TRD")));
	assert!(!validate_captcha_text(&String::from("AP6TRD")));
}

/// Prompt the user for text input.
fn prompt() -> String {
	let mut text = String::new();
	let _ = std::io::stdout().flush();
	stdin().read_line(&mut text).expect("Did not enter a correct string");
	return String::from(text.strip_suffix('\n').unwrap());
}

fn prompt_captcha_text(captcha_gid: &String) -> String {
	println!("Captcha required. Open this link in your web browser: https://steamcommunity.com/public/captcha.php?gid={}", captcha_gid);
	let mut captcha_text;
	loop {
		print!("Enter captcha text: ");
		captcha_text = prompt();
		if captcha_text.len() > 0 && validate_captcha_text(&captcha_text) {
			break;
		}
		warn!("Invalid chars for captcha text found in user's input. Prompting again...");
	}
	return captcha_text;
}

fn do_login(account: &mut SteamGuardAccount) {
	if account.account_name.len() > 0 {
		println!("Username: {}", account.account_name);
	} else {
		print!("Username: ");
		account.account_name = prompt();
	}
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if password.len() > 0 {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	// TODO: reprompt if password is empty
	let mut login = steamapi::UserLogin::new(account.account_name.clone(), password);
	let mut loops = 0;
	loop {
		match login.login() {
			steamapi::LoginResult::Ok(s) => {
				account.session = Option::Some(s);
				break;
			}
			steamapi::LoginResult::Need2FA => {
				let server_time = steamapi::get_server_time();
				login.twofactor_code = account.generate_code(server_time);
			}
			steamapi::LoginResult::NeedCaptcha{ captcha_gid } => {
				login.captcha_text = prompt_captcha_text(&captcha_gid);
			}
			steamapi::LoginResult::NeedEmail => {
				println!("You should have received an email with a code.");
				print!("Enter code");
				login.email_code = prompt();
			}
			r => {
				error!("Fatal login result: {:?}", r);
				return;
			}
		}
		loops += 1;
		if loops > 2 {
			error!("Too many loops. Aborting login process, to avoid getting rate limited.");
			return;
		}
	}
}
