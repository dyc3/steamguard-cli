extern crate rpassword;
use clap::{crate_version, App, Arg};
use log::*;
use regex::Regex;
use std::collections::HashSet;
use std::{
	io::{stdin, stdout, Write},
	path::Path,
	sync::{Arc, Mutex},
};
use steamguard::{
	steamapi, AccountLinkError, AccountLinker, Confirmation, ConfirmationType, FinalizeLinkError,
	LoginError, SteamGuardAccount, UserLogin,
};
use termion::{
	event::{Event, Key},
	input::TermRead,
	raw::IntoRawMode,
	screen::AlternateScreen,
};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
mod accountmanager;

lazy_static! {
	static ref CAPTCHA_VALID_CHARS: Regex =
		Regex::new("^([A-H]|[J-N]|[P-R]|[T-Z]|[2-4]|[7-9]|[@%&])+$").unwrap();
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
				.takes_value(true)
				.help("Select the account you want by steam username. By default, the first account in the manifest is selected.")
				.conflicts_with("all")
		)
		.arg(
			Arg::with_name("all")
				.long("all")
				.short("a")
				.takes_value(false)
				.help("Select all accounts in the manifest.")
				.conflicts_with("username")
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
		.subcommand(
			App::new("remove")
			.about("Remove the authenticator from an account.")
		)
		.subcommand(
			App::new("debug")
			.arg(
				Arg::with_name("demo-conf-menu")
				.help("Show an example confirmation menu using dummy data.")
				.takes_value(false)
			)
		)
		.get_matches();

	let verbosity = matches.occurrences_of("verbosity") as usize + 2;
	stderrlog::new()
		.verbosity(verbosity)
		.module(module_path!())
		.module("steamguard")
		.init()
		.unwrap();

	if let Some(demo_matches) = matches.subcommand_matches("debug") {
		if demo_matches.is_present("demo-conf-menu") {
			demo_confirmation_menu();
		}
		return;
	}

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

	manifest
		.load_accounts()
		.expect("Failed to load accounts in manifest");

	if matches.is_present("setup") {
		println!("Log in to the account that you want to link to steamguard-cli");
		let session = do_login_raw().expect("Failed to log in. Account has not been linked.");

		let mut linker = AccountLinker::new(session);
		let account: SteamGuardAccount;
		loop {
			match linker.link() {
				Ok(a) => {
					account = a;
					break;
				}
				Err(AccountLinkError::MustRemovePhoneNumber) => {
					println!("There is already a phone number on this account, please remove it and try again.");
					return;
				}
				Err(AccountLinkError::MustProvidePhoneNumber) => {
					println!("Enter your phone number in the following format: +1 123-456-7890");
					print!("Phone number: ");
					linker.phone_number = prompt().replace(&['(', ')', '-'][..], "");
				}
				Err(AccountLinkError::AuthenticatorPresent) => {
					println!("An authenticator is already present on this account.");
					return;
				}
				Err(AccountLinkError::MustConfirmEmail) => {
					println!("Check your email and click the link.");
					pause();
				}
				Err(err) => {
					error!(
						"Failed to link authenticator. Account has not been linked. {}",
						err
					);
					return;
				}
			}
		}
		manifest.add_account(account);
		match manifest.save() {
			Ok(_) => {}
			Err(err) => {
				error!("Aborting the account linking process because we failed to save the manifest. This is really bad. Here is the error: {}", err);
				println!(
					"Just in case, here is the account info. Save it somewhere just in case!\n{:?}",
					manifest.accounts.last().unwrap().lock().unwrap()
				);
				return;
			}
		}

		let mut account = manifest
			.accounts
			.last()
			.as_ref()
			.unwrap()
			.clone()
			.lock()
			.unwrap();

		debug!("attempting link finalization");
		print!("Enter SMS code: ");
		let sms_code = prompt();
		let mut tries = 0;
		loop {
			match linker.finalize(&mut account, sms_code.clone()) {
				Ok(_) => break,
				Err(FinalizeLinkError::WantMore) => {
					debug!("steam wants more 2fa codes (tries: {})", tries);
					tries += 1;
					if tries >= 30 {
						error!("Failed to finalize: unable to generate valid 2fa codes");
						break;
					}
					continue;
				}
				Err(err) => {
					error!("Failed to finalize: {}", err);
					break;
				}
			}
		}

		println!("Authenticator finalized.");
		match manifest.save() {
			Ok(_) => {}
			Err(err) => {
				println!(
					"Failed to save manifest, but we were able to save it before. {}",
					err
				);
				return;
			}
		}

		return;
	}

	let mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>> = vec![];
	if matches.is_present("all") {
		// manifest.accounts.iter().map(|a| selected_accounts.push(a.b));
		for account in &manifest.accounts {
			selected_accounts.push(account.clone());
		}
	} else {
		for account in &manifest.accounts {
			if !matches.is_present("username") {
				selected_accounts.push(account.clone());
				break;
			}
			if matches.value_of("username").unwrap() == account.lock().unwrap().account_name {
				selected_accounts.push(account.clone());
				break;
			}
		}
	}

	debug!(
		"selected accounts: {:?}",
		selected_accounts
			.iter()
			.map(|a| a.lock().unwrap().account_name.clone())
			.collect::<Vec<String>>()
	);

	if let Some(trade_matches) = matches.subcommand_matches("trade") {
		info!("trade");
		for a in selected_accounts.iter_mut() {
			let mut account = a.lock().unwrap();

			info!("Checking for trade confirmations");
			let confirmations: Vec<Confirmation>;
			loop {
				match account.get_trade_confirmations() {
					Ok(confs) => {
						confirmations = confs;
						break;
					}
					Err(_) => {
						info!("failed to get trade confirmations, asking user to log in");
						do_login(&mut account);
					}
				}
			}

			if trade_matches.is_present("accept-all") {
				info!("accepting all confirmations");
				for conf in &confirmations {
					let result = account.accept_confirmation(conf);
					debug!("accept confirmation result: {:?}", result);
				}
			} else {
				if termion::is_tty(&stdout()) {
					let (accept, deny) = prompt_confirmation_menu(confirmations);
					for conf in &accept {
						let result = account.accept_confirmation(conf);
						debug!("accept confirmation result: {:?}", result);
					}
					for conf in &deny {
						let result = account.deny_confirmation(conf);
						debug!("deny confirmation result: {:?}", result);
					}
				} else {
					warn!("not a tty, not showing menu");
					for conf in &confirmations {
						println!("{}", conf.description());
					}
				}
			}
		}

		manifest.save();
	} else if let Some(_) = matches.subcommand_matches("remove") {
		println!(
			"This will remove the mobile authenticator from {} accounts: {}",
			selected_accounts.len(),
			selected_accounts
				.iter()
				.map(|a| a.lock().unwrap().account_name.clone())
				.collect::<Vec<String>>()
				.join(", ")
		);

		print!("Do you want to continue? [yN] ");
		match prompt().as_str() {
			"y" => {}
			_ => {
				println!("Aborting!");
				return;
			}
		}

		let mut successful = vec![];
		for a in selected_accounts {
			let account = a.lock().unwrap();
			match account.remove_authenticator(None) {
				Ok(success) => {
					if success {
						println!("Removed authenticator from {}", account.account_name);
						successful.push(account.account_name.clone());
					} else {
						println!(
							"Failed to remove authenticator from {}",
							account.account_name
						);
					}
				}
				Err(err) => {
					println!(
						"Unexpected error when removing authenticator from {}: {}",
						account.account_name, err
					);
				}
			}
		}

		for account_name in successful {
			manifest.remove_account(account_name);
		}

		manifest.save().expect("Failed to save manifest.");
	} else {
		let server_time = steamapi::get_server_time();
		for account in selected_accounts {
			trace!("{:?}", account);
			let code = account.lock().unwrap().generate_code(server_time);
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
	stdin()
		.read_line(&mut text)
		.expect("Did not enter a correct string");
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

/// Returns a tuple of (accepted, denied). Ignored confirmations are not included.
fn prompt_confirmation_menu(
	confirmations: Vec<Confirmation>,
) -> (Vec<Confirmation>, Vec<Confirmation>) {
	println!("press a key other than enter to show the menu.");
	let mut to_accept_idx: HashSet<usize> = HashSet::new();
	let mut to_deny_idx: HashSet<usize> = HashSet::new();

	let mut screen = AlternateScreen::from(stdout().into_raw_mode().unwrap());
	let stdin = stdin();

	let mut selected_idx = 0;

	for c in stdin.events() {
		match c.expect("could not get events") {
			Event::Key(Key::Char('a')) => {
				to_accept_idx.insert(selected_idx);
				to_deny_idx.remove(&selected_idx);
			}
			Event::Key(Key::Char('d')) => {
				to_accept_idx.remove(&selected_idx);
				to_deny_idx.insert(selected_idx);
			}
			Event::Key(Key::Char('i')) => {
				to_accept_idx.remove(&selected_idx);
				to_deny_idx.remove(&selected_idx);
			}
			Event::Key(Key::Char('A')) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.insert(i);
					to_deny_idx.remove(&i);
				});
			}
			Event::Key(Key::Char('D')) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.remove(&i);
					to_deny_idx.insert(i);
				});
			}
			Event::Key(Key::Char('I')) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.remove(&i);
					to_deny_idx.remove(&i);
				});
			}
			Event::Key(Key::Up) if selected_idx > 0 => {
				selected_idx -= 1;
			}
			Event::Key(Key::Down) if selected_idx < confirmations.len() - 1 => {
				selected_idx += 1;
			}
			Event::Key(Key::Char('\n')) => {
				break;
			}
			Event::Key(Key::Esc) | Event::Key(Key::Ctrl('c')) => {
				return (vec![], vec![]);
			}
			_ => {}
		}

		write!(
			screen,
			"{}{}{}arrow keys to select, [a]ccept, [d]eny, [i]gnore, [enter] confirm choices\n\n",
			termion::clear::All,
			termion::cursor::Goto(1, 1),
			termion::color::Fg(termion::color::White)
		)
		.unwrap();
		for i in 0..confirmations.len() {
			if selected_idx == i {
				write!(
					screen,
					"\r{} >",
					termion::color::Fg(termion::color::LightYellow)
				)
				.unwrap();
			} else {
				write!(screen, "\r{}  ", termion::color::Fg(termion::color::White)).unwrap();
			}

			if to_accept_idx.contains(&i) {
				write!(
					screen,
					"{}[a]",
					termion::color::Fg(termion::color::LightGreen)
				)
				.unwrap();
			} else if to_deny_idx.contains(&i) {
				write!(
					screen,
					"{}[d]",
					termion::color::Fg(termion::color::LightRed)
				)
				.unwrap();
			} else {
				write!(screen, "[ ]").unwrap();
			}

			if selected_idx == i {
				write!(
					screen,
					"{}",
					termion::color::Fg(termion::color::LightYellow)
				)
				.unwrap();
			}

			write!(screen, " {}\n", confirmations[i].description()).unwrap();
		}
	}

	return (
		to_accept_idx.iter().map(|i| confirmations[*i]).collect(),
		to_deny_idx.iter().map(|i| confirmations[*i]).collect(),
	);
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
	let mut login = UserLogin::new(account.account_name.clone(), password);
	let mut loops = 0;
	loop {
		match login.login() {
			Ok(s) => {
				account.session = Option::Some(s);
				break;
			}
			Err(LoginError::Need2FA) => {
				debug!("generating 2fa code and retrying");
				let server_time = steamapi::get_server_time();
				login.twofactor_code = account.generate_code(server_time);
			}
			Err(LoginError::NeedCaptcha { captcha_gid }) => {
				debug!("need captcha to log in");
				login.captcha_text = prompt_captcha_text(&captcha_gid);
			}
			Err(LoginError::NeedEmail) => {
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

fn do_login_raw() -> anyhow::Result<steamapi::Session> {
	print!("Username: ");
	let username = prompt();
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if password.len() > 0 {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	// TODO: reprompt if password is empty
	let mut login = UserLogin::new(username, password);
	let mut loops = 0;
	loop {
		match login.login() {
			Ok(s) => {
				return Ok(s);
			}
			Err(LoginError::Need2FA) => {
				print!("Enter 2fa code: ");
				login.twofactor_code = prompt();
			}
			Err(LoginError::NeedCaptcha { captcha_gid }) => {
				debug!("need captcha to log in");
				login.captcha_text = prompt_captcha_text(&captcha_gid);
			}
			Err(LoginError::NeedEmail) => {
				println!("You should have received an email with a code.");
				print!("Enter code: ");
				login.email_code = prompt();
			}
			Err(r) => {
				error!("Fatal login result: {:?}", r);
				bail!(r);
			}
		}
		loops += 1;
		if loops > 2 {
			error!("Too many loops. Aborting login process, to avoid getting rate limited.");
			bail!("Too many loops. Login process aborted to avoid getting rate limited.");
		}
	}
}

fn pause() {
	println!("Press any key to continue...");
	let mut stdout = stdout().into_raw_mode().unwrap();
	stdout.flush().unwrap();
	stdin().events().next();
}

fn demo_confirmation_menu() {
	info!("showing demo menu");
	let (accept, deny) = prompt_confirmation_menu(vec![
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::Trade,
			creator: 09870987,
		},
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::MarketSell,
			creator: 09870987,
		},
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::AccountRecovery,
			creator: 09870987,
		},
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::Trade,
			creator: 09870987,
		},
	]);
	println!("accept: {}, deny: {}", accept.len(), deny.len());
}
