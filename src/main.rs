extern crate rpassword;
use clap::{crate_version, App, Arg, Shell};
use log::*;
use std::str::FromStr;
use std::{
	io::{stdout, Write},
	path::Path,
	sync::{Arc, Mutex},
};
use steamguard::{
	steamapi, AccountLinkError, AccountLinker, Confirmation, FinalizeLinkError, LoginError,
	SteamGuardAccount, UserLogin,
};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate base64;
extern crate dirs;
#[cfg(test)]
extern crate proptest;
extern crate ring;
mod accountmanager;
mod demos;
mod encryption;
mod tui;

fn cli() -> App<'static, 'static> {
	App::new("steamguard-cli")
		.version(crate_version!())
		.bin_name("steamguard")
		.author("dyc3 (Carson McManus)")
		.about("Generate Steam 2FA codes and confirm Steam trades from the command line.")
		.arg(
			Arg::with_name("username")
				.long("username")
				.short("u")
				.takes_value(true)
				.help("Select the account you want by steam username. Case-sensitive. By default, the first account in the manifest is selected.")
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
				.help("Specify which folder your maFiles are in. This should be a path to a folder that contains manifest.json.")
		)
		.arg(
			Arg::with_name("passkey")
				.long("passkey")
				.short("p")
				.help("Specify your encryption passkey.")
				.takes_value(true)
		)
		.arg(
			Arg::with_name("verbosity")
				.short("v")
				.help("Log what is going on verbosely.")
				.takes_value(false)
				.multiple(true)
		)
		.subcommand(
			App::new("completion")
				.about("Generate shell completions")
				.arg(
					Arg::with_name("shell")
						.long("shell")
						.takes_value(true)
						.possible_values(&Shell::variants())
				)
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
			App::new("import")
				.about("Import an account with steamguard already set up")
				.arg(
					Arg::with_name("files")
						.required(true)
						.multiple(true)
				)
		)
		.subcommand(
			App::new("remove")
			.about("Remove the authenticator from an account.")
		)
		.subcommand(
			App::new("encrypt")
				.about("Encrypt maFiles.")
		)
		.subcommand(
			App::new("decrypt")
				.about("Decrypt maFiles.")
		)
		.subcommand(
			App::new("debug")
			.arg(
				Arg::with_name("demo-conf-menu")
				.help("Show an example confirmation menu using dummy data.")
				.takes_value(false)
			)
		)
}

fn main() {
	let matches = cli().get_matches();

	let verbosity = matches.occurrences_of("verbosity") as usize + 2;
	stderrlog::new()
		.verbosity(verbosity)
		.module(module_path!())
		.module("steamguard")
		.init()
		.unwrap();

	if let Some(demo_matches) = matches.subcommand_matches("debug") {
		if demo_matches.is_present("demo-conf-menu") {
			demos::demo_confirmation_menu();
		}
		return;
	}
	if let Some(completion_matches) = matches.subcommand_matches("completion") {
		cli().gen_completions_to(
			"steamguard",
			Shell::from_str(completion_matches.value_of("shell").unwrap()).unwrap(),
			&mut std::io::stdout(),
		);
		return;
	}

	let mafiles_dir = if matches.occurrences_of("mafiles-path") > 0 {
		matches.value_of("mafiles-path").unwrap().into()
	} else {
		get_mafiles_dir()
	};
	info!("reading manifest from {}", mafiles_dir);
	let path = Path::new(&mafiles_dir).join("manifest.json");
	let mut manifest: accountmanager::Manifest;
	if !path.exists() {
		error!("Did not find manifest in {}", mafiles_dir);
		match tui::prompt_char(
			format!("Would you like to create a manifest in {} ?", mafiles_dir).as_str(),
			"Yn",
		) {
			'n' => {
				info!("Aborting!");
				return;
			}
			_ => {}
		}
		std::fs::create_dir_all(mafiles_dir).expect("failed to create directory");

		manifest = accountmanager::Manifest::new(path.as_path());
		manifest.save().expect("Failed to save manifest");
	} else {
		match accountmanager::Manifest::load(path.as_path()) {
			Ok(m) => {
				manifest = m;
			}
			Err(e) => {
				error!("Could not load manifest: {}", e);
				return;
			}
		}
	}

	let mut passkey: Option<String> = matches.value_of("passkey").map(|s| s.into());
	manifest.submit_passkey(passkey);

	loop {
		match manifest.load_accounts() {
			Ok(_) => break,
			Err(
				accountmanager::ManifestAccountLoadError::MissingPasskey
				| accountmanager::ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manifest.has_passkey() {
					error!("Incorrect passkey");
				}
				passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				manifest.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return;
			}
		}
	}

	if matches.is_present("setup") {
		println!("Log in to the account that you want to link to steamguard-cli");
		print!("Username: ");
		let username = tui::prompt();
		let account_name = username.clone();
		if manifest.account_exists(&username) {
			error!(
				"Account {} already exists in manifest, remove it first",
				username
			);
		}
		let session =
			do_login_raw(username).expect("Failed to log in. Account has not been linked.");

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
					linker.phone_number = tui::prompt().replace(&['(', ')', '-'][..], "");
				}
				Err(AccountLinkError::AuthenticatorPresent) => {
					println!("An authenticator is already present on this account.");
					return;
				}
				Err(AccountLinkError::MustConfirmEmail) => {
					println!("Check your email and click the link.");
					tui::pause();
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
					manifest.get_account(&account_name).unwrap().lock().unwrap()
				);
				return;
			}
		}

		let account_arc = manifest
			.get_account(&account_name)
			.unwrap();
		let mut account = account_arc
			.lock()
			.unwrap();

		println!("Authenticator has not yet been linked. Before continuing with finalization, please take the time to write down your revocation code: {}", account.revocation_code);
		tui::pause();

		debug!("attempting link finalization");
		print!("Enter SMS code: ");
		let sms_code = tui::prompt();
		let mut tries = 0;
		loop {
			match linker.finalize(&mut account, sms_code.clone()) {
				Ok(_) => break,
				Err(FinalizeLinkError::WantMore) => {
					debug!("steam wants more 2fa codes (tries: {})", tries);
					tries += 1;
					if tries >= 30 {
						error!("Failed to finalize: unable to generate valid 2fa codes");
						return;
					}
				}
				Err(err) => {
					error!("Failed to finalize: {}", err);
					return;
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

		println!(
			"Authenticator has been finalized. Please actually write down your revocation code: {}",
			account.revocation_code
		);

		return;
	} else if let Some(import_matches) = matches.subcommand_matches("import") {
		for file_path in import_matches.values_of("files").unwrap() {
			match manifest.import_account(file_path.into()) {
				Ok(_) => {
					info!("Imported account: {}", file_path);
				}
				Err(err) => {
					error!("Failed to import account: {} {}", file_path, err);
				}
			}
		}

		manifest.save().expect("Failed to save manifest.");
		return;
	} else if matches.is_present("encrypt") {
		if !manifest.has_passkey() {
			loop {
				passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				let passkey_confirm =
					rpassword::prompt_password_stdout("Confirm encryption passkey: ").ok();
				if passkey == passkey_confirm {
					break;
				}
				error!("Passkeys do not match, try again.");
			}
			manifest.submit_passkey(passkey);
		}
		for entry in &mut manifest.entries {
			entry.encryption = Some(accountmanager::EntryEncryptionParams::generate());
		}
		manifest.save().expect("Failed to save manifest.");
		return;
	} else if matches.is_present("decrypt") {
		for entry in &mut manifest.entries {
			entry.encryption = None;
		}
		manifest.submit_passkey(None);
		manifest.save().expect("Failed to save manifest.");
		return;
	}

	let mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>> = vec![];
	if matches.is_present("all") {
		manifest.load_accounts().expect("Failed to load all requested accounts, aborting");
		// manifest.accounts.iter().map(|a| selected_accounts.push(a.b));
		for entry in &manifest.entries {
			selected_accounts.push(manifest.get_account(&entry.account_name).unwrap().clone());
		}
	} else {
		for entry in &manifest.entries {
			if !matches.is_present("username") {
				selected_accounts.push(manifest.get_account(&entry.account_name).unwrap().clone());
				break;
			}
			if matches.value_of("username").unwrap() == entry.account_name {
				selected_accounts.push(manifest.get_account(&entry.account_name).unwrap().clone());
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
						do_login(&mut account).expect("Failed to log in");
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
					let (accept, deny) = tui::prompt_confirmation_menu(confirmations);
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

		manifest.save().expect("Failed to save manifest");
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

		match tui::prompt_char("Do you want to continue?", "yN") {
			'y' => {}
			_ => {
				info!("Aborting!");
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
						match tui::prompt_char(
							"Would you like to remove it from the manifest anyway?",
							"yN",
						) {
							'y' => {
								successful.push(account.account_name.clone());
							}
							_ => {}
						}
					}
				}
				Err(err) => {
					error!(
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
		debug!("Time used to generate codes: {}", server_time);
		for account in selected_accounts {
			info!(
				"Generating code for {}",
				account.lock().unwrap().account_name
			);
			trace!("{:?}", account);
			let code = account.lock().unwrap().generate_code(server_time);
			println!("{}", code);
		}
	}
}

fn do_login(account: &mut SteamGuardAccount) -> anyhow::Result<()> {
	if account.account_name.len() > 0 {
		println!("Username: {}", account.account_name);
	} else {
		print!("Username: ");
		account.account_name = tui::prompt();
	}
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if password.len() > 0 {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	account.session = Some(do_login_impl(
		account.account_name.clone(),
		password,
		Some(account),
	)?);
	return Ok(());
}

fn do_login_raw(username: String) -> anyhow::Result<steamapi::Session> {
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if password.len() > 0 {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	return do_login_impl(username, password, None);
}

fn do_login_impl(
	username: String,
	password: String,
	account: Option<&SteamGuardAccount>,
) -> anyhow::Result<steamapi::Session> {
	// TODO: reprompt if password is empty
	let mut login = UserLogin::new(username, password);
	let mut loops = 0;
	loop {
		match login.login() {
			Ok(s) => {
				return Ok(s);
			}
			Err(LoginError::Need2FA) => match account {
				Some(a) => {
					let server_time = steamapi::get_server_time();
					login.twofactor_code = a.generate_code(server_time);
				}
				None => {
					print!("Enter 2fa code: ");
					login.twofactor_code = tui::prompt();
				}
			},
			Err(LoginError::NeedCaptcha { captcha_gid }) => {
				debug!("need captcha to log in");
				login.captcha_text = tui::prompt_captcha_text(&captcha_gid);
			}
			Err(LoginError::NeedEmail) => {
				println!("You should have received an email with a code.");
				print!("Enter code: ");
				login.email_code = tui::prompt();
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

fn get_mafiles_dir() -> String {
	let paths = vec![
		Path::new(&dirs::config_dir().unwrap()).join("steamguard-cli/maFiles"),
		Path::new(&dirs::home_dir().unwrap()).join("maFiles"),
	];

	for path in &paths {
		if path.join("manifest.json").is_file() {
			return path.to_str().unwrap().into();
		}
	}

	return paths[0].to_str().unwrap().into();
}
