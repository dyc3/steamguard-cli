extern crate rpassword;
use clap::{IntoApp, Parser};
use log::*;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
	io::{stdout, Write},
	path::Path,
	sync::{Arc, Mutex},
};
use steamguard::{
	steamapi, AccountLinkError, AccountLinker, Confirmation, ExposeSecret, FinalizeLinkError,
	LoginError, SteamGuardAccount, UserLogin,
};

use crate::accountmanager::ManifestAccountLoadError;

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
mod cli;
mod demos;
mod encryption;
mod errors;
pub(crate) mod tui;

fn main() {
	std::process::exit(match run() {
		Ok(_) => 0,
		Err(e) => {
			error!("{:?}", e);
			255
		}
	});
}

fn run() -> anyhow::Result<()> {
	let args = cli::Args::parse();
	info!("{:?}", args);

	stderrlog::new()
		.verbosity(args.verbosity as usize)
		.module(module_path!())
		.module("steamguard")
		.init()
		.unwrap();

	match args.sub {
		Some(cli::Subcommands::Debug(args)) => {
			return do_subcmd_debug(args);
		}
		Some(cli::Subcommands::Completion(args)) => {
			return do_subcmd_completion(args);
		}
		_ => {}
	};

	let mafiles_dir = if let Some(mafiles_path) = &args.mafiles_path {
		mafiles_path.clone()
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
				return Err(errors::UserError::Aborted.into());
			}
			_ => {}
		}
		std::fs::create_dir_all(mafiles_dir)?;

		manifest = accountmanager::Manifest::new(path.as_path());
		manifest.save()?;
	} else {
		manifest = accountmanager::Manifest::load(path.as_path())?;
	}

	let mut passkey: Option<String> = args.passkey.clone();
	manifest.submit_passkey(passkey);

	loop {
		match manifest.auto_upgrade() {
			Ok(upgraded) => {
				if upgraded {
					info!("Manifest auto-upgraded");
					manifest.save()?;
				} else {
					debug!("Manifest is up to date");
				}
				break;
			}
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
				return Err(e.into());
			}
		}
	}

	match args.sub {
		Some(cli::Subcommands::Setup(args)) => {
			return do_subcmd_setup(args, &mut manifest);
		}
		Some(cli::Subcommands::Import(args)) => {
			return do_subcmd_import(args, &mut manifest);
		}
		Some(cli::Subcommands::Encrypt(args)) => {
			return do_subcmd_encrypt(args, &mut manifest);
		}
		Some(cli::Subcommands::Decrypt(args)) => {
			return do_subcmd_decrypt(args, &mut manifest);
		}
		_ => {}
	}

	let selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>;
	loop {
		match get_selected_accounts(&args, &mut manifest) {
			Ok(accounts) => {
				selected_accounts = accounts;
				break;
			}
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
				return Err(e.into());
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

	match args.sub.unwrap_or(cli::Subcommands::Code(args.code)) {
		cli::Subcommands::Trade(args) => {
			return do_subcmd_trade(args, &mut manifest, selected_accounts);
		}
		cli::Subcommands::Remove(args) => {
			return do_subcmd_remove(args, &mut manifest, selected_accounts);
		}
		cli::Subcommands::Code(args) => {
			return do_subcmd_code(args, selected_accounts);
		}
		s => {
			error!("Unknown subcommand: {:?}", s);
			return Err(errors::UserError::UnknownSubcommand.into());
		}
	}
}

fn get_selected_accounts(
	args: &cli::Args,
	manifest: &mut accountmanager::Manifest,
) -> anyhow::Result<Vec<Arc<Mutex<SteamGuardAccount>>>, ManifestAccountLoadError> {
	let mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>> = vec![];

	if args.all {
		manifest.load_accounts()?;
		for entry in &manifest.entries {
			selected_accounts.push(manifest.get_account(&entry.account_name).unwrap().clone());
		}
	} else {
		let entry = if let Some(username) = &args.username {
			manifest.get_entry(&username)
		} else {
			manifest
				.entries
				.first()
				.ok_or(ManifestAccountLoadError::MissingManifestEntry)
		}?;

		let account_name = entry.account_name.clone();
		let account = manifest.get_or_load_account(&account_name)?;
		selected_accounts.push(account);
	}
	return Ok(selected_accounts);
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
	account.set_session(do_login_impl(
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
					let server_time = steamapi::get_server_time()?.server_time;
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

fn load_accounts_with_prompts(manifest: &mut accountmanager::Manifest) -> anyhow::Result<()> {
	loop {
		match manifest.load_accounts() {
			Ok(_) => return Ok(()),
			Err(
				accountmanager::ManifestAccountLoadError::MissingPasskey
				| accountmanager::ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manifest.has_passkey() {
					error!("Incorrect passkey");
				}
				let passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				manifest.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return Err(e.into());
			}
		}
	}
}

fn do_subcmd_debug(args: cli::ArgsDebug) -> anyhow::Result<()> {
	if args.demo_conf_menu {
		demos::demo_confirmation_menu();
	}
	return Ok(());
}

fn do_subcmd_completion(args: cli::ArgsCompletions) -> Result<(), anyhow::Error> {
	let mut app = cli::Args::command_for_update();
	clap_complete::generate(args.shell, &mut app, "steamguard", &mut std::io::stdout());
	return Ok(());
}

fn do_subcmd_setup(
	args: cli::ArgsSetup,
	manifest: &mut accountmanager::Manifest,
) -> anyhow::Result<()> {
	println!("Log in to the account that you want to link to steamguard-cli");
	print!("Username: ");
	let username = if args.username.is_some() {
		let u = args.username.unwrap();
		println!("{}", u);
		u
	} else {
		tui::prompt()
	};
	let account_name = username.clone();
	if manifest.account_exists(&username) {
		bail!(
			"Account {} already exists in manifest, remove it first",
			username
		);
	}
	let session = do_login_raw(username).expect("Failed to log in. Account has not been linked.");

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
				bail!("There is already a phone number on this account, please remove it and try again.");
			}
			Err(AccountLinkError::MustProvidePhoneNumber) => {
				println!("Enter your phone number in the following format: +1 123-456-7890");
				print!("Phone number: ");
				linker.phone_number = tui::prompt().replace(&['(', ')', '-'][..], "");
			}
			Err(AccountLinkError::AuthenticatorPresent) => {
				println!("An authenticator is already present on this account.");
				bail!("An authenticator is already present on this account.");
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
				return Err(err.into());
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
			return Err(err.into());
		}
	}

	let account_arc = manifest.get_account(&account_name).unwrap();
	let mut account = account_arc.lock().unwrap();

	println!("Authenticator has not yet been linked. Before continuing with finalization, please take the time to write down your revocation code: {}", account.revocation_code.expose_secret());
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
					bail!("Failed to finalize: unable to generate valid 2fa codes");
				}
			}
			Err(err) => {
				error!("Failed to finalize: {}", err);
				return Err(err.into());
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
			return Err(err);
		}
	}

	println!(
		"Authenticator has been finalized. Please actually write down your revocation code: {}",
		account.revocation_code.expose_secret()
	);

	return Ok(());
}

fn do_subcmd_import(
	args: cli::ArgsImport,
	manifest: &mut accountmanager::Manifest,
) -> anyhow::Result<()> {
	for file_path in args.files {
		match manifest.import_account(&file_path) {
			Ok(_) => {
				info!("Imported account: {}", &file_path);
			}
			Err(err) => {
				bail!("Failed to import account: {} {}", &file_path, err);
			}
		}
	}

	manifest.save()?;
	return Ok(());
}

fn do_subcmd_trade(
	args: cli::ArgsTrade,
	manifest: &mut accountmanager::Manifest,
	mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> anyhow::Result<()> {
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
					do_login(&mut account)?;
				}
			}
		}

		let mut any_failed = false;
		if args.accept_all {
			info!("accepting all confirmations");
			for conf in &confirmations {
				let result = account.accept_confirmation(conf);
				if result.is_err() {
					warn!("accept confirmation result: {:?}", result);
					any_failed = true;
					if args.fail_fast {
						return result;
					}
				} else {
					debug!("accept confirmation result: {:?}", result);
				}
			}
		} else {
			if termion::is_tty(&stdout()) {
				let (accept, deny) = tui::prompt_confirmation_menu(confirmations);
				for conf in &accept {
					let result = account.accept_confirmation(conf);
					if result.is_err() {
						warn!("accept confirmation result: {:?}", result);
						any_failed = true;
						if args.fail_fast {
							return result;
						}
					} else {
						debug!("accept confirmation result: {:?}", result);
					}
				}
				for conf in &deny {
					let result = account.deny_confirmation(conf);
					debug!("deny confirmation result: {:?}", result);
					if result.is_err() {
						warn!("deny confirmation result: {:?}", result);
						any_failed = true;
						if args.fail_fast {
							return result;
						}
					} else {
						debug!("deny confirmation result: {:?}", result);
					}
				}
			} else {
				warn!("not a tty, not showing menu");
				for conf in &confirmations {
					println!("{}", conf.description());
				}
			}
		}

		if any_failed {
			error!("Failed to respond to some confirmations.");
		}
	}

	manifest.save()?;
	return Ok(());
}

fn do_subcmd_remove(
	_args: cli::ArgsRemove,
	manifest: &mut accountmanager::Manifest,
	selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> anyhow::Result<()> {
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
			return Err(errors::UserError::Aborted.into());
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

	manifest.save()?;
	return Ok(());
}

fn do_subcmd_encrypt(
	_args: cli::ArgsEncrypt,
	manifest: &mut accountmanager::Manifest,
) -> anyhow::Result<()> {
	if !manifest.has_passkey() {
		let mut passkey;
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
	manifest.load_accounts()?;
	for entry in &mut manifest.entries {
		entry.encryption = Some(accountmanager::EntryEncryptionParams::generate());
	}
	manifest.save()?;
	return Ok(());
}

fn do_subcmd_decrypt(
	_args: cli::ArgsDecrypt,
	manifest: &mut accountmanager::Manifest,
) -> anyhow::Result<()> {
	load_accounts_with_prompts(manifest)?;
	for entry in &mut manifest.entries {
		entry.encryption = None;
	}
	manifest.submit_passkey(None);
	manifest.save()?;
	return Ok(());
}

fn do_subcmd_code(
	args: cli::ArgsCode,
	selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> anyhow::Result<()> {
	let server_time = if args.offline {
		SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
	} else {
		steamapi::get_server_time()?.server_time
	};
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
	return Ok(());
}
