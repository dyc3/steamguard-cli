extern crate rpassword;
use clap::{IntoApp, Parser};
use crossterm::tty::IsTty;
use log::*;
#[cfg(feature = "qr")]
use qrcode::QrCode;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
	io::{stdout, Write},
	path::Path,
	sync::{Arc, Mutex},
};
use steamguard::accountlinker::AccountLinkSuccess;
use steamguard::protobufs::steammessages_auth_steamclient::{
	EAuthSessionGuardType, EAuthTokenPlatformType,
};
use steamguard::token::Tokens;
use steamguard::{
	steamapi, AccountLinkError, AccountLinker, Confirmation, DeviceDetails, ExposeSecret,
	FinalizeLinkError, LoginError, SteamGuardAccount, UserLogin,
};

use crate::accountmanager::migrate::load_and_migrate;
use crate::accountmanager::{AccountManager, ManifestAccountLoadError, ManifestLoadError};

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
mod secret_string;
mod test_login;
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
	let mut manager: accountmanager::AccountManager;
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

		manager = accountmanager::AccountManager::new(path.as_path());
		manager.save()?;
	} else {
		manager = match accountmanager::AccountManager::load(path.as_path()) {
			Ok(m) => m,
			Err(ManifestLoadError::MigrationNeeded) => {
				info!("Migrating manifest");
				let (manifest, accounts) = load_and_migrate(path.as_path(), args.passkey.as_ref())?;
				let mut manager = AccountManager::from_manifest(manifest, mafiles_dir);
				manager.register_accounts(accounts);
				manager.save()?;
				manager
			}
			Err(err) => {
				error!("Failed to load manifest: {}", err);
				return Err(err.into());
			}
		}
	}

	let mut passkey: Option<String> = args.passkey.clone();
	manager.submit_passkey(passkey);

	loop {
		match manager.auto_upgrade() {
			Ok(upgraded) => {
				if upgraded {
					info!("Manifest auto-upgraded");
					manager.save()?;
				} else {
					debug!("Manifest is up to date");
				}
				break;
			}
			Err(
				accountmanager::ManifestAccountLoadError::MissingPasskey
				| accountmanager::ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manager.has_passkey() {
					error!("Incorrect passkey");
				}
				passkey = rpassword::prompt_password_stderr("Enter encryption passkey: ").ok();
				manager.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return Err(e.into());
			}
		}
	}

	match args.sub {
		Some(cli::Subcommands::Setup(args)) => {
			return do_subcmd_setup(args, &mut manager);
		}
		Some(cli::Subcommands::Import(args)) => {
			return do_subcmd_import(args, &mut manager);
		}
		Some(cli::Subcommands::Encrypt(args)) => {
			return do_subcmd_encrypt(args, &mut manager);
		}
		Some(cli::Subcommands::Decrypt(args)) => {
			return do_subcmd_decrypt(args, &mut manager);
		}
		_ => {}
	}

	let selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>;
	loop {
		match get_selected_accounts(&args, &mut manager) {
			Ok(accounts) => {
				selected_accounts = accounts;
				break;
			}
			Err(
				accountmanager::ManifestAccountLoadError::MissingPasskey
				| accountmanager::ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manager.has_passkey() {
					error!("Incorrect passkey");
				}
				passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				manager.submit_passkey(passkey);
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
		cli::Subcommands::Trade(args) => do_subcmd_trade(args, &mut manager, selected_accounts),
		cli::Subcommands::Remove(args) => do_subcmd_remove(args, &mut manager, selected_accounts),
		cli::Subcommands::Code(args) => do_subcmd_code(args, selected_accounts),
		#[cfg(feature = "qr")]
		cli::Subcommands::Qr(args) => do_subcmd_qr(args, selected_accounts),
		#[cfg(debug_assertions)]
		cli::Subcommands::TestLogin => test_login::do_subcmd_test_login(selected_accounts),
		s => {
			error!("Unknown subcommand: {:?}", s);
			Err(errors::UserError::UnknownSubcommand.into())
		}
	}
}

fn get_selected_accounts(
	args: &cli::Args,
	manifest: &mut accountmanager::AccountManager,
) -> anyhow::Result<Vec<Arc<Mutex<SteamGuardAccount>>>, ManifestAccountLoadError> {
	let mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>> = vec![];

	if args.all {
		manifest.load_accounts()?;
		for entry in manifest.iter() {
			selected_accounts.push(manifest.get_account(&entry.account_name).unwrap().clone());
		}
	} else {
		let entry = if let Some(username) = &args.username {
			manifest.get_entry(username)
		} else {
			manifest
				.iter()
				.next()
				.ok_or(ManifestAccountLoadError::MissingManifestEntry)
		}?;

		let account_name = entry.account_name.clone();
		let account = manifest.get_or_load_account(&account_name)?;
		selected_accounts.push(account);
	}
	Ok(selected_accounts)
}

fn do_login(account: &mut SteamGuardAccount) -> anyhow::Result<()> {
	if !account.account_name.is_empty() {
		info!("Username: {}", account.account_name);
	} else {
		eprint!("Username: ");
		account.account_name = tui::prompt();
	}
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if !password.is_empty() {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	let tokens = do_login_impl(account.account_name.clone(), password, Some(account))?;
	let steam_id = tokens.access_token().decode()?.steam_id();
	account.set_tokens(tokens);
	account.steam_id = steam_id;
	Ok(())
}

fn do_login_raw(username: String) -> anyhow::Result<Tokens> {
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if !password.is_empty() {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	do_login_impl(username, password, None)
}

fn do_login_impl(
	username: String,
	password: String,
	account: Option<&SteamGuardAccount>,
) -> anyhow::Result<Tokens> {
	let mut login = UserLogin::new(
		EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
		build_device_details(),
	);

	let mut password = password;
	let mut confirmation_methods;
	loop {
		match login.begin_auth_via_credentials(&username, &password) {
			Ok(methods) => {
				confirmation_methods = methods;
				break;
			}
			Err(LoginError::TooManyAttempts) => {
				error!("Too many login attempts. Steam is rate limiting you. Please wait a while and try again later.");
				return Err(LoginError::TooManyAttempts.into());
			}
			Err(LoginError::BadCredentials) => {
				error!("Incorrect password.");
				password = rpassword::prompt_password_stdout("Password: ")
					.unwrap()
					.trim()
					.to_owned();
				continue;
			}
			Err(err) => {
				error!("Unexpected error when trying to log in. If you report this as a bug, please rerun with `-v debug` or `-v trace` and include all output in your issue. {:?}", err);
				return Err(err.into());
			}
		}
	}

	for (method) in confirmation_methods {
		match method.confirmation_type {
			EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
				eprintln!("Please confirm this login on your other device.");
				eprintln!("Press enter when you have confirmed.");
				tui::pause();
			}
			EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
				eprint!("Please confirm this login by clicking the link in your email.");
				if !method.associated_messsage.is_empty() {
					eprint!(" ({})", method.associated_messsage);
				}
				eprintln!();
				eprintln!("Press enter when you have confirmed.");
				tui::pause();
			}
			EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
				let code = if let Some(account) = account {
					debug!("Generating 2fa code...");
					let time = steamapi::get_server_time()?.server_time;
					account.generate_code(time)
				} else {
					eprint!("Enter the 2fa code from your device: ");
					tui::prompt().trim().to_owned()
				};
				login.submit_steam_guard_code(method.confirmation_type, code)?;
			}
			EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => {
				eprint!("Enter the 2fa code sent to your email: ");
				let code = tui::prompt().trim().to_owned();
				login.submit_steam_guard_code(method.confirmation_type, code)?;
			}
			_ => {
				warn!("Unknown confirmation method: {:?}", method);
				continue;
			}
		}
		break;
	}

	info!("Polling for tokens... -- If this takes a long time, try logging in again.");
	let tokens = login.poll_until_tokens()?;

	info!("Logged in successfully!");
	Ok(tokens)
}

fn build_device_details() -> DeviceDetails {
	DeviceDetails {
		friendly_name: format!(
			"{} (steamguard-cli)",
			gethostname::gethostname()
				.into_string()
				.expect("failed to get hostname")
		),
		platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
		os_type: -500,
		gaming_device_type: 528,
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

fn load_accounts_with_prompts(manifest: &mut accountmanager::AccountManager) -> anyhow::Result<()> {
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
	if args.demo_prompt {
		demos::demo_prompt();
	}
	if args.demo_pause {
		demos::demo_pause();
	}
	if args.demo_prompt_char {
		demos::demo_prompt_char();
	}
	if args.demo_conf_menu {
		demos::demo_confirmation_menu();
	}
	Ok(())
}

fn do_subcmd_completion(args: cli::ArgsCompletions) -> Result<(), anyhow::Error> {
	let mut app = cli::Args::command_for_update();
	clap_complete::generate(args.shell, &mut app, "steamguard", &mut std::io::stdout());
	Ok(())
}

fn do_subcmd_setup(
	_args: cli::ArgsSetup,
	manifest: &mut accountmanager::AccountManager,
) -> anyhow::Result<()> {
	eprintln!("Log in to the account that you want to link to steamguard-cli");
	eprint!("Username: ");
	let username = tui::prompt().to_lowercase();
	let account_name = username.clone();
	if manifest.account_exists(&username) {
		bail!(
			"Account {} already exists in manifest, remove it first",
			username
		);
	}
	info!("Logging in to {}", username);
	let session = do_login_raw(username).expect("Failed to log in. Account has not been linked.");

	info!("Adding authenticator...");
	let mut linker = AccountLinker::new(session);
	let link: AccountLinkSuccess;
	loop {
		match linker.link() {
			Ok(a) => {
				link = a;
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
	let mut server_time = link.server_time();
	let phone_number_hint = link.phone_number_hint().to_owned();
	manifest.add_account(link.into_account());
	match manifest.save() {
		Ok(_) => {}
		Err(err) => {
			error!("Aborting the account linking process because we failed to save the manifest. This is really bad. Here is the error: {}", err);
			println!(
				"Just in case, here is the account info. Save it somewhere just in case!\n{:#?}",
				manifest.get_account(&account_name).unwrap().lock().unwrap()
			);
			return Err(err);
		}
	}

	let account_arc = manifest
		.get_account(&account_name)
		.expect("account was not present in manifest");
	let mut account = account_arc.lock().unwrap();

	println!("Authenticator has not yet been linked. Before continuing with finalization, please take the time to write down your revocation code: {}", account.revocation_code.expose_secret());
	tui::pause();

	debug!("attempting link finalization");
	println!(
		"A code has been sent to your phone number ending in {}.",
		phone_number_hint
	);
	print!("Enter SMS code: ");
	let sms_code = tui::prompt();
	let mut tries = 0;
	loop {
		match linker.finalize(server_time, &mut account, sms_code.clone()) {
			Ok(_) => break,
			Err(FinalizeLinkError::WantMore { server_time: s }) => {
				server_time = s;
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
	let revocation_code = account.revocation_code.clone();
	drop(account); // explicitly drop the lock so we don't hang on the mutex

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
		revocation_code.expose_secret()
	);

	Ok(())
}

fn do_subcmd_import(
	args: cli::ArgsImport,
	manifest: &mut accountmanager::AccountManager,
) -> anyhow::Result<()> {
	for file_path in args.files {
		if args.sda {
			let path = Path::new(&file_path);
			let account = accountmanager::migrate::load_and_upgrade_sda_account(path)?;
			manifest.add_account(account);
			info!("Imported account: {}", &file_path);
		} else {
			match manifest.import_account(&file_path) {
				Ok(_) => {
					info!("Imported account: {}", &file_path);
				}
				Err(err) => {
					bail!("Failed to import account: {} {}", &file_path, err);
				}
			}
		}
	}

	manifest.save()?;
	Ok(())
}

fn do_subcmd_trade(
	args: cli::ArgsTrade,
	manifest: &mut accountmanager::AccountManager,
	mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> anyhow::Result<()> {
	for a in selected_accounts.iter_mut() {
		let mut account = a.lock().unwrap();

		if !account.is_logged_in() {
			info!("Account does not have tokens, logging in");
			do_login(&mut account)?;
		}

		info!("Checking for trade confirmations");
		let confirmations: Vec<Confirmation>;
		loop {
			match account.get_trade_confirmations() {
				Ok(confs) => {
					confirmations = confs;
					break;
				}
				Err(err) => {
					error!("Failed to get trade confirmations: {:#?}", err);
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
		} else if stdout().is_tty() {
			let (accept, deny) = tui::prompt_confirmation_menu(confirmations)?;
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

		if any_failed {
			error!("Failed to respond to some confirmations.");
		}
	}

	manifest.save()?;
	Ok(())
}

fn do_subcmd_remove(
	_args: cli::ArgsRemove,
	manifest: &mut accountmanager::AccountManager,
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
		let mut account = a.lock().unwrap();
		if !account.is_logged_in() {
			info!("Account does not have tokens, logging in");
			do_login(&mut account)?;
		}

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
	Ok(())
}

fn do_subcmd_encrypt(
	_args: cli::ArgsEncrypt,
	manifest: &mut accountmanager::AccountManager,
) -> anyhow::Result<()> {
	if !manifest.has_passkey() {
		let mut passkey;
		loop {
			passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
			if let Some(p) = passkey.as_ref() {
				if p.is_empty() {
					error!("Passkey cannot be empty, try again.");
					continue;
				}
			}
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
	for entry in manifest.iter_mut() {
		entry.encryption = Some(accountmanager::EntryEncryptionParams::generate());
	}
	manifest.save()?;
	Ok(())
}

fn do_subcmd_decrypt(
	_args: cli::ArgsDecrypt,
	manifest: &mut accountmanager::AccountManager,
) -> anyhow::Result<()> {
	load_accounts_with_prompts(manifest)?;
	for mut entry in manifest.iter_mut() {
		entry.encryption = None;
	}
	manifest.submit_passkey(None);
	manifest.save()?;
	Ok(())
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
	Ok(())
}

#[cfg(feature = "qr")]
fn do_subcmd_qr(
	args: cli::ArgsQr,
	selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> anyhow::Result<()> {
	use anyhow::Context;

	info!(
		"Generating QR codes for {} accounts",
		selected_accounts.len()
	);

	for account in selected_accounts {
		let account = account.lock().unwrap();
		let qr = QrCode::new(account.uri.expose_secret())
			.context(format!("generating qr code for {}", account.account_name))?;

		info!("Printing QR code for {}", account.account_name);
		let qr_string = if args.ascii {
			qr.render()
				.light_color(' ')
				.dark_color('#')
				.module_dimensions(2, 1)
				.build()
		} else {
			use qrcode::render::unicode;
			qr.render::<unicode::Dense1x2>()
				.dark_color(unicode::Dense1x2::Light)
				.light_color(unicode::Dense1x2::Dark)
				.build()
		};

		println!("{}", qr_string);
	}
	Ok(())
}
