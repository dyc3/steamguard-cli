extern crate rpassword;
use clap::Parser;
use log::*;
use secrecy::SecretString;
use std::{
	io::Write,
	path::Path,
	sync::{Arc, Mutex},
};
use steamguard::{
	protobufs::steammessages_auth_steamclient::{EAuthSessionGuardType, EAuthTokenPlatformType},
	refresher::TokenRefresher,
	transport::{Transport, WebApiTransport},
};
use steamguard::{steamapi, DeviceDetails, LoginError, SteamGuardAccount, UserLogin};
use steamguard::{steamapi::AuthenticationClient, token::Tokens};

use crate::accountmanager::migrate::{load_and_migrate, MigrationError};
pub use crate::accountmanager::{AccountManager, ManifestAccountLoadError, ManifestLoadError};
use crate::commands::{CommandType, Subcommands};

extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate base64;
extern crate dirs;
#[cfg(test)]
extern crate proptest;
extern crate ring;
mod accountmanager;
mod commands;
mod debug;
mod encryption;
mod errors;
mod secret_string;
pub(crate) mod tui;
#[cfg(feature = "updater")]
mod updater;

fn main() {
	let args = commands::Args::parse();

	stderrlog::new()
		.verbosity(args.global.verbosity as usize)
		.module(module_path!())
		.module("steamguard")
		.init()
		.unwrap();
	debug!("{:?}", args);
	#[cfg(feature = "updater")]
	let should_do_update_check = !args.global.no_update_check;

	let exit_code = match run(args) {
		Ok(_) => 0,
		Err(e) => {
			error!("{:?}", e);
			255
		}
	};

	#[cfg(feature = "updater")]
	if should_do_update_check {
		match updater::check_for_update() {
			Ok(Some(version)) => {
				eprintln!();
				info!(
					"steamguard-cli {} is available. Download it here: https://github.com/dyc3/steamguard-cli/releases",
					version
				);
			}
			Ok(None) => {
				debug!("No update available");
			}
			Err(e) => {
				warn!("Failed to check for updates: {}", e);
			}
		}
	}

	std::process::exit(exit_code);
}

fn run(args: commands::Args) -> anyhow::Result<()> {
	let globalargs = args.global;

	let cmd: CommandType<WebApiTransport> = match args.sub.unwrap_or(Subcommands::Code(args.code)) {
		Subcommands::Debug(args) => CommandType::Const(Box::new(args)),
		Subcommands::Completion(args) => CommandType::Const(Box::new(args)),
		Subcommands::Setup(args) => CommandType::Manifest(Box::new(args)),
		Subcommands::Import(args) => CommandType::Manifest(Box::new(args)),
		Subcommands::Encrypt(args) => CommandType::Manifest(Box::new(args)),
		Subcommands::Decrypt(args) => CommandType::Manifest(Box::new(args)),
		Subcommands::Trade(args) => CommandType::Account(Box::new(args)),
		Subcommands::Remove(args) => CommandType::Account(Box::new(args)),
		Subcommands::Code(args) => CommandType::Account(Box::new(args)),
		#[cfg(feature = "qr")]
		Subcommands::Qr(args) => CommandType::Account(Box::new(args)),
		Subcommands::QrLogin(args) => CommandType::Account(Box::new(args)),
	};

	if let CommandType::Const(cmd) = cmd {
		return cmd.execute();
	}

	let mafiles_dir = if let Some(mafiles_path) = &globalargs.mafiles_path {
		mafiles_path.clone()
	} else {
		get_mafiles_dir()
	};
	info!("reading manifest from {}", mafiles_dir);
	let path = Path::new(&mafiles_dir).join("manifest.json");
	let mut passkey = globalargs.passkey.clone();

	let mut manager: accountmanager::AccountManager;
	if !path.exists() {
		error!("Did not find manifest in {}", mafiles_dir);
		if tui::prompt_char(
			format!("Would you like to create a manifest in {} ?", mafiles_dir).as_str(),
			"Yn",
		) == 'n'
		{
			info!("Aborting!");
			return Err(errors::UserError::Aborted.into());
		}
		std::fs::create_dir_all(mafiles_dir)?;

		manager = accountmanager::AccountManager::new(path.as_path());
		manager.save()?;
	} else {
		manager = match accountmanager::AccountManager::load(path.as_path()) {
			Ok(m) => m,
			Err(ManifestLoadError::MigrationNeeded) => {
				info!("Migrating manifest");
				let manifest;
				let accounts;
				loop {
					match load_and_migrate(path.as_path(), passkey.as_ref()) {
						Ok((m, a)) => {
							manifest = m;
							accounts = a;
							break;
						}
						Err(MigrationError::MissingPasskey { keyring_id }) => {
							if passkey.is_some() {
								error!("Incorrect passkey");
							}

							#[cfg(feature = "keyring")]
							if let Some(keyring_id) = keyring_id {
								if passkey.is_none() {
									info!("Attempting to load encryption passkey from keyring");
									let entry = encryption::init_keyring(keyring_id)?;
									let raw = entry.get_password()?;
									passkey = Some(SecretString::new(raw));
									continue;
								}
							}

							let raw =
								rpassword::prompt_password_stdout("Enter encryption passkey: ")?;
							passkey = Some(SecretString::new(raw));
						}
						Err(e) => {
							error!("Failed to migrate manifest: {}", e);
							return Err(e.into());
						}
					}
				}
				let mut manager = AccountManager::from_manifest(manifest, mafiles_dir);
				manager.register_accounts(accounts);
				manager.submit_passkey(globalargs.passkey.clone());
				manager.save()?;
				manager
			}
			Err(err) => {
				error!("Failed to load manifest: {}", err);
				return Err(err.into());
			}
		}
	}

	#[cfg(feature = "keyring")]
	if let Some(keyring_id) = manager.keyring_id() {
		if passkey.is_none() {
			info!("Attempting to load encryption passkey from keyring");
			match encryption::try_passkey_from_keyring(keyring_id.clone()) {
				Ok(k) => passkey = k,
				Err(e) => {
					warn!("Failed to load encryption passkey from keyring: {}", e);
				}
			}
		}
	}

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
				let raw = rpassword::prompt_password_stdout("Enter encryption passkey: ")?;
				passkey = Some(SecretString::new(raw));
				manager.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return Err(e.into());
			}
		}
	}

	let mut http_client = reqwest::blocking::Client::builder();
	if let Some(proxy) = &globalargs.http_proxy {
		let proxy = reqwest::Proxy::all(proxy)?;
		http_client = http_client.proxy(proxy);
	}
	let http_client = http_client.build()?;
	let transport = WebApiTransport::new(http_client);

	if let CommandType::Manifest(cmd) = cmd {
		cmd.execute(transport, &mut manager)?;
		return Ok(());
	}

	let selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>;
	loop {
		match get_selected_accounts(&globalargs, &mut manager) {
			Ok(accounts) => {
				selected_accounts = accounts;
				break;
			}
			Err(
				accountmanager::ManifestAccountLoadError::MissingPasskey { .. }
				| accountmanager::ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manager.has_passkey() {
					error!("Incorrect passkey");
				}
				let raw = rpassword::prompt_password_stdout("Enter encryption passkey: ")?;
				passkey = Some(SecretString::new(raw));
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

	if let CommandType::Account(cmd) = cmd {
		return cmd.execute(transport, &mut manager, selected_accounts);
	}

	Ok(())
}

fn get_selected_accounts(
	args: &commands::GlobalArgs,
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

fn do_login<T: Transport + Clone>(
	transport: T,
	account: &mut SteamGuardAccount,
) -> anyhow::Result<()> {
	if let Some(tokens) = account.tokens.as_mut() {
		info!("Refreshing access token...");
		let client = AuthenticationClient::new(transport.clone());
		let mut refresher = TokenRefresher::new(client);
		match refresher.refresh(account.steam_id, tokens) {
			Ok(token) => {
				info!("Successfully refreshed access token, no need to prompt to log in.");
				tokens.set_access_token(token);
				return Ok(());
			}
			Err(err) => {
				warn!(
					"Failed to refresh access token, prompting for login: {}",
					err
				);
			}
		}
	}

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
	let tokens = do_login_impl(
		transport,
		account.account_name.clone(),
		password,
		Some(account),
	)?;
	let steam_id = tokens.access_token().decode()?.steam_id();
	account.set_tokens(tokens);
	account.steam_id = steam_id;
	Ok(())
}

fn do_login_raw<T: Transport + Clone>(transport: T, username: String) -> anyhow::Result<Tokens> {
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if !password.is_empty() {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	do_login_impl(transport, username, password, None)
}

fn do_login_impl<T: Transport + Clone>(
	transport: T,
	username: String,
	password: String,
	account: Option<&SteamGuardAccount>,
) -> anyhow::Result<Tokens> {
	let mut login = UserLogin::new(transport.clone(), build_device_details());

	let mut password = password;
	let confirmation_methods;
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

	for method in confirmation_methods {
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
					let time = steamapi::get_server_time(transport)?.server_time();
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
