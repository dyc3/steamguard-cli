use std::io::Write;

use log::*;
use secrecy::{ExposeSecret, SecretString};
use steamguard::{
	protobufs::steammessages_auth_steamclient::{EAuthSessionGuardType, EAuthTokenPlatformType},
	refresher::TokenRefresher,
	steamapi::{self, AuthenticationClient},
	token::Tokens,
	transport::Transport,
	DeviceDetails, LoginError, SteamGuardAccount, UserLogin,
};

use crate::tui;

/// Performs a login, prompting for credentials if necessary.
pub fn do_login<T: Transport + Clone>(
	transport: T,
	account: &mut SteamGuardAccount,
	password: Option<SecretString>,
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
	let password = if let Some(p) = password {
		p
	} else {
		tui::prompt_password()?
	};
	if !password.expose_secret().is_empty() {
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

pub fn do_login_raw<T: Transport + Clone>(
	transport: T,
	username: String,
	password: Option<SecretString>,
) -> anyhow::Result<Tokens> {
	let _ = std::io::stdout().flush();
	let password = if let Some(p) = password {
		p
	} else {
		tui::prompt_password()?
	};
	if !password.expose_secret().is_empty() {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	do_login_impl(transport, username, password, None)
}

fn do_login_impl<T: Transport + Clone>(
	transport: T,
	username: String,
	password: SecretString,
	account: Option<&SteamGuardAccount>,
) -> anyhow::Result<Tokens> {
	debug!("starting login");
	let mut login = UserLogin::new(transport.clone(), build_device_details());

	let mut password = password;
	let confirmation_methods;
	loop {
		match login.begin_auth_via_credentials(&username, password.expose_secret()) {
			Ok(methods) => {
				confirmation_methods = methods;
				break;
			}
			Err(LoginError::TooManyAttempts) => {
				error!("Too many login attempts. Steam is rate limiting you. Please wait a while and try again later.");
				return Err(LoginError::TooManyAttempts.into());
			}
			Err(LoginError::BadCredentials) => {
				error!("Incorrect password for {username}");
				password = tui::prompt_password()?;
				continue;
			}
			Err(err) => {
				error!("Unexpected error when trying to log in. If you report this as a bug, please rerun with `-v debug` or `-v trace` and include all output in your issue. {:?}", err);
				return Err(err.into());
			}
		}
	}

	debug!(
		"got {} confirmation methods: {:#?}",
		confirmation_methods.len(),
		confirmation_methods
	);

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
			EAuthSessionGuardType::k_EAuthSessionGuardType_None => {
				debug!("No login confirmation required. Proceeding with login.");
				continue;
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
