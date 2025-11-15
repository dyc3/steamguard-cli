use crate::commands::AccountCommand;
use crate::{commands::GlobalArgs, AccountManager};
use base64::Engine;
use clap::Parser;
use hmac::{Hmac, Mac};
use log::*;
use secrecy::ExposeSecret;
use sha1::Sha1;
use sha2::Sha256;
use std::sync::{Arc, Mutex};
use steamguard::protobufs::service_twofactor::{
	CTwoFactor_Status_Request, CTwoFactor_UpdateTokenVersion_Request,
};
use steamguard::steamapi::{EResult, TwoFactorClient};
use steamguard::transport::{Transport, TransportError};
use steamguard::SteamGuardAccount;
use thiserror::Error;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Upgrade the token version for accounts.")]
pub struct UpgradeTokenCommand;

impl<T> AccountCommand<T> for UpgradeTokenCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
		let twofactor = TwoFactorClient::new(transport.clone());
		for account in accounts {
			let mut account = account.lock().unwrap();
			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(transport.clone(), &mut account, args.password.clone())?;
			}

			// check the version of the token
			let version = self.get_token_version(&twofactor, &account)?;
			if version == 2 {
				info!(
					"Token for {} is already at version 2. Nothing to do.",
					account.account_name
				);
				continue;
			}

			let result = self.upgrade_token(&twofactor, &account);
			match result {
				Ok(_) => {
					info!("Successfully upgraded token for {}", account.account_name);
				}
				Err(e) => {
					error!(
						"Failed to upgrade token for {}: {}",
						account.account_name, e
					);
				}
			}
		}
		manager.save()?;
		Ok(())
	}
}

impl UpgradeTokenCommand {
	/// Upgrade the token version for the given account to version 2.
	fn upgrade_token<T: Transport>(
		&self,
		client: &TwoFactorClient<T>,
		account: &SteamGuardAccount,
	) -> Result<(), UpgradeTokenError> {
		let access_token = account
			.tokens
			.as_ref()
			.ok_or(TransportError::Unauthorized)?
			.access_token();
		let signature = build_upgrade_signature(account, 2);

		let mut req = CTwoFactor_UpdateTokenVersion_Request::new();
		req.set_steamid(account.steam_id);
		req.set_version(2);
		req.set_signature(signature.to_vec());

		let resp = client.update_token_version(req, access_token)?;
		// Thankfully, we don't need to save anything from this response since it's empty.

		match resp.result() {
			EResult::OK => Ok(()),
			EResult::InvalidSignature => Err(UpgradeTokenError::InvalidSignature),
			err => Err(UpgradeTokenError::Unknown(err).into()),
		}
	}

	fn get_token_version<T: Transport>(
		&self,
		client: &TwoFactorClient<T>,
		account: &SteamGuardAccount,
	) -> Result<u32, UpgradeTokenError> {
		let access_token = account
			.tokens
			.as_ref()
			.ok_or(TransportError::Unauthorized)?
			.access_token();

		let mut req = CTwoFactor_Status_Request::new();
		req.set_steamid(account.steam_id);
		let resp = client.query_status(req, access_token)?;

		let data = resp.into_response_data();

		Ok(data.version())
	}
}

/// Reverse engineered from the Steam mobile app. (WIP: does not work yet)
///
/// Pretty confident that it uses Sha1 for the HMAC.
fn build_upgrade_signature(account: &SteamGuardAccount, version: u32) -> [u8; 32] {
	let mut buffer = [0u8; 12];
	buffer[0..4].copy_from_slice(&version.to_le_bytes());
	buffer[4..12].copy_from_slice(&account.steam_id.to_le_bytes());

	let mut mac = Hmac::<Sha1>::new_from_slice(&buffer).unwrap();
	// mac.update(account.shared_secret.expose_secret());
	let decode: &[u8] = &base64::engine::general_purpose::STANDARD
		.decode(account.identity_secret.expose_secret())
		.unwrap();
	mac.update(decode);
	let result = mac.finalize();
	result.into_bytes().into()
}

#[derive(Debug, Error)]
enum UpgradeTokenError {
	#[error(
		"The signature we provided was invalid. This is a bug in steamguard-cli, please report it!"
	)]
	InvalidSignature,
	#[error("Steam returned an unexpected error code when upgrading the 2fa token: {0:?}")]
	Unknown(EResult),
	#[error("Transport error: {0}")]
	TransportError(#[from] TransportError),
}
