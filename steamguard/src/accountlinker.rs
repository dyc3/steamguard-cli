use crate::{steamapi::Session, SteamGuardAccount};
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct AccountLinker {
	device_id: String,
	phone_number: String,
	pub account: SteamGuardAccount,
	pub finalized: bool,
	client: reqwest::blocking::Client,
}

impl AccountLinker {
	pub fn new() -> AccountLinker {
		return AccountLinker {
			device_id: generate_device_id(),
			phone_number: String::from(""),
			account: SteamGuardAccount::new(),
			finalized: false,
			client: reqwest::blocking::ClientBuilder::new()
				.cookie_store(true)
				.build()
				.unwrap(),
		};
	}

	pub fn link(
		&self,
		session: &mut Session,
	) -> anyhow::Result<AddAuthenticatorResponse, AccountLinkError> {
		let mut params = HashMap::new();
		params.insert("access_token", session.token.clone());
		params.insert("steamid", session.steam_id.to_string());
		params.insert("device_identifier", self.device_id.clone());
		params.insert("authenticator_type", "1".into());
		params.insert("sms_phone_id", "1".into());

		let resp: AddAuthenticatorResponse = self
			.client
			.post("https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v0001")
			.form(&params)
			.send()?
			.json()?;

		return Err(AccountLinkError::Unknown);
	}

	pub fn finalize(&self, session: &Session) {}
}

fn generate_device_id() -> String {
	return format!("android:{}", uuid::Uuid::new_v4().to_string());
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddAuthenticatorResponse {
	pub response: SteamGuardAccount,
}

#[derive(Debug)]
pub enum AccountLinkError {
	/// No phone number on the account
	MustProvidePhoneNumber,
	/// A phone number is already on the account
	MustRemovePhoneNumber,
	/// User need to click link from confirmation email
	MustConfirmEmail,
	/// Must provide an SMS code
	AwaitingFinalization,
	AuthenticatorPresent,
	NetworkFailure(reqwest::Error),
	Unknown,
}

impl Display for AccountLinkError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl Error for AccountLinkError {}

impl From<reqwest::Error> for AccountLinkError {
	fn from(err: reqwest::Error) -> AccountLinkError {
		AccountLinkError::NetworkFailure(err)
	}
}
