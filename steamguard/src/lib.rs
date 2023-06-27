use crate::protobufs::service_twofactor::CTwoFactor_RemoveAuthenticator_Request;
use crate::steamapi::EResult;
use crate::{
	steamapi::twofactor::TwoFactorClient, token::TwoFactorSecret, transport::WebApiTransport,
};
pub use accountlinker::{AccountLinkError, AccountLinker, FinalizeLinkError};
pub use confirmation::*;
pub use qrapprover::{QrApprover, QrApproverError};
pub use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::Read;
use token::Tokens;
pub use userlogin::{DeviceDetails, LoginError, UserLogin};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate maplit;

pub mod accountlinker;
mod api_responses;
mod confirmation;
pub mod phonelinker;
pub mod protobufs;
mod qrapprover;
pub mod refresher;
mod secret_string;
pub mod steamapi;
pub mod token;
pub mod transport;
pub mod userlogin;

extern crate base64;
extern crate cookie;
extern crate hmacsha1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamGuardAccount {
	pub account_name: String,
	pub steam_id: u64,
	pub serial_number: String,
	#[serde(with = "secret_string")]
	pub revocation_code: SecretString,
	pub shared_secret: TwoFactorSecret,
	pub token_gid: String,
	#[serde(with = "secret_string")]
	pub identity_secret: SecretString,
	#[serde(with = "secret_string")]
	pub uri: SecretString,
	pub device_id: String,
	#[serde(with = "secret_string")]
	pub secret_1: SecretString,
	pub tokens: Option<Tokens>,
}

impl Default for SteamGuardAccount {
	fn default() -> Self {
		Self {
			account_name: String::from(""),
			steam_id: 0,
			serial_number: String::from(""),
			revocation_code: String::from("").into(),
			shared_secret: TwoFactorSecret::new(),
			token_gid: String::from(""),
			identity_secret: String::from("").into(),
			uri: String::from("").into(),
			device_id: String::from(""),
			secret_1: String::from("").into(),
			tokens: None,
		}
	}
}

impl SteamGuardAccount {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn from_reader<T>(r: T) -> anyhow::Result<Self>
	where
		T: Read,
	{
		Ok(serde_json::from_reader(r)?)
	}

	pub fn set_tokens(&mut self, tokens: Tokens) {
		self.tokens = Some(tokens);
	}

	pub fn is_logged_in(&self) -> bool {
		self.tokens.is_some()
	}

	pub fn generate_code(&self, time: u64) -> String {
		self.shared_secret.generate_code(time)
	}

	/// Removes the mobile authenticator from the steam account. If this operation succeeds, this object can no longer be considered valid.
	/// Returns whether or not the operation was successful.
	pub fn remove_authenticator(&self, revocation_code: Option<String>) -> anyhow::Result<bool> {
		ensure!(
			matches!(revocation_code, Some(_)) || !self.revocation_code.expose_secret().is_empty(),
			"Revocation code not provided."
		);
		let Some(tokens) = &self.tokens else {
			return Err(anyhow!("Tokens not set, login required"));
		};
		let mut client = TwoFactorClient::new(WebApiTransport::new());
		let mut req = CTwoFactor_RemoveAuthenticator_Request::new();
		req.set_revocation_code(
			revocation_code.unwrap_or(self.revocation_code.expose_secret().to_owned()),
		);
		let resp = client.remove_authenticator(req, tokens.access_token())?;
		if resp.result != EResult::OK {
			Err(anyhow!("Failed to remove authenticator: {:?}", resp.result))
		} else {
			Ok(true)
		}
	}
}
