use crate::token::TwoFactorSecret;
use accountlinker::RemoveAuthenticatorError;
pub use accountlinker::{AccountLinkError, AccountLinker, FinalizeLinkError};
pub use approver::{ApproverError, LoginApprover};
pub use confirmation::*;
pub use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::Read;
use token::Tokens;
use transport::{Transport, TransportError};
pub use userlogin::{DeviceDetails, LoginError, UserLogin};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate maplit;

pub mod accountlinker;
mod api_responses;
pub mod approver;
mod confirmation;
pub mod phonelinker;
pub mod protobufs;
pub mod refresher;
mod secret_string;
pub mod steamapi;
pub mod token;
pub mod transport;
pub mod userlogin;

extern crate base64;
extern crate cookie;

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

	pub fn from_file(path: &str) -> anyhow::Result<Self> {
		let file = std::fs::File::open(path)?;
		Self::from_reader(file)
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
	///
	/// A convenience method for [`AccountLinker::remove_authenticator`].
	pub fn remove_authenticator(
		&self,
		transport: impl Transport,
		revocation_code: Option<&String>,
	) -> Result<(), RemoveAuthenticatorError> {
		let Some(tokens) = &self.tokens else {
			return Err(RemoveAuthenticatorError::TransportError(
				TransportError::Unauthorized,
			));
		};
		let revocation_code =
			Some(revocation_code.unwrap_or_else(|| self.revocation_code.expose_secret()));
		let linker = AccountLinker::new(transport, tokens.clone());
		linker.remove_authenticator(revocation_code)
	}
}
