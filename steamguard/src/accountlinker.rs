use crate::{
	steamapi::{AddAuthenticatorResponse, Session, SteamApiClient},
	SteamGuardAccount,
};
use log::*;
use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub struct AccountLinker {
	device_id: String,
	phone_number: String,
	pub account: Option<SteamGuardAccount>,
	pub finalized: bool,
	sent_confirmation_email: bool,
	session: Session,
	client: SteamApiClient,
}

impl AccountLinker {
	pub fn new(session: Session) -> AccountLinker {
		return AccountLinker {
			device_id: generate_device_id(),
			phone_number: "".into(),
			account: None,
			finalized: false,
			sent_confirmation_email: false,
			session: session,
			client: SteamApiClient::new(),
		};
	}

	pub fn link(&mut self) -> anyhow::Result<SteamGuardAccount> {
		ensure!(!self.finalized);

		let has_phone = self.client.has_phone()?;

		if has_phone && !self.phone_number.is_empty() {
			bail!(AccountLinkError::MustRemovePhoneNumber);
		}
		if !has_phone && self.phone_number.is_empty() {
			bail!(AccountLinkError::MustProvidePhoneNumber);
		}

		if !has_phone {
			if self.sent_confirmation_email {
				if !self.client.check_email_confirmation()? {
					bail!("Failed email confirmation check");
				}
			} else if !self.client.add_phone_number(self.phone_number.clone())? {
				bail!("Failed to add phone number");
			} else {
				self.sent_confirmation_email = true;
				bail!(AccountLinkError::MustConfirmEmail);
			}
		}

		let resp: AddAuthenticatorResponse =
			self.client.add_authenticator(self.device_id.clone())?;

		match resp.status {
			29 => {
				bail!(AccountLinkError::AuthenticatorPresent);
			}
			1 => {
				let mut account = resp.to_steam_guard_account();
				account.device_id = self.device_id.clone();
				account.session = self.client.session.clone();
				return Ok(account);
			}
			status => {
				bail!("Unknown add authenticator status code: {}", status);
			}
		}
	}

	/// You may have to call this multiple times. If you have to call it a bunch of times, then you can assume that you are unable to generate correct 2fa codes.
	pub fn finalize(
		&mut self,
		account: &mut SteamGuardAccount,
		sms_code: String,
	) -> anyhow::Result<()> {
		ensure!(!account.fully_enrolled);
		ensure!(!self.finalized);

		let time = crate::steamapi::get_server_time();
		let code = account.generate_code(time);
		let resp = self
			.client
			.finalize_authenticator(sms_code.clone(), code, time)?;
		info!("finalize response status: {}", resp.status);

		match resp.status {
			89 => {
				bail!(FinalizeLinkError::BadSmsCode);
			}
			_ => {}
		}

		if !resp.success {
			bail!("Failed to finalize authenticator. Status: {}", resp.status);
		}

		if resp.want_more {
			bail!(FinalizeLinkError::WantMore);
		}

		self.finalized = true;
		account.fully_enrolled = true;
		return Ok(());
	}
}

fn generate_device_id() -> String {
	return format!("android:{}", uuid::Uuid::new_v4().to_string());
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
}

impl Display for AccountLinkError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl Error for AccountLinkError {}

#[derive(Debug)]
pub enum FinalizeLinkError {
	BadSmsCode,
	/// Steam wants more 2fa codes to verify that we can generate valid codes. Call finalize again.
	WantMore,
}

impl Display for FinalizeLinkError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl Error for FinalizeLinkError {}
