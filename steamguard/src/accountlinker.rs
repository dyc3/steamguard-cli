use crate::{
	steamapi::{AddAuthenticatorResponse, Session, SteamApiClient},
	SteamGuardAccount,
};
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

	pub fn link(&mut self) -> anyhow::Result<SteamGuardAccount, AccountLinkError> {
		let has_phone = self.client.has_phone()?;

		if has_phone && !self.phone_number.is_empty() {
			return Err(AccountLinkError::MustRemovePhoneNumber);
		}
		if !has_phone && self.phone_number.is_empty() {
			return Err(AccountLinkError::MustProvidePhoneNumber);
		}

		if !has_phone {
			if self.sent_confirmation_email {
				if !self.client.check_email_confirmation()? {
					return Err(AccountLinkError::Unknown(anyhow!(
						"Failed email confirmation check"
					)));
				}
			} else if !self.client.add_phone_number(self.phone_number.clone())? {
				return Err(AccountLinkError::Unknown(anyhow!(
					"Failed to add phone number"
				)));
			} else {
				self.sent_confirmation_email = true;
				return Err(AccountLinkError::MustConfirmEmail);
			}
		}

		let resp: AddAuthenticatorResponse =
			self.client.add_authenticator(self.device_id.clone())?;

		match resp.response.status {
			29 => {
				return Err(AccountLinkError::AuthenticatorPresent);
			}
			1 => {
				let mut account = resp.to_steam_guard_account();
				account.device_id = self.device_id.clone();
				account.session = self.client.session.clone();
				return Ok(account);
			}
			status => {
				return Err(AccountLinkError::Unknown(anyhow!(
					"Unknown add authenticator status code: {}",
					status
				)));
			}
		}
	}

	pub fn finalize(&self, account: &SteamGuardAccount, sms_code: String) {}
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
	NetworkFailure(reqwest::Error),
	Unknown(anyhow::Error),
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

impl From<anyhow::Error> for AccountLinkError {
	fn from(err: anyhow::Error) -> AccountLinkError {
		AccountLinkError::Unknown(err)
	}
}
