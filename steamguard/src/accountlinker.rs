use crate::{
	steamapi::{
		AddAuthenticatorResponse, FinalizeAddAuthenticatorResponse, Session, SteamApiClient,
	},
	SteamGuardAccount,
};
use log::*;
use thiserror::Error;

#[derive(Debug)]
pub struct AccountLinker {
	device_id: String,
	pub phone_number: String,
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
			session: session.clone(),
			client: SteamApiClient::new(Some(session)),
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
					return Err(anyhow!("Failed email confirmation check"))?;
				}
			} else if !self.client.add_phone_number(self.phone_number.clone())? {
				return Err(anyhow!("Failed to add phone number"))?;
			} else {
				self.sent_confirmation_email = true;
				return Err(AccountLinkError::MustConfirmEmail);
			}
		}

		let resp: AddAuthenticatorResponse =
			self.client.add_authenticator(self.device_id.clone())?;

		match resp.status {
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
				return Err(anyhow!("Unknown add authenticator status code: {}", status))?;
			}
		}
	}

	/// You may have to call this multiple times. If you have to call it a bunch of times, then you can assume that you are unable to generate correct 2fa codes.
	pub fn finalize(
		&mut self,
		account: &mut SteamGuardAccount,
		sms_code: String,
	) -> anyhow::Result<(), FinalizeLinkError> {
		let time = crate::steamapi::get_server_time();
		let code = account.generate_code(time);
		let resp: FinalizeAddAuthenticatorResponse =
			self.client
				.finalize_authenticator(sms_code.clone(), code, time)?;
		info!("finalize response status: {}", resp.status);

		match resp.status {
			89 => {
				return Err(FinalizeLinkError::BadSmsCode);
			}
			_ => {}
		}

		if !resp.success {
			return Err(FinalizeLinkError::Failure {
				status: resp.status,
			})?;
		}

		if resp.want_more {
			return Err(FinalizeLinkError::WantMore);
		}

		self.finalized = true;
		account.fully_enrolled = true;
		return Ok(());
	}
}

fn generate_device_id() -> String {
	return format!("android:{}", uuid::Uuid::new_v4().to_string());
}

#[derive(Error, Debug)]
pub enum AccountLinkError {
	/// No phone number on the account
	#[error("A phone number is needed, but not already present on the account.")]
	MustProvidePhoneNumber,
	/// A phone number is already on the account
	#[error("A phone number was provided, but one is already present on the account.")]
	MustRemovePhoneNumber,
	/// User need to click link from confirmation email
	#[error("An email has been sent to the user's email, click the link in that email.")]
	MustConfirmEmail,
	#[error("Authenticator is already present.")]
	AuthenticatorPresent,
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum FinalizeLinkError {
	#[error("Provided SMS code was incorrect.")]
	BadSmsCode,
	/// Steam wants more 2fa codes to verify that we can generate valid codes. Call finalize again.
	#[error("Steam wants more 2fa codes for verification.")]
	WantMore,
	#[error("Finalization was not successful. Status code {status:?}")]
	Failure { status: i32 },
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}
