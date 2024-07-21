use crate::protobufs::service_twofactor::{
	CTwoFactor_AddAuthenticator_Request, CTwoFactor_FinalizeAddAuthenticator_Request,
	CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Request,
	CTwoFactor_RemoveAuthenticatorViaChallengeStart_Request,
	CTwoFactor_RemoveAuthenticator_Request, CTwoFactor_Status_Request, CTwoFactor_Status_Response,
};
use crate::steamapi::twofactor::TwoFactorClient;
use crate::token::TwoFactorSecret;
use crate::transport::{Transport, TransportError};
use crate::{steamapi::EResult, token::Tokens, SteamGuardAccount};
use anyhow::Context;
use base64::Engine;
use log::*;
use thiserror::Error;

#[derive(Debug)]
pub struct AccountLinker<T>
where
	T: Transport,
{
	device_id: String,
	pub account: Option<SteamGuardAccount>,
	pub finalized: bool,
	tokens: Tokens,
	client: TwoFactorClient<T>,
}

impl<T> AccountLinker<T>
where
	T: Transport,
{
	pub fn new(transport: T, tokens: Tokens) -> Self {
		Self {
			device_id: generate_device_id(),
			account: None,
			finalized: false,
			tokens,
			client: TwoFactorClient::new(transport),
		}
	}

	pub fn tokens(&self) -> &Tokens {
		&self.tokens
	}

	pub fn link(&mut self) -> Result<AccountLinkSuccess, AccountLinkError> {
		let access_token = self.tokens.access_token();
		let steam_id = access_token
			.decode()
			.context("decoding access token")?
			.steam_id();

		let mut req = CTwoFactor_AddAuthenticator_Request::new();
		req.set_authenticator_type(1);
		req.set_steamid(steam_id);
		req.set_sms_phone_id("1".to_owned());
		req.set_device_identifier(self.device_id.clone());

		let resp = self
			.client
			.add_authenticator(req, access_token)
			.context("add authenticator request")?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let mut resp = resp.into_response_data();

		let account = SteamGuardAccount {
			account_name: resp.take_account_name(),
			steam_id,
			serial_number: resp.serial_number().to_string(),
			revocation_code: resp.take_revocation_code().into(),
			uri: resp.take_uri().into(),
			shared_secret: TwoFactorSecret::from_bytes(resp.take_shared_secret()),
			token_gid: resp.take_token_gid(),
			identity_secret: base64::engine::general_purpose::STANDARD
				.encode(resp.take_identity_secret())
				.into(),
			device_id: self.device_id.clone(),
			secret_1: base64::engine::general_purpose::STANDARD
				.encode(resp.take_secret_1())
				.into(),
			tokens: Some(self.tokens.clone()),
		};
		let success = AccountLinkSuccess {
			account,
			server_time: resp.server_time(),
			phone_number_hint: resp.take_phone_number_hint(),
			confirm_type: resp.confirm_type().into(),
		};
		Ok(success)
	}

	/// You may have to call this multiple times. If you have to call it a bunch of times, then you can assume that you are unable to generate correct 2fa codes.
	pub fn finalize(
		&mut self,
		time: u64,
		account: &mut SteamGuardAccount,
		confirm_code: String,
	) -> Result<(), FinalizeLinkError> {
		let code = account.generate_code(time);

		let token = self.tokens.access_token();
		let steam_id = account.steam_id;

		let mut req = CTwoFactor_FinalizeAddAuthenticator_Request::new();
		req.set_steamid(steam_id);
		req.set_authenticator_code(code);
		req.set_authenticator_time(time);
		req.set_activation_code(confirm_code);
		req.set_validate_sms_code(true);

		let resp = self.client.finalize_authenticator(req, token)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let resp = resp.into_response_data();

		if resp.want_more() {
			return Err(FinalizeLinkError::WantMore {
				server_time: resp.server_time(),
			});
		}

		self.finalized = true;
		Ok(())
	}

	pub fn query_status(
		&self,
		account: &SteamGuardAccount,
	) -> Result<CTwoFactor_Status_Response, TransportError> {
		let mut req = CTwoFactor_Status_Request::new();
		req.set_steamid(account.steam_id);

		let resp = self.client.query_status(req, self.tokens.access_token())?;

		Ok(resp.into_response_data())
	}

	pub fn remove_authenticator(
		&self,
		revocation_code: Option<&String>,
	) -> Result<(), RemoveAuthenticatorError> {
		let Some(revocation_code) = revocation_code else {
			return Err(RemoveAuthenticatorError::MissingRevocationCode);
		};
		if revocation_code.is_empty() {
			return Err(RemoveAuthenticatorError::MissingRevocationCode);
		}
		let mut req = CTwoFactor_RemoveAuthenticator_Request::new();
		req.set_revocation_code(revocation_code.clone());
		let resp = self
			.client
			.remove_authenticator(req, self.tokens.access_token())?;

		// returns EResult::TwoFactorCodeMismatch if the revocation code is incorrect
		if resp.result != EResult::OK && resp.result != EResult::TwoFactorCodeMismatch {
			return Err(resp.result.into());
		}
		let resp = resp.into_response_data();
		if !resp.success() {
			return Err(RemoveAuthenticatorError::IncorrectRevocationCode {
				attempts_remaining: resp.revocation_attempts_remaining(),
			});
		}

		Ok(())
	}

	/// Begin the process of "transfering" a mobile authenticator from a different device to this device.
	///
	/// "Transfering" does not actually literally transfer the secrets from one device to another. Instead, it generates a new set of secrets on this device, and invalidates the old secrets on the other device. Call [`Self::transfer_finish`] to complete the process.
	pub fn transfer_start(&mut self) -> Result<(), TransferError> {
		let req = CTwoFactor_RemoveAuthenticatorViaChallengeStart_Request::new();
		let resp = self
			.client
			.remove_authenticator_via_challenge_start(req, self.tokens().access_token())?;
		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}
		// the success field in the response is always None, so we can't check that
		// it appears to not be used at all
		Ok(())
	}

	/// Completes the process of "transfering" a mobile authenticator from a different device to this device.
	pub fn transfer_finish(
		&mut self,
		sms_code: impl AsRef<str>,
	) -> Result<SteamGuardAccount, TransferError> {
		let access_token = self.tokens.access_token();
		let steam_id = access_token
			.decode()
			.context("decoding access token")?
			.steam_id();
		let mut req = CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Request::new();
		req.set_sms_code(sms_code.as_ref().to_owned());
		req.set_generate_new_token(true);
		let resp = self
			.client
			.remove_authenticator_via_challenge_continue(req, access_token)?;
		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}
		let resp = resp.into_response_data();
		let mut resp = resp.replacement_token.clone().unwrap();
		let account = SteamGuardAccount {
			account_name: resp.take_account_name(),
			steam_id,
			serial_number: resp.serial_number().to_string(),
			revocation_code: resp.take_revocation_code().into(),
			uri: resp.take_uri().into(),
			shared_secret: TwoFactorSecret::from_bytes(resp.take_shared_secret()),
			token_gid: resp.take_token_gid(),
			identity_secret: base64::engine::general_purpose::STANDARD
				.encode(resp.take_identity_secret())
				.into(),
			device_id: self.device_id.clone(),
			secret_1: base64::engine::general_purpose::STANDARD
				.encode(resp.take_secret_1())
				.into(),
			tokens: Some(self.tokens.clone()),
		};
		Ok(account)
	}
}

#[derive(Debug)]
pub struct AccountLinkSuccess {
	account: SteamGuardAccount,
	server_time: u64,
	phone_number_hint: String,
	confirm_type: AccountLinkConfirmType,
}

impl AccountLinkSuccess {
	pub fn account(&self) -> &SteamGuardAccount {
		&self.account
	}

	pub fn into_account(self) -> SteamGuardAccount {
		self.account
	}

	pub fn server_time(&self) -> u64 {
		self.server_time
	}

	pub fn phone_number_hint(&self) -> &str {
		&self.phone_number_hint
	}

	pub fn confirm_type(&self) -> AccountLinkConfirmType {
		self.confirm_type
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AccountLinkConfirmType {
	SMS = 1,
	Email = 3,
	Unknown(i32),
}

impl From<i32> for AccountLinkConfirmType {
	fn from(i: i32) -> Self {
		match i {
			1 => AccountLinkConfirmType::SMS,
			3 => AccountLinkConfirmType::Email,
			_ => AccountLinkConfirmType::Unknown(i),
		}
	}
}

fn generate_device_id() -> String {
	format!("android:{}", uuid::Uuid::new_v4())
}

#[derive(Error, Debug)]
pub enum AccountLinkError {
	/// No phone number on the account
	#[error("A phone number is needed, but not already present on the account.")]
	MustProvidePhoneNumber,
	/// User need to click link from confirmation email
	#[error("An email has been sent to the user's email, click the link in that email.")]
	MustConfirmEmail,
	#[error("Authenticator is already present on this account.")]
	AuthenticatorPresent,
	#[error("You are sending too many requests to Steam, and we got rate limited. Wait at least a couple hours and try again.")]
	RateLimitExceeded,
	#[error("Steam was unable to link the authenticator to the account. No additional information about this error is available. This is a Steam error, not a steamguard-cli error. Try adding a phone number to your Steam account (which you can do here: https://store.steampowered.com/phone/add), or try again later.")]
	GenericFailure,
	#[error("Steam returned an unexpected error code: {0:?}")]
	UnknownEResult(EResult),
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

impl From<EResult> for AccountLinkError {
	fn from(result: EResult) -> Self {
		match result {
			EResult::RateLimitExceeded => AccountLinkError::RateLimitExceeded,
			EResult::NoVerifiedPhone => AccountLinkError::MustProvidePhoneNumber,
			EResult::DuplicateRequest => AccountLinkError::AuthenticatorPresent,
			// If the user has no phone number on their account, it will always return this status code.
			// However, this does not mean that this status just means "no phone number". It can also
			// be literally anything else, so that's why we return GenericFailure here.
			// update 2023: This may be no longer true, now it seems to return NoVerifiedPhone if there is no phone number. We'll see.
			EResult::Fail => AccountLinkError::GenericFailure,
			r => AccountLinkError::UnknownEResult(r),
		}
	}
}

#[derive(Error, Debug)]
pub enum FinalizeLinkError {
	#[error("Provided SMS code was incorrect.")]
	BadSmsCode,
	/// Steam wants more 2fa codes to verify that we can generate valid codes. Call finalize again.
	#[error("Steam wants more 2fa codes for verification.")]
	WantMore { server_time: u64 },
	#[error("Steam returned an unexpected error code: {0:?}")]
	UnknownEResult(EResult),
	#[error("Transport error: {0}")]
	TransportError(#[from] TransportError),
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

impl From<EResult> for FinalizeLinkError {
	fn from(result: EResult) -> Self {
		match result {
			EResult::TwoFactorActivationCodeMismatch => FinalizeLinkError::BadSmsCode,
			r => FinalizeLinkError::UnknownEResult(r),
		}
	}
}

#[derive(Debug, thiserror::Error)]
pub enum RemoveAuthenticatorError {
	#[error("Missing revocation code")]
	MissingRevocationCode,
	#[error("Incorrect revocation code, {attempts_remaining} attempts remaining")]
	IncorrectRevocationCode { attempts_remaining: u32 },
	#[error("Transport error: {0}")]
	TransportError(#[from] TransportError),
	#[error("Steam returned an enexpected result: {0:?}")]
	UnknownEResult(EResult),
	#[error("Unexpected error: {0}")]
	Unknown(#[from] anyhow::Error),
}

impl From<EResult> for RemoveAuthenticatorError {
	fn from(e: EResult) -> Self {
		Self::UnknownEResult(e)
	}
}

#[derive(Error, Debug)]
pub enum TransferError {
	#[error("Provided SMS code was incorrect.")]
	BadSmsCode,
	#[error("Failed to send request to Steam: {0:?}")]
	Transport(#[from] crate::transport::TransportError),
	#[error("Steam returned an unexpected error code: {0:?}")]
	UnknownEResult(EResult),
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

impl From<EResult> for TransferError {
	fn from(result: EResult) -> Self {
		match result {
			EResult::SMSCodeFailed => TransferError::BadSmsCode,
			r => TransferError::UnknownEResult(r),
		}
	}
}
