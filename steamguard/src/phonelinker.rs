use crate::protobufs::service_phone::*;
use crate::transport::{Transport, TransportError};
use crate::{
	steamapi::{EResult, PhoneClient},
	token::Tokens,
};

pub use phonenumber::PhoneNumber;

pub struct PhoneLinker<T>
where
	T: Transport,
{
	client: PhoneClient<T>,
	tokens: Tokens,
}

impl<T> PhoneLinker<T>
where
	T: Transport,
{
	pub fn new(client: PhoneClient<T>, tokens: Tokens) -> Self {
		Self { client, tokens }
	}

	/// If successful, wait for the user to click the link in the email, then immediately call [`Self::send_phone_verification_code`].
	pub fn set_account_phone_number(
		&self,
		phone_number: PhoneNumber,
	) -> Result<SetAccountPhoneNumberResponse, SetPhoneNumberError> {
		// This results in an email being sent to the account's email address with a link to click on to confirm the phone number.
		// This endpoint also does almost no validation of the phone number. It only validates it after the user clicks the link.

		// `phone_number` needs to include the country code in the format `11234567890`

		let mut req = CPhone_SetAccountPhoneNumber_Request::new();
		req.set_phone_number(
			phone_number
				.format()
				.mode(phonenumber::Mode::E164)
				.to_string(),
		);
		req.set_phone_country_code(phone_number.code().value().to_string());

		let resp = self
			.client
			.set_account_phone_number(req, self.tokens.access_token())?;

		if resp.result != EResult::Pending {
			return Err(SetPhoneNumberError::UnknownEResult(resp.result));
		}

		let resp = resp.into_response_data();
		Ok(resp.into())
	}

	// confirm_add_phone_to_account is actually not needed, because it's performed by the user clicking the link in the email.

	/// language 0 is english
	pub fn send_phone_verification_code(&self, language: u32) -> anyhow::Result<()> {
		let mut req = CPhone_SendPhoneVerificationCode_Request::new();
		req.set_language(language);

		let resp = self
			.client
			.send_phone_verification_code(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(anyhow::anyhow!(
				"Failed to send phone verification code: {:?}",
				resp.result
			));
		}

		Ok(())
	}

	pub fn verify_account_phone_with_code(
		&self,
		code: String,
	) -> anyhow::Result<(), VerifyPhoneError> {
		let mut req = CPhone_VerifyAccountPhoneWithCode_Request::new();
		req.set_code(code);

		let resp = self
			.client
			.verify_account_phone_with_code(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		Ok(())
	}

	/// If true, returns `Some` with the value inside being the time in seconds until the email expires.
	pub fn is_account_waiting_for_email_confirmation(&self) -> anyhow::Result<Option<u32>> {
		let req = CPhone_IsAccountWaitingForEmailConfirmation_Request::new();

		let resp = self
			.client
			.is_account_waiting_for_email_confirmation(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(anyhow::anyhow!(
				"Failed to check if account is waiting for email confirmation: {:?}",
				resp.result
			));
		}

		let resp = resp.into_response_data();
		if !resp.awaiting_email_confirmation() {
			return Ok(None);
		}

		Ok(resp.seconds_to_wait)
	}
}

#[derive(Debug, thiserror::Error)]
pub enum SetPhoneNumberError {
	#[error("Transport error: {0}")]
	TransportError(#[from] TransportError),
	#[error("Steam says: {0:?}")]
	UnknownEResult(EResult),
}

impl From<EResult> for SetPhoneNumberError {
	fn from(result: EResult) -> Self {
		SetPhoneNumberError::UnknownEResult(result)
	}
}

#[derive(Debug)]
pub struct SetAccountPhoneNumberResponse {
	confirmation_email_address: String,
	phone_number_formatted: String,
}

impl SetAccountPhoneNumberResponse {
	pub fn confirmation_email_address(&self) -> &str {
		&self.confirmation_email_address
	}

	pub fn phone_number_formatted(&self) -> &str {
		&self.phone_number_formatted
	}
}

impl From<CPhone_SetAccountPhoneNumber_Response> for SetAccountPhoneNumberResponse {
	fn from(mut resp: CPhone_SetAccountPhoneNumber_Response) -> Self {
		Self {
			confirmation_email_address: resp.take_confirmation_email_address(),
			phone_number_formatted: resp.take_phone_number_formatted(),
		}
	}
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyPhoneError {
	#[error("Transport error: {0}")]
	TransportError(#[from] TransportError),
	#[error("Steam says: {0:?}")]
	UnknownEResult(EResult),
}

impl From<EResult> for VerifyPhoneError {
	fn from(result: EResult) -> Self {
		VerifyPhoneError::UnknownEResult(result)
	}
}
