use crate::protobufs::service_phone::*;
use crate::transport::TransportError;
use crate::{
	steamapi::{EResult, PhoneClient},
	token::Tokens,
	transport::WebApiTransport,
};

pub struct PhoneLinker {
	client: PhoneClient<WebApiTransport>,
	tokens: Tokens,
}

impl PhoneLinker {
	pub fn new(client: PhoneClient<WebApiTransport>, tokens: Tokens) -> Self {
		Self { client, tokens }
	}

	pub fn set_account_phone_number(
		&self,
		phone_number: String,
		phone_country_code: String,
	) -> Result<SetAccountPhoneNumberResponse, SetPhoneNumberError> {
		// This results in an email being sent to the account's email address with a link to click on to confirm the phone number.
		// This endpoint also does almost no validation of the phone number. It only validates it after the user clicks the link.

		// `phone_number` needs to include the country code

		let mut req = CPhone_SetAccountPhoneNumber_Request::new();
		req.set_phone_number(phone_number);
		req.set_phone_country_code(phone_country_code);

		let resp = self
			.client
			.set_account_phone_number(req, self.tokens.access_token())?;

		if resp.result != EResult::Pending {
			return Err(SetPhoneNumberError::UnknownEResult(resp.result));
		}

		let resp = resp.into_response_data();
		Ok(resp.into())
	}

	pub fn confirm_add_phone_to_account(
		&self,
		steam_id: u64,
		stoken: String,
	) -> anyhow::Result<(), ConfirmPhoneNumberError> {
		// this step is actually not needed, because it's performed by the user clicking the link in the email.
		let mut req = CPhone_ConfirmAddPhoneToAccount_Request::new();
		req.set_steamid(steam_id);
		req.set_stoken(stoken);

		let resp = self
			.client
			.confirm_add_phone_to_account(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let resp = resp.into_response_data();

		if !resp.success() {
			return Err(ConfirmPhoneNumberError::Failed);
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
pub enum ConfirmPhoneNumberError {
	#[error("Failed to confirm phone number")]
	Failed,
	#[error("Transport error: {0}")]
	TransportError(#[from] TransportError),
	#[error("Steam says: {0:?}")]
	UnknownEResult(EResult),
}

impl From<EResult> for ConfirmPhoneNumberError {
	fn from(result: EResult) -> Self {
		ConfirmPhoneNumberError::UnknownEResult(result)
	}
}
