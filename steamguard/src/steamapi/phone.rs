use crate::{
	protobufs::service_phone::*,
	token::Jwt,
	transport::{Transport, TransportError},
};

const SERVICE_NAME: &str = "IPhoneService";

use super::{ApiRequest, ApiResponse, BuildableRequest};

/// A client for the IPhoneService API.
#[derive(Debug)]
pub struct PhoneClient<T>
where
	T: Transport,
{
	transport: T,
}

impl<T> PhoneClient<T>
where
	T: Transport,
{
	#[must_use]
	pub fn new(transport: T) -> Self {
		Self { transport }
	}

	pub fn set_account_phone_number(
		&self,
		req: CPhone_SetAccountPhoneNumber_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CPhone_SetAccountPhoneNumber_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "SetAccountPhoneNumber", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CPhone_SetAccountPhoneNumber_Request, CPhone_SetAccountPhoneNumber_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn send_phone_verification_code(
		&self,
		req: CPhone_SendPhoneVerificationCode_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CPhone_SendPhoneVerificationCode_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "SendPhoneVerificationCode", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CPhone_SendPhoneVerificationCode_Request, CPhone_SendPhoneVerificationCode_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn is_account_waiting_for_email_confirmation(
		&self,
		req: CPhone_IsAccountWaitingForEmailConfirmation_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CPhone_IsAccountWaitingForEmailConfirmation_Response>, TransportError>
	{
		let req = ApiRequest::new(
			SERVICE_NAME,
			"IsAccountWaitingForEmailConfirmation",
			1u32,
			req,
		)
		.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CPhone_IsAccountWaitingForEmailConfirmation_Request, CPhone_IsAccountWaitingForEmailConfirmation_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn confirm_add_phone_to_account(
		&self,
		req: CPhone_ConfirmAddPhoneToAccount_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CPhone_AddPhoneToAccount_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "ConfirmAddPhoneToAccount", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CPhone_ConfirmAddPhoneToAccount_Request, CPhone_AddPhoneToAccount_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn verify_account_phone_with_code(
		&self,
		req: CPhone_VerifyAccountPhoneWithCode_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CPhone_VerifyAccountPhoneWithCode_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "VerifyAccountPhoneWithCode", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CPhone_VerifyAccountPhoneWithCode_Request, CPhone_VerifyAccountPhoneWithCode_Response>(
				req,
			)?;
		Ok(resp)
	}

	/// Reverse engineered from steam mobile app.
	pub fn account_phone_status(
		&self,
		req: CPhone_AccountPhoneStatus_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CPhone_AccountPhoneStatus_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "AccountPhoneStatus", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CPhone_AccountPhoneStatus_Request, CPhone_AccountPhoneStatus_Response>(
				req,
			)?;
		Ok(resp)
	}
}

macro_rules! impl_buildable_req {
	($type:ty, $needs_auth:literal) => {
		impl BuildableRequest for $type {
			fn method() -> reqwest::Method {
				reqwest::Method::POST
			}

			fn requires_access_token() -> bool {
				$needs_auth
			}
		}
	};
}

impl_buildable_req!(CPhone_SetAccountPhoneNumber_Request, true);
impl_buildable_req!(CPhone_SendPhoneVerificationCode_Request, true);
impl_buildable_req!(CPhone_IsAccountWaitingForEmailConfirmation_Request, true);
impl_buildable_req!(CPhone_ConfirmAddPhoneToAccount_Request, true);
impl_buildable_req!(CPhone_VerifyAccountPhoneWithCode_Request, true);
impl_buildable_req!(CPhone_AccountPhoneStatus_Request, true);
