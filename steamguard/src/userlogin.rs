use crate::api_responses::AllowedConfirmation;
use crate::protobufs::custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData;
use crate::protobufs::enums::ESessionPersistence;
use crate::protobufs::steammessages_auth_steamclient::{
	CAuthentication_AllowedConfirmation, CAuthentication_DeviceDetails,
	CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response,
	EAuthSessionGuardType,
};
use crate::protobufs::steammessages_auth_steamclient::{
	CAuthentication_BeginAuthSessionViaCredentials_Response,
	CAuthentication_BeginAuthSessionViaQR_Request, CAuthentication_BeginAuthSessionViaQR_Response,
	CAuthentication_GetPasswordRSAPublicKey_Response,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, EAuthTokenPlatformType,
};
use crate::refresher::TokenRefresher;
use crate::steamapi::authentication::AuthenticationClient;
use crate::steamapi::EResult;
use crate::token::Tokens;
use crate::transport::{Transport, TransportError};
use anyhow::Context;
use base64::Engine;
use log::*;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::time::Duration;

#[derive(Debug)]
pub enum LoginError {
	BadCredentials,
	TooManyAttempts,
	UnknownEResult(EResult),
	AuthAlreadyStarted,
	TransportError(TransportError),
	NetworkFailure(reqwest::Error),
	OtherFailure(anyhow::Error),
}

impl std::fmt::Display for LoginError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for LoginError {}

impl From<TransportError> for LoginError {
	fn from(err: TransportError) -> Self {
		LoginError::TransportError(err)
	}
}

impl From<reqwest::Error> for LoginError {
	fn from(err: reqwest::Error) -> Self {
		LoginError::NetworkFailure(err)
	}
}

impl From<anyhow::Error> for LoginError {
	fn from(err: anyhow::Error) -> Self {
		LoginError::OtherFailure(err)
	}
}

impl From<EResult> for LoginError {
	fn from(err: EResult) -> Self {
		match err {
			EResult::InvalidPassword => LoginError::BadCredentials,
			EResult::RateLimitExceeded => LoginError::TooManyAttempts,
			err => LoginError::UnknownEResult(err),
		}
	}
}

#[derive(Debug, Clone)]
pub struct BeginQrLoginResponse {
	challenge_url: String,
	confirmation_methonds: Vec<AllowedConfirmation>,
}

impl BeginQrLoginResponse {
	pub fn challenge_url(&self) -> &String {
		&self.challenge_url
	}

	pub fn confirmation_methods(&self) -> &Vec<AllowedConfirmation> {
		&self.confirmation_methonds
	}
}

/// Handles the user login flow.
#[derive(Debug)]
pub struct UserLogin<T>
where
	T: Transport + Clone,
{
	client: AuthenticationClient<T>,
	device_details: DeviceDetails,

	started_auth: Option<StartAuth>,
}

impl<T> UserLogin<T>
where
	T: Transport + Clone,
{
	pub fn new(transport: T, device_details: DeviceDetails) -> Self {
		Self {
			client: AuthenticationClient::new(transport),
			device_details,
			started_auth: None,
		}
	}

	pub fn begin_auth_via_credentials(
		&mut self,
		account_name: &str,
		password: &str,
	) -> Result<Vec<AllowedConfirmation>, LoginError> {
		if self.started_auth.is_some() {
			return Err(LoginError::AuthAlreadyStarted);
		}
		trace!("UserLogin::begin_auth_via_credentials");

		let rsa = self.client.fetch_rsa_key(account_name.to_owned())?;

		let mut req = CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData::new();
		req.set_account_name(account_name.to_owned());
		let rsa_resp = rsa.into_response_data();
		req.set_encryption_timestamp(rsa_resp.timestamp());
		let encrypted_password = encrypt_password(rsa_resp, password);
		req.set_encrypted_password(encrypted_password);
		req.set_persistence(ESessionPersistence::k_ESessionPersistence_Persistent);
		req.device_details = self.device_details.clone().into_message_field();
		req.set_language(0); // english, probably
		req.set_qos_level(2); // value from observed traffic

		let resp = self.client.begin_auth_session_via_credentials(req)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		debug!("auth session started");
		self.started_auth = Some(resp.into_response_data().into());

		Ok(self
			.started_auth
			.as_ref()
			.unwrap()
			.allowed_confirmations()
			.iter()
			.map(|c| c.clone().into())
			.collect())
	}

	pub fn begin_auth_via_qr(&mut self) -> Result<BeginQrLoginResponse, LoginError> {
		if self.started_auth.is_some() {
			return Err(LoginError::AuthAlreadyStarted);
		}

		let mut req = CAuthentication_BeginAuthSessionViaQR_Request::new();
		req.set_platform_type(self.device_details.platform_type);
		req.set_device_friendly_name(self.device_details.friendly_name.clone());
		let resp = self.client.begin_auth_session_via_qr(req)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let data = resp.response_data();
		let return_resp = BeginQrLoginResponse {
			challenge_url: data.challenge_url().into(),
			confirmation_methonds: data
				.allowed_confirmations
				.iter()
				.map(|c| c.clone().into())
				.collect(),
		};

		debug!("auth session started");
		self.started_auth = Some(resp.into_response_data().into());

		Ok(return_resp)
	}

	fn poll_until_info(
		&mut self,
	) -> anyhow::Result<CAuthentication_PollAuthSessionStatus_Response> {
		let Some(started_auth) = self.started_auth.as_ref() else {
			return Err(anyhow::anyhow!("no auth session started"));
		};

		loop {
			let mut req = CAuthentication_PollAuthSessionStatus_Request::new();
			req.set_client_id(started_auth.client_id());
			req.set_request_id(started_auth.request_id().to_vec());

			let resp = self.client.poll_auth_session(req)?;
			if resp.result != EResult::OK {
				// EResult::FileNotFound is returned when the server couldn't find the auth session
				return Err(anyhow::anyhow!("poll failed: {:?}", resp.result));
			}

			let data = resp.response_data();
			let has_data = data.has_access_token()
				|| data.has_account_name()
				|| data.has_agreement_session_url()
				|| data.has_had_remote_interaction()
				|| data.has_new_challenge_url()
				|| data.has_new_client_id()
				|| data.has_new_guard_data()
				|| data.has_refresh_token();

			if has_data {
				return Ok(resp.into_response_data());
			}

			std::thread::sleep(Duration::from_secs_f32(started_auth.interval()));
		}
	}

	pub fn poll_until_tokens(&mut self) -> anyhow::Result<Tokens> {
		loop {
			let mut next_poll = self.poll_until_info()?;

			if next_poll.has_access_token() || next_poll.has_refresh_token() {
				// On 2023-09-12, Steam stopped issuing access tokens alongside refresh tokens for newly authenticated sessions.
				// If they decide to revert this change, we'll accept the access token if it's present.

				let access_token = next_poll.take_access_token();
				if access_token.is_empty() {
					// Let's go ahead an fetch the access token, because we are going to need it anyway.
					let mut refresher = TokenRefresher::new(self.client.clone());
					let mut tokens = Tokens::new(
						next_poll.take_access_token(),
						next_poll.take_refresh_token(),
					);
					let steamid = tokens
						.refresh_token()
						.decode()
						.context("decoding refresh token for steam id")?
						.steam_id();
					let access_token = refresher.refresh(steamid, &tokens)?;
					tokens.set_access_token(access_token);
					return Ok(tokens);
				} else {
					return Ok(Tokens::new(access_token, next_poll.take_refresh_token()));
				};
			}
		}
	}

	/// Submit a 2fa code generated from a device, or received in an email.
	pub fn submit_steam_guard_code(
		&mut self,
		guard_type: EAuthSessionGuardType,
		code: String,
	) -> Result<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, UpdateAuthSessionError>
	{
		let Some(started_auth) = self.started_auth.as_ref() else {
			return Err(UpdateAuthSessionError::SessionNotStarted);
		};

		if guard_type != EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
			&& guard_type != EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
		{
			return Err(UpdateAuthSessionError::InvalidGuardType);
		}

		let mut req = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::new();
		req.set_client_id(started_auth.client_id());
		req.set_code_type(guard_type);
		req.set_code(code);
		match started_auth {
			StartAuth::BeginAuthSessionViaCredentials(ref resp) => {
				req.set_steamid(resp.steamid());
			}
			StartAuth::BeginAuthSessionViaQR(_) => {
				return Err(anyhow::anyhow!("qr auth not supported").into());
			}
		}

		let resp = self.client.update_session_with_steam_guard_code(req)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		Ok(resp.into_response_data())
	}
}

fn encrypt_password(
	rsa_resp: CAuthentication_GetPasswordRSAPublicKey_Response,
	password: impl AsRef<[u8]>,
) -> String {
	let rsa_exponent = rsa::BigUint::parse_bytes(rsa_resp.publickey_exp().as_bytes(), 16).unwrap();
	let rsa_modulus = rsa::BigUint::parse_bytes(rsa_resp.publickey_mod().as_bytes(), 16).unwrap();
	let public_key = RsaPublicKey::new(rsa_modulus, rsa_exponent).unwrap();
	#[cfg(test)]
	let mut rng = tests::MockStepRng(rand::rngs::mock::StepRng::new(2, 1));
	#[cfg(not(test))]
	let mut rng = rand::rngs::OsRng;
	base64::engine::general_purpose::STANDARD.encode(
		public_key
			.encrypt(&mut rng, Pkcs1v15Encrypt, password.as_ref())
			.unwrap(),
	)
}

#[derive(Debug)]
enum StartAuth {
	BeginAuthSessionViaCredentials(CAuthentication_BeginAuthSessionViaCredentials_Response),
	BeginAuthSessionViaQR(CAuthentication_BeginAuthSessionViaQR_Response),
}

impl StartAuth {
	pub(crate) fn client_id(&self) -> u64 {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => resp.client_id(),
			StartAuth::BeginAuthSessionViaQR(resp) => resp.client_id(),
		}
	}

	pub(crate) fn request_id(&self) -> &[u8] {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => resp.request_id(),
			StartAuth::BeginAuthSessionViaQR(resp) => resp.request_id(),
		}
	}

	pub(crate) fn interval(&self) -> f32 {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => resp.interval(),
			StartAuth::BeginAuthSessionViaQR(resp) => resp.interval(),
		}
	}

	pub(crate) fn allowed_confirmations(&self) -> &Vec<CAuthentication_AllowedConfirmation> {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => &resp.allowed_confirmations,
			StartAuth::BeginAuthSessionViaQR(resp) => &resp.allowed_confirmations,
		}
	}
}

impl From<CAuthentication_BeginAuthSessionViaCredentials_Response> for StartAuth {
	fn from(resp: CAuthentication_BeginAuthSessionViaCredentials_Response) -> Self {
		Self::BeginAuthSessionViaCredentials(resp)
	}
}

impl From<CAuthentication_BeginAuthSessionViaQR_Response> for StartAuth {
	fn from(resp: CAuthentication_BeginAuthSessionViaQR_Response) -> Self {
		Self::BeginAuthSessionViaQR(resp)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDetails {
	/// The name to display for this device. You should make this unique, identifiable, and human readable. Used when managing account sessions.
	pub friendly_name: String,
	pub platform_type: EAuthTokenPlatformType,
	/// Corresponds to the EOSType enum.
	pub os_type: i32,
	/// Corresponds to the EGamingDeviceType enum.
	pub gaming_device_type: u32,
}

impl DeviceDetails {
	fn into_message_field(self) -> protobuf::MessageField<CAuthentication_DeviceDetails> {
		Some(self.into()).into()
	}
}

impl From<DeviceDetails> for CAuthentication_DeviceDetails {
	fn from(details: DeviceDetails) -> Self {
		let mut inner = CAuthentication_DeviceDetails::new();
		inner.set_device_friendly_name(details.friendly_name);
		inner.set_platform_type(details.platform_type);
		inner.set_os_type(details.os_type);
		inner.set_gaming_device_type(details.gaming_device_type);
		inner
	}
}

#[derive(Debug)]
pub enum UpdateAuthSessionError {
	SessionNotStarted,
	InvalidGuardType,
	TooManyAttempts,
	SessionExpired,
	IncorrectSteamGuardCode,
	UnknownEResult(EResult),
	TransportError(TransportError),
	NetworkFailure(reqwest::Error),
	OtherFailure(anyhow::Error),
}

impl std::fmt::Display for UpdateAuthSessionError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for UpdateAuthSessionError {}

impl From<EResult> for UpdateAuthSessionError {
	fn from(err: EResult) -> Self {
		match err {
			EResult::RateLimitExceeded => UpdateAuthSessionError::TooManyAttempts,
			EResult::Expired => UpdateAuthSessionError::SessionExpired,
			EResult::TwoFactorCodeMismatch => UpdateAuthSessionError::IncorrectSteamGuardCode,
			_ => UpdateAuthSessionError::UnknownEResult(err),
		}
	}
}

impl From<TransportError> for UpdateAuthSessionError {
	fn from(err: TransportError) -> Self {
		UpdateAuthSessionError::TransportError(err)
	}
}

impl From<reqwest::Error> for UpdateAuthSessionError {
	fn from(err: reqwest::Error) -> Self {
		UpdateAuthSessionError::NetworkFailure(err)
	}
}

impl From<anyhow::Error> for UpdateAuthSessionError {
	fn from(err: anyhow::Error) -> Self {
		UpdateAuthSessionError::OtherFailure(err)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	pub(crate) struct MockStepRng(pub rand::rngs::mock::StepRng);
	impl rand::RngCore for MockStepRng {
		fn next_u32(&mut self) -> u32 {
			self.0.next_u32()
		}

		fn next_u64(&mut self) -> u64 {
			self.0.next_u64()
		}

		fn fill_bytes(&mut self, dest: &mut [u8]) {
			self.0.fill_bytes(dest)
		}

		fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
			self.0.try_fill_bytes(dest)
		}
	}
	impl rand::CryptoRng for MockStepRng {}

	#[test]
	fn test_encrypt_password() {
		let mut rsa_resp = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		rsa_resp.set_publickey_exp(String::from("010001"));
		rsa_resp.set_publickey_mod(String::from("98f9088c1250b17fe19d2b2422d54a1eef0036875301731f11bd17900e215318eb6de1546727c0b7b61b86cefccdcb2f8108c813154d9a7d55631965eece810d4ab9d8a59c486bda778651b876176070598a93c2325c275cb9c17bdbcacf8edc9c18c0c5d59bc35703505ef8a09ed4c62b9f92a3fac5740ce25e490ab0e26d872140e4103d912d1e3958f844264211277ee08d2b4dd3ac58b030b25342bd5c949ae7794e46a8eab26d5a8deca683bfd381da6c305b19868b8c7cd321ce72c693310a6ebf2ecd43642518f825894602f6c239cf193cb4346ce64beac31e20ef88f934f2f776597734bb9eae1ebdf4a453973b6df9d5e90777bffe5db83dd1757b"));
		rsa_resp.set_timestamp(1);
		let result = encrypt_password(rsa_resp, "kelwleofpsm3n4ofc");
		assert_eq!(result.len(), 344);
		assert_eq!(result, "RUo/3IfbkVcJi1q1S5QlpKn1mEn3gNJoc/Z4VwxRV9DImV6veq/YISEuSrHB3885U5MYFLn1g94Y+cWRL6HGXoV+gOaVZe43m7O92RwiVz6OZQXMfAv3UC/jcqn/xkitnj+tNtmx55gCxmGbO2KbqQ0TQqAyqCOOw565B+Cwr2OOorpMZAViv9sKA/G3Q6yzscU6rhua179c8QjC1Hk3idUoSzpWfT4sHNBW/EREXZ3Dkjwu17xzpfwIUpnBVIlR8Vj3coHgUCpTsKVRA3T814v9BYPlvLYwmw5DW3ddx+2SyTY0P5uuog36TN2PqYS7ioF5eDe16gyfRR4Nzn/7wA==");
	}

	#[test]
	fn test_encrypt_password_2() {
		let mut rsa_resp = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		rsa_resp.set_publickey_exp(String::from("010001"));
		rsa_resp.set_publickey_mod(String::from("ca6a8dc290279b25c38a282b9a7b01306c5978bd7a2f60dcfd52134ac58faf121568ebd85ca6a2128413b76ec70fb3150b3181bbe2a1a8349b68da9c303960bdf4e34296b27bd4ea29b4d1a695168ddfc974bb6ba427206fdcdb088bf27261a52f343a51e19759fe4072b7a2047a6bc31361950d9e87d7977b31b71696572babe45ea6a7d132547984462fd5787607e0d9ff1c637e04d593e7538c880c3cdd252b75bcb703a7b8bb01cd8898b04980f40b76235d50fc1544c39ccbe763892322fc6d0a5acaf8be09efbc20fcfebcd3b02a1eb95d9d0c338e96674c17edbb0257cd43d04974423f1f995a28b9e159322d9db2708826804c0eccafffc94dd2a3d5"));
		rsa_resp.set_timestamp(104444850000);
		let result = encrypt_password(rsa_resp, "foo");
		assert_eq!(result, "jmlMXmhbweWn+wJnnf96W3Lsh0dRmzrBfMxREUuEW11rRYcfXWupBIT3eK1fmQHMZmyJeMhZiRpgIaZ7DafojQT6djJr+RKeREJs0ys9hKwxD5FGlqsTLXXEeuyopyd2smHBbmmF47voe59KEoiZZapP+eYnpJy3O2k7e1P9BH9LsKIN/nWF1ogM2jjJ328AejUpM64tPl/kInFJ1CHrLiAAKDPk42fLAAKs97xIi0JkosG6yp+8HhFqQxxZ8/bNI1IVkQC1Hdc2AN0QlNKxbDXquAn6ARgw/4b5DwUpnOb9de+Q6iX3v1/M07Se7JV8/4tuz8Thy2Chbxsf9E1TuQ==");
	}
}
