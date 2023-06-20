use crate::api_responses::AllowedConfirmation;
use crate::protobufs::steammessages_auth_steamclient::{
	CAuthentication_AllowedConfirmation, CAuthentication_DeviceDetails,
	CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response,
	EAuthSessionGuardType,
};
use crate::steamapi::{ApiRequest, ApiResponse, EResult};
use crate::transport::Transport;
use crate::{
	api_responses::{LoginResponse, RsaResponse},
	protobufs::steammessages_auth_steamclient::{
		CAuthenticationSupport_RevokeToken_Request, CAuthenticationSupport_RevokeToken_Response,
		CAuthentication_AccessToken_GenerateForApp_Request,
		CAuthentication_AccessToken_GenerateForApp_Response,
		CAuthentication_BeginAuthSessionViaCredentials_Request,
		CAuthentication_BeginAuthSessionViaCredentials_Response,
		CAuthentication_BeginAuthSessionViaQR_Request,
		CAuthentication_BeginAuthSessionViaQR_Response,
		CAuthentication_GetPasswordRSAPublicKey_Request,
		CAuthentication_GetPasswordRSAPublicKey_Response,
		CAuthentication_MigrateMobileSession_Request,
		CAuthentication_MigrateMobileSession_Response, CAuthentication_RefreshToken_Revoke_Request,
		CAuthentication_RefreshToken_Revoke_Response,
		CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
		CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response,
		CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
		CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, EAuthTokenPlatformType,
	},
	steamapi::{Session, SteamApiClient},
	transport::WebApiTransport,
};
use log::*;
use rsa::{PublicKey, RsaPublicKey};
use secrecy::ExposeSecret;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum LoginError {
	BadCredentials,
	TooManyAttempts,
	UnknownEResult(EResult),
	AuthAlreadyStarted,
	NetworkFailure(reqwest::Error),
	OtherFailure(anyhow::Error),
}

impl std::fmt::Display for LoginError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for LoginError {}

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

/// Handles the user login flow.
#[derive(Debug)]
pub struct UserLogin {
	platform_type: EAuthTokenPlatformType,
	client: AuthenticationClient<WebApiTransport>,
	device_details: DeviceDetails,

	started_auth: Option<StartAuth>,
}

impl UserLogin {
	pub fn new(platform_type: EAuthTokenPlatformType, device_details: DeviceDetails) -> Self {
		return Self {
			platform_type,
			client: AuthenticationClient::new(WebApiTransport::new()),
			device_details,
			started_auth: None,
		};
	}

	pub fn begin_auth_via_credentials(
		&mut self,
		account_name: &String,
		password: &String,
	) -> anyhow::Result<Vec<AllowedConfirmation>, LoginError> {
		if self.started_auth.is_some() {
			return Err(LoginError::AuthAlreadyStarted);
		}
		trace!("UserLogin::begin_auth_via_credentials");

		let rsa = self.client.fetch_rsa_key(account_name.clone())?;

		let mut req = CAuthentication_BeginAuthSessionViaCredentials_Request::new();
		req.set_account_name(account_name.clone());
		let rsa_resp = rsa.into_response_data();
		req.set_encryption_timestamp(rsa_resp.timestamp());
		let encrypted_password = encrypt_password(rsa_resp, &password);
		req.set_encrypted_password(encrypted_password);
		req.set_persistence(
			crate::protobufs::enums::ESessionPersistence::k_ESessionPersistence_Persistent,
		);
		req.device_details = self.device_details.clone().into_message_field();
		req.set_language(0); // english, probably
		req.set_qos_level(2); // value from observed traffic

		let resp = self.client.begin_auth_session_via_credentials(req)?;

		match resp.result {
			EResult::OK => {}
			EResult::InvalidPassword => return Err(LoginError::BadCredentials),
			EResult::RateLimitExceeded => return Err(LoginError::TooManyAttempts),
			r => return Err(LoginError::UnknownEResult(r)),
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

	pub fn begin_auth_via_qr(&mut self) -> anyhow::Result<()> {
		if self.started_auth.is_some() {
			return Err(anyhow::anyhow!("already started auth"));
		}

		let mut req = CAuthentication_BeginAuthSessionViaQR_Request::new();
		req.set_platform_type(self.platform_type);
		let resp = self
			.client
			.begin_auth_session_via_qr(req)?
			.into_response_data();

		debug!("auth session started");
		self.started_auth = Some(resp.into());

		Ok(())
	}

	// pub fn fetch_new_access_token(&mut self) -> anyhow::Result<()> {
	// 	let Some(refresh_token) = self.refresh_token.as_ref() else {
	// 		return Err(anyhow::anyhow!("no refresh token"));
	// 	};

	// 	let mut req = CAuthentication_AccessToken_GenerateForApp_Request::new();
	// 	req.set_refresh_token(refresh_token.clone());

	// 	let mut resp = self.client.generate_access_token(req)?.into_response_data();
	// 	trace!("resp: {:?}", resp);
	// 	self.access_token = Some(resp.take_access_token());

	// 	Ok(())
	// }

	pub fn poll_until_info(
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

	pub fn submit_steam_guard_code(
		&mut self,
		guard_type: EAuthSessionGuardType,
		code: String,
	) -> anyhow::Result<()> {
		let Some(started_auth) = self.started_auth.as_ref() else {
			return Err(anyhow::anyhow!("no auth session started"));
		};

		ensure!(
			guard_type == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
				|| guard_type == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
			"invalid guard type"
		);

		let mut req = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::new();
		req.set_client_id(started_auth.client_id());
		req.set_code_type(guard_type);
		req.set_code(code);

		let resp = self.client.update_session_with_steam_guard_code(req)?;

		if resp.result != EResult::OK {
			return Err(anyhow::anyhow!("update failed: {:?}", resp.result));
		}

		Ok(())
	}

	pub fn login(&mut self) -> anyhow::Result<Session, LoginError> {
		todo!();
		trace!("UserLogin::login");
		// if self.captcha_required && self.captcha_text.len() == 0 {
		// 	return Err(LoginError::NeedCaptcha {
		// 		captcha_gid: self.captcha_gid.clone(),
		// 	});
		// }

		// if self.client.session.is_none() {
		// 	self.client.update_session()?;
		// }

		// let params = hashmap! {
		// 	"donotcache" => format!(
		// 		"{}",
		// 		SystemTime::now()
		// 			.duration_since(UNIX_EPOCH)
		// 			.unwrap()
		// 			.as_secs()
		// 			* 1000
		// 	),
		// 	"username" => self.username.clone(),
		// };
		// let resp = self
		// 	.client
		// 	.post("https://steamcommunity.com/login/getrsakey")
		// 	.form(&params)
		// 	.send()?;

		// let encrypted_password: String;
		// let rsa_timestamp: String;
		// match resp.json::<RsaResponse>() {
		// 	Ok(rsa_resp) => {
		// 		rsa_timestamp = rsa_resp.timestamp.clone();
		// 		encrypted_password = encrypt_password(rsa_resp, &self.password);
		// 	}
		// 	Err(error) => {
		// 		error!("rsa error: {:?}", error);
		// 		return Err(LoginError::BadRSA);
		// 	}
		// }

		// trace!("captchagid: {}", self.captcha_gid);
		// trace!("captcha_text: {}", self.captcha_text);
		// trace!("twofactorcode: {}", self.twofactor_code);
		// trace!("emailauth: {}", self.email_code);

		// let login_resp: LoginResponse = self.client.login(
		// 	self.username.clone(),
		// 	encrypted_password,
		// 	self.twofactor_code.clone(),
		// 	self.email_code.clone(),
		// 	self.captcha_gid.clone(),
		// 	self.captcha_text.clone(),
		// 	rsa_timestamp,
		// )?;

		// if login_resp.message.contains("too many login") {
		// 	return Err(LoginError::TooManyAttempts);
		// }

		// if login_resp.message.contains("Incorrect login") {
		// 	return Err(LoginError::BadCredentials);
		// }

		// if login_resp.captcha_needed {
		// 	self.captcha_gid = login_resp.captcha_gid.clone();
		// 	return Err(LoginError::NeedCaptcha {
		// 		captcha_gid: self.captcha_gid.clone(),
		// 	});
		// }

		// if login_resp.emailauth_needed {
		// 	self.steam_id = login_resp.emailsteamid.clone();
		// 	return Err(LoginError::NeedEmail);
		// }

		// if login_resp.requires_twofactor {
		// 	return Err(LoginError::Need2FA);
		// }

		// if !login_resp.login_complete {
		// 	return Err(LoginError::BadCredentials);
		// }

		// if login_resp.needs_transfer_login() {
		// 	self.client.transfer_login(login_resp)?;
		// }

		// return Ok(self
		// 	.client
		// 	.session
		// 	.as_ref()
		// 	.unwrap()
		// 	.expose_secret()
		// 	.to_owned());
	}
}

fn encrypt_password(
	rsa_resp: CAuthentication_GetPasswordRSAPublicKey_Response,
	password: &String,
) -> String {
	let rsa_exponent = rsa::BigUint::parse_bytes(rsa_resp.publickey_exp().as_bytes(), 16).unwrap();
	let rsa_modulus = rsa::BigUint::parse_bytes(rsa_resp.publickey_mod().as_bytes(), 16).unwrap();
	let public_key = RsaPublicKey::new(rsa_modulus, rsa_exponent).unwrap();
	#[cfg(test)]
	let mut rng = rand::rngs::mock::StepRng::new(2, 1);
	#[cfg(not(test))]
	let mut rng = rand::rngs::OsRng;
	let padding = rsa::PaddingScheme::new_pkcs1v15_encrypt();
	let encrypted_password = base64::encode(
		public_key
			.encrypt(&mut rng, padding, password.as_bytes())
			.unwrap(),
	);
	return encrypted_password;
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
pub(crate) struct AuthenticationClient<T>
where
	T: Transport,
{
	transport: T,
}

impl<T> AuthenticationClient<T>
where
	T: Transport,
{
	#[must_use]
	pub fn new(transport: T) -> Self {
		Self { transport }
	}

	pub fn begin_auth_session_via_credentials(
		&mut self,
		req: CAuthentication_BeginAuthSessionViaCredentials_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_BeginAuthSessionViaCredentials_Response>> {
		let req = ApiRequest::new(
			"Authentication",
			"BeginAuthSessionViaCredentials",
			1u32,
			req,
		);
		let resp = self.transport.send_request::<
			CAuthentication_BeginAuthSessionViaCredentials_Request,
			CAuthentication_BeginAuthSessionViaCredentials_Response>(req)?;
		Ok(resp)
	}

	pub fn begin_auth_session_via_qr(
		&mut self,
		req: CAuthentication_BeginAuthSessionViaQR_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_BeginAuthSessionViaQR_Response>> {
		let req = ApiRequest::new("Authentication", "BeginAuthSessionViaQR", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_BeginAuthSessionViaQR_Request, CAuthentication_BeginAuthSessionViaQR_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn generate_access_token(
		&mut self,
		req: CAuthentication_AccessToken_GenerateForApp_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_AccessToken_GenerateForApp_Response>> {
		let req = ApiRequest::new("Authentication", "GenerateAccessTokenForApp", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_AccessToken_GenerateForApp_Request, CAuthentication_AccessToken_GenerateForApp_Response>(
				req,
			)?;
		Ok(resp)
	}

	/// ```no_run
	/// let mut client =
	/// 		AuthenticationClient::new(crate::transport::webapi::WebApiTransport::new());
	/// let resp = client.fetch_rsa_key(String::from("hydrastar2"));
	/// ```
	pub fn fetch_rsa_key(
		&mut self,
		account_name: String,
	) -> anyhow::Result<ApiResponse<CAuthentication_GetPasswordRSAPublicKey_Response>> {
		let mut inner = CAuthentication_GetPasswordRSAPublicKey_Request::new();
		inner.set_account_name(account_name);
		let req = ApiRequest::new("Authentication", "GetPasswordRSAPublicKey", 1u32, inner);
		let resp = self
			.transport
			.send_request::<CAuthentication_GetPasswordRSAPublicKey_Request, CAuthentication_GetPasswordRSAPublicKey_Response>(
				req,
			)?;

		return Ok(resp);
	}

	pub fn migrate_mobile_session(
		&mut self,
		req: CAuthentication_MigrateMobileSession_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_MigrateMobileSession_Response>> {
		let req = ApiRequest::new("Authentication", "MigrateMobileSession", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_MigrateMobileSession_Request, CAuthentication_MigrateMobileSession_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn poll_auth_session(
		&mut self,
		req: CAuthentication_PollAuthSessionStatus_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_PollAuthSessionStatus_Response>> {
		let req = ApiRequest::new("Authentication", "PollAuthSessionStatus", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn revoke_refresh_token(
		&mut self,
		req: CAuthentication_RefreshToken_Revoke_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_RefreshToken_Revoke_Response>> {
		let req = ApiRequest::new("Authentication", "RevokeRefreshToken", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_RefreshToken_Revoke_Request, CAuthentication_RefreshToken_Revoke_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn revoke_access_token(
		&mut self,
		req: CAuthenticationSupport_RevokeToken_Request,
	) -> anyhow::Result<ApiResponse<CAuthenticationSupport_RevokeToken_Response>> {
		let req = ApiRequest::new("Authentication", "RevokeToken", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthenticationSupport_RevokeToken_Request, CAuthenticationSupport_RevokeToken_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn update_session_with_mobile_confirmation(
		&mut self,
		req: CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response>>
	{
		let req = ApiRequest::new(
			"Authentication",
			"UpdateAuthSessionWithMobileConfirmation",
			1u32,
			req,
		);
		let resp = self
			.transport
			.send_request::<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request, CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn update_session_with_steam_guard_code(
		&mut self,
		req: CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response>> {
		let req = ApiRequest::new(
			"Authentication",
			"UpdateAuthSessionWithSteamGuardCode",
			1u32,
			req,
		);
		let resp = self
			.transport
			.send_request::<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request, CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response>(
				req,
			)?;
		Ok(resp)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_encrypt_password() {
		let mut rsa_resp = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		rsa_resp.set_publickey_exp(String::from("010001"));
		rsa_resp.set_publickey_mod(String::from("98f9088c1250b17fe19d2b2422d54a1eef0036875301731f11bd17900e215318eb6de1546727c0b7b61b86cefccdcb2f8108c813154d9a7d55631965eece810d4ab9d8a59c486bda778651b876176070598a93c2325c275cb9c17bdbcacf8edc9c18c0c5d59bc35703505ef8a09ed4c62b9f92a3fac5740ce25e490ab0e26d872140e4103d912d1e3958f844264211277ee08d2b4dd3ac58b030b25342bd5c949ae7794e46a8eab26d5a8deca683bfd381da6c305b19868b8c7cd321ce72c693310a6ebf2ecd43642518f825894602f6c239cf193cb4346ce64beac31e20ef88f934f2f776597734bb9eae1ebdf4a453973b6df9d5e90777bffe5db83dd1757b"));
		rsa_resp.set_timestamp(1);
		let result = encrypt_password(rsa_resp, &String::from("kelwleofpsm3n4ofc"));
		assert_eq!(result.len(), 344);
		assert_eq!(result, "RUo/3IfbkVcJi1q1S5QlpKn1mEn3gNJoc/Z4VwxRV9DImV6veq/YISEuSrHB3885U5MYFLn1g94Y+cWRL6HGXoV+gOaVZe43m7O92RwiVz6OZQXMfAv3UC/jcqn/xkitnj+tNtmx55gCxmGbO2KbqQ0TQqAyqCOOw565B+Cwr2OOorpMZAViv9sKA/G3Q6yzscU6rhua179c8QjC1Hk3idUoSzpWfT4sHNBW/EREXZ3Dkjwu17xzpfwIUpnBVIlR8Vj3coHgUCpTsKVRA3T814v9BYPlvLYwmw5DW3ddx+2SyTY0P5uuog36TN2PqYS7ioF5eDe16gyfRR4Nzn/7wA==");
	}

	#[test]
	fn test_encrypt_password_2() {
		let mut rsa_resp = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		rsa_resp.set_publickey_exp(String::from("010001"));
		rsa_resp.set_publickey_mod(String::from("ca6a8dc290279b25c38a282b9a7b01306c5978bd7a2f60dcfd52134ac58faf121568ebd85ca6a2128413b76ec70fb3150b3181bbe2a1a8349b68da9c303960bdf4e34296b27bd4ea29b4d1a695168ddfc974bb6ba427206fdcdb088bf27261a52f343a51e19759fe4072b7a2047a6bc31361950d9e87d7977b31b71696572babe45ea6a7d132547984462fd5787607e0d9ff1c637e04d593e7538c880c3cdd252b75bcb703a7b8bb01cd8898b04980f40b76235d50fc1544c39ccbe763892322fc6d0a5acaf8be09efbc20fcfebcd3b02a1eb95d9d0c338e96674c17edbb0257cd43d04974423f1f995a28b9e159322d9db2708826804c0eccafffc94dd2a3d5"));
		rsa_resp.set_timestamp(104444850000);
		let result = encrypt_password(rsa_resp, &String::from("foo"));
		assert_eq!(result, "jmlMXmhbweWn+wJnnf96W3Lsh0dRmzrBfMxREUuEW11rRYcfXWupBIT3eK1fmQHMZmyJeMhZiRpgIaZ7DafojQT6djJr+RKeREJs0ys9hKwxD5FGlqsTLXXEeuyopyd2smHBbmmF47voe59KEoiZZapP+eYnpJy3O2k7e1P9BH9LsKIN/nWF1ogM2jjJ328AejUpM64tPl/kInFJ1CHrLiAAKDPk42fLAAKs97xIi0JkosG6yp+8HhFqQxxZ8/bNI1IVkQC1Hdc2AN0QlNKxbDXquAn6ARgw/4b5DwUpnOb9de+Q6iX3v1/M07Se7JV8/4tuz8Thy2Chbxsf9E1TuQ==");
	}
}
