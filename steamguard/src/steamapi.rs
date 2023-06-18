mod authentication;

use crate::api_responses::*;
use log::*;
use reqwest::{
	blocking::RequestBuilder,
	cookie::CookieStore,
	header::COOKIE,
	header::{HeaderMap, HeaderName, HeaderValue, SET_COOKIE},
	Url,
};
use secrecy::{CloneableSecret, DebugSecret, ExposeSecret, SerializableSecret};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{convert::TryFrom, iter::FromIterator};
use zeroize::Zeroize;

lazy_static! {
	static ref STEAM_COOKIE_URL: Url = "https://steamcommunity.com".parse::<Url>().unwrap();
	static ref STEAM_API_BASE: String = "https://api.steampowered.com".into();
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Session {
	#[serde(rename = "SessionID")]
	pub session_id: String,
	#[serde(rename = "SteamLogin")]
	pub steam_login: String,
	#[serde(rename = "SteamLoginSecure")]
	pub steam_login_secure: String,
	#[serde(default, rename = "WebCookie")]
	pub web_cookie: Option<String>,
	#[serde(rename = "OAuthToken")]
	pub token: String,
	#[serde(rename = "SteamID")]
	pub steam_id: u64,
}

impl SerializableSecret for Session {}
impl CloneableSecret for Session {}
impl DebugSecret for Session {}

/// Queries Steam for the current time.
///
/// Endpoint: `/ITwoFactorService/QueryTime/v0001`
///
/// Example Response:
/// ```json
/// {
///   "response": {
///     "server_time": "1655768666",
///     "skew_tolerance_seconds": "60",
///     "large_time_jink": "86400",
///     "probe_frequency_seconds": 3600,
///     "adjusted_time_probe_frequency_seconds": 300,
///     "hint_probe_frequency_seconds": 60,
///     "sync_timeout": 60,
///     "try_again_seconds": 900,
///     "max_attempts": 3
///   }
/// }
/// ```
pub fn get_server_time() -> anyhow::Result<QueryTimeResponse> {
	let client = reqwest::blocking::Client::new();
	let resp = client
		.post("https://api.steampowered.com/ITwoFactorService/QueryTime/v0001")
		.body("steamid=0")
		.send()?;
	let resp: SteamApiResponse<QueryTimeResponse> = resp.json()?;

	return Ok(resp.response);
}

/// Provides raw access to the Steam API. Handles cookies, some deserialization, etc. to make it easier. It covers `ITwoFactorService` from the Steam web API, and some mobile app specific api endpoints.
#[derive(Debug)]
pub struct SteamApiClient {
	cookies: reqwest::cookie::Jar,
	client: reqwest::blocking::Client,
	pub session: Option<secrecy::Secret<Session>>,
}

impl SteamApiClient {
	pub fn new(session: Option<secrecy::Secret<Session>>) -> SteamApiClient {
		SteamApiClient {
			cookies: reqwest::cookie::Jar::default(),
			client: reqwest::blocking::ClientBuilder::new()
				.cookie_store(true)
				.user_agent("Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
				.default_headers(HeaderMap::from_iter(hashmap! {
					HeaderName::from_str("X-Requested-With").expect("could not build default request headers") => HeaderValue::from_str("com.valvesoftware.android.steam.community").expect("could not build default request headers")
				}.into_iter()))
				.build()
				.unwrap(),
			session: session,
		}
	}

	fn build_session(&self, data: &OAuthData) -> Session {
		trace!("SteamApiClient::build_session");
		return Session {
			token: data.oauth_token.clone(),
			steam_id: data.steamid.parse().unwrap(),
			steam_login: format!("{}%7C%7C{}", data.steamid, data.wgtoken),
			steam_login_secure: format!("{}%7C%7C{}", data.steamid, data.wgtoken_secure),
			session_id: self
				.extract_session_id()
				.expect("failed to extract session id from cookies"),
			web_cookie: Some(data.webcookie.clone()),
		};
	}

	fn extract_session_id(&self) -> Option<String> {
		let cookies = self.cookies.cookies(&STEAM_COOKIE_URL).unwrap();
		let all_cookies = cookies.to_str().unwrap();
		for cookie in all_cookies
			.split(";")
			.map(|s| cookie::Cookie::parse(s).unwrap())
		{
			if cookie.name() == "sessionid" {
				return Some(cookie.value().into());
			}
		}
		return None;
	}

	pub fn save_cookies_from_response(&mut self, response: &reqwest::blocking::Response) {
		let set_cookie_iter = response.headers().get_all(SET_COOKIE);

		for c in set_cookie_iter {
			c.to_str()
				.into_iter()
				.for_each(|cookie_str| self.cookies.add_cookie_str(cookie_str, &STEAM_COOKIE_URL));
		}
	}

	pub fn request<U: reqwest::IntoUrl + std::fmt::Display>(
		&self,
		method: reqwest::Method,
		url: U,
	) -> RequestBuilder {
		trace!("making request: {} {}", method, url);
		self.cookies
			.add_cookie_str("mobileClientVersion=0 (2.1.3)", &STEAM_COOKIE_URL);
		self.cookies
			.add_cookie_str("mobileClient=android", &STEAM_COOKIE_URL);
		self.cookies
			.add_cookie_str("Steam_Language=english", &STEAM_COOKIE_URL);
		if let Some(session) = &self.session {
			self.cookies.add_cookie_str(
				format!("sessionid={}", session.expose_secret().session_id).as_str(),
				&STEAM_COOKIE_URL,
			);
		}

		self.client
			.request(method, url)
			.header(COOKIE, self.cookies.cookies(&STEAM_COOKIE_URL).unwrap())
	}

	pub fn get<U: reqwest::IntoUrl + std::fmt::Display>(&self, url: U) -> RequestBuilder {
		self.request(reqwest::Method::GET, url)
	}

	pub fn post<U: reqwest::IntoUrl + std::fmt::Display>(&self, url: U) -> RequestBuilder {
		self.request(reqwest::Method::POST, url)
	}

	/// Updates the cookie jar with the session cookies by pinging steam servers.
	pub fn update_session(&mut self) -> anyhow::Result<()> {
		trace!("SteamApiClient::update_session");

		let resp = self
			.get("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client".parse::<Url>().unwrap())
			.send()?;
		self.save_cookies_from_response(&resp);
		trace!("{:?}", resp);

		trace!("cookies: {:?}", self.cookies);
		Ok(())
	}

	/// Endpoint: POST /login/dologin
	pub fn login(
		&mut self,
		username: String,
		encrypted_password: String,
		twofactor_code: String,
		email_code: String,
		captcha_gid: String,
		captcha_text: String,
		rsa_timestamp: String,
	) -> anyhow::Result<LoginResponse> {
		let params = hashmap! {
			"donotcache" => format!(
				"{}",
				SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_secs()
					* 1000
			),
			"username" => username,
			"password" => encrypted_password,
			"twofactorcode" => twofactor_code,
			"emailauth" => email_code,
			"captchagid" => captcha_gid,
			"captcha_text" => captcha_text,
			"rsatimestamp" => rsa_timestamp,
			"remember_login" => "true".into(),
			"oauth_client_id" => "DE45CD61".into(),
			"oauth_scope" => "read_profile write_profile read_client write_client".into(),
		};

		let resp = self
			.post("https://steamcommunity.com/login/dologin")
			.form(&params)
			.send()?;
		self.save_cookies_from_response(&resp);
		let text = resp.text()?;
		trace!("raw login response: {}", text);

		let login_resp: LoginResponse = serde_json::from_str(text.as_str())?;

		if let Some(oauth) = &login_resp.oauth {
			self.session = Some(secrecy::Secret::new(self.build_session(&oauth)));
		}

		return Ok(login_resp);
	}

	/// A secondary step in the login flow. Does not seem to always be needed?
	/// Endpoints: provided by `login()`
	pub fn transfer_login(&mut self, login_resp: LoginResponse) -> anyhow::Result<OAuthData> {
		match (login_resp.transfer_urls, login_resp.transfer_parameters) {
			(Some(urls), Some(params)) => {
				debug!("received transfer parameters, relaying data...");
				for url in urls {
					trace!("posting transfer to {}", url);
					let resp = self.client.post(url).json(&params).send()?;
					self.save_cookies_from_response(&resp);
				}

				let oauth = OAuthData {
					oauth_token: params.auth,
					steamid: params.steamid.parse().unwrap(),
					wgtoken: params.token_secure.clone(), // guessing
					wgtoken_secure: params.token_secure,
					webcookie: params.webcookie,
				};
				self.session = Some(secrecy::Secret::new(self.build_session(&oauth)));
				return Ok(oauth);
			}
			(None, None) => {
				bail!("did not receive transfer_urls and transfer_parameters");
			}
			(_, None) => {
				bail!("did not receive transfer_parameters");
			}
			(None, _) => {
				bail!("did not receive transfer_urls");
			}
		}
	}

	/// Likely removed now
	///
	/// One of the endpoints that handles phone number things. Can check to see if phone is present on account, and maybe do some other stuff. It's not really super clear.
	///
	/// Host: steamcommunity.com
	/// Endpoint: POST /steamguard/phoneajax
	/// Requires `sessionid` cookie to be set.
	fn phoneajax(&self, op: &str, arg: &str) -> anyhow::Result<bool> {
		let mut params = hashmap! {
			"op" => op,
			"arg" => arg,
			"sessionid" => self.session.as_ref().unwrap().expose_secret().session_id.as_str(),
		};
		if op == "check_sms_code" {
			params.insert("checkfortos", "0");
			params.insert("skipvoip", "1");
		}

		let resp = self
			.post("https://steamcommunity.com/steamguard/phoneajax")
			.form(&params)
			.send()?;

		trace!("phoneajax: status={}", resp.status());
		let result: Value = resp.json()?;
		trace!("phoneajax: {:?}", result);
		if result["has_phone"] != Value::Null {
			trace!("op: {} - found has_phone field", op);
			return result["has_phone"]
				.as_bool()
				.ok_or(anyhow!("failed to parse has_phone field into boolean"));
		} else if result["success"] != Value::Null {
			trace!("op: {} - found success field", op);
			return result["success"]
				.as_bool()
				.ok_or(anyhow!("failed to parse success field into boolean"));
		} else {
			trace!("op: {} - did not find any expected field", op);
			return Ok(false);
		}
	}

	/// Works similar to phoneajax. Used in the process to add a phone number to a steam account.
	/// Valid ops:
	/// - get_phone_number => `input` is treated as a phone number to add to the account. Yes, this is somewhat counter intuitive.
	/// - resend_sms
	/// - get_sms_code => `input` is treated as a the SMS code that was texted to the phone number. Again, this is somewhat counter intuitive. After this succeeds, the phone number is added to the account.
	/// - email_verification => If the account is protected with steam guard email, a verification link is sent. After the link in the email is clicked, send this op. After, an SMS code is sent to the phone number.
	/// - retry_email_verification
	///
	/// Host: store.steampowered.com
	/// Endpoint: /phone/add_ajaxop
	fn phone_add_ajaxop(&self, op: &str, input: &str) -> anyhow::Result<()> {
		trace!("phone_add_ajaxop: op={} input={}", op, input);
		let params = hashmap! {
			"op" => op,
			"input" => input,
			"sessionid" => self.session.as_ref().unwrap().expose_secret().session_id.as_str(),
		};

		let resp = self
			.post("https://store.steampowered.com/phone/add_ajaxop")
			.form(&params)
			.send()?;
		trace!("phone_add_ajaxop: http status={}", resp.status());
		let text = resp.text()?;
		trace!("phone_add_ajaxop response: {}", text);

		todo!();
	}

	pub fn has_phone(&self) -> anyhow::Result<bool> {
		return self.phoneajax("has_phone", "null");
	}

	pub fn check_sms_code(&self, sms_code: String) -> anyhow::Result<bool> {
		return self.phoneajax("check_sms_code", sms_code.as_str());
	}

	pub fn check_email_confirmation(&self) -> anyhow::Result<bool> {
		return self.phoneajax("email_confirmation", "");
	}

	pub fn add_phone_number(&self, phone_number: String) -> anyhow::Result<bool> {
		// return self.phoneajax("add_phone_number", phone_number.as_str());
		todo!();
	}

	/// Provides lots of juicy information, like if the number is a VOIP number.
	/// Host: store.steampowered.com
	/// Endpoint: POST /phone/validate
	/// Body format: form data
	/// Example:
	/// ```form
	/// sessionID=FOO&phoneNumber=%2B1+1234567890
	/// ```
	/// Found on page: https://store.steampowered.com/phone/add
	pub fn phone_validate(&self, phone_number: &String) -> anyhow::Result<PhoneValidateResponse> {
		let params = hashmap! {
			"sessionID" => self.session.as_ref().unwrap().expose_secret().session_id.as_str(),
			"phoneNumber" => phone_number.as_str(),
		};

		let resp = self
			.client
			.post("https://store.steampowered.com/phone/validate")
			.form(&params)
			.send()?
			.json::<PhoneValidateResponse>()?;

		return Ok(resp);
	}

	/// Starts the authenticator linking process.
	/// This doesn't check any prereqisites to ensure the request will pass validation on Steam's side (eg. sms/email confirmations).
	/// A valid `Session` is required for this request. Cookies are not needed for this request, but they are set anyway.
	///
	/// Host: api.steampowered.com
	/// Endpoint: POST /ITwoFactorService/AddAuthenticator/v0001
	pub fn add_authenticator(
		&mut self,
		device_id: String,
	) -> anyhow::Result<AddAuthenticatorResponse> {
		ensure!(matches!(self.session, Some(_)));
		let params = hashmap! {
			"access_token" => self.session.as_ref().unwrap().expose_secret().token.clone(),
			"steamid" => self.session.as_ref().unwrap().expose_secret().steam_id.to_string(),
			"authenticator_type" => "1".into(),
			"device_identifier" => device_id,
			"sms_phone_id" => "1".into(),
		};

		let resp = self
			.post(format!(
				"{}/ITwoFactorService/AddAuthenticator/v0001",
				STEAM_API_BASE.to_string()
			))
			.form(&params)
			.send()?;
		self.save_cookies_from_response(&resp);
		let text = resp.text()?;
		trace!("raw add authenticator response: {}", text);

		let resp: SteamApiResponse<AddAuthenticatorResponse> = serde_json::from_str(text.as_str())?;

		Ok(resp.response)
	}

	/// Host: api.steampowered.com
	/// Endpoint: POST /ITwoFactorService/FinalizeAddAuthenticator/v0001
	pub fn finalize_authenticator(
		&self,
		sms_code: String,
		code_2fa: String,
		time_2fa: u64,
	) -> anyhow::Result<FinalizeAddAuthenticatorResponse> {
		ensure!(matches!(self.session, Some(_)));
		let params = hashmap! {
			"steamid" => self.session.as_ref().unwrap().expose_secret().steam_id.to_string(),
			"access_token" => self.session.as_ref().unwrap().expose_secret().token.clone(),
			"activation_code" => sms_code,
			"authenticator_code" => code_2fa,
			"authenticator_time" => time_2fa.to_string(),
		};

		let resp = self
			.post(format!(
				"{}/ITwoFactorService/FinalizeAddAuthenticator/v0001",
				STEAM_API_BASE.to_string()
			))
			.form(&params)
			.send()?;

		let text = resp.text()?;
		trace!("raw finalize authenticator response: {}", text);

		let resp: SteamApiResponse<FinalizeAddAuthenticatorResponse> =
			serde_json::from_str(text.as_str())?;

		return Ok(resp.response);
	}

	/// Host: api.steampowered.com
	/// Endpoint: POST /ITwoFactorService/RemoveAuthenticator/v0001
	pub fn remove_authenticator(
		&self,
		revocation_code: String,
	) -> anyhow::Result<RemoveAuthenticatorResponse> {
		let params = hashmap! {
			"steamid" => self.session.as_ref().unwrap().expose_secret().steam_id.to_string(),
			"steamguard_scheme" => "2".into(),
			"revocation_code" => revocation_code,
			"access_token" => self.session.as_ref().unwrap().expose_secret().token.to_string(),
		};

		let resp = self
			.post(format!(
				"{}/ITwoFactorService/RemoveAuthenticator/v0001",
				STEAM_API_BASE.to_string()
			))
			.form(&params)
			.send()?;

		let text = resp.text()?;
		trace!("raw remove authenticator response: {}", text);

		let resp: SteamApiResponse<RemoveAuthenticatorResponse> =
			serde_json::from_str(text.as_str())?;

		return Ok(resp.response);
	}
}

pub trait BuildableRequest {
	fn method() -> reqwest::Method;

	fn build(&self, req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder;
}

#[derive(Debug, Clone)]
pub struct ApiRequest<T> {
	api_interface: String,
	api_method: String,
	api_version: u32,
	access_token: Option<String>,
	request_data: T,
}

impl<T: BuildableRequest> ApiRequest<T> {
	pub fn new(
		api_interface: impl Into<String>,
		api_method: impl Into<String>,
		api_version: u32,
		request_data: T,
	) -> Self {
		Self {
			api_interface: api_interface.into(),
			api_method: api_method.into(),
			api_version,
			access_token: None,
			request_data,
		}
	}

	pub fn with_access_token(mut self, access_token: String) -> Self {
		self.access_token = Some(access_token);
		self
	}

	pub(crate) fn build_url(&self) -> String {
		format!(
			"{}/I{}Service/{}/v{}",
			STEAM_API_BASE.to_string(),
			self.api_interface,
			self.api_method,
			self.api_version
		)
	}

	pub(crate) fn request_data(&self) -> &T {
		&self.request_data
	}
}

#[derive(Debug, Clone)]
pub struct ApiResponse<T> {
	result: EResult,
	error_message: Option<String>,
	response_data: T,
}

impl<T> ApiResponse<T> {
	pub fn result(&self) -> EResult {
		self.result
	}

	pub(crate) fn with_error_message(mut self, error_message: Option<String>) -> Self {
		self.error_message = error_message;
		self
	}

	pub fn error_message(&self) -> Option<&String> {
		self.error_message.as_ref()
	}

	pub fn response_data(&self) -> &T {
		&self.response_data
	}

	pub fn into_response_data(self) -> T {
		self.response_data
	}
}

// TODO: generate from protobufs
#[derive(Debug, Clone, Deserialize)]
pub enum EResult {
	Invalid = 0,
	OK = 1,
	Fail = 2,
	NoConnection = 3,
	InvalidPassword = 5,
	LoggedInElsewhere = 6,
	InvalidProtocolVer = 7,
	InvalidParam = 8,
	FileNotFound = 9,
	Busy = 10,
	InvalidState = 11,
	InvalidName = 12,
	InvalidEmail = 13,
	DuplicateName = 14,
	AccessDenied = 15,
	Timeout = 16,
	Banned = 17,
	AccountNotFound = 18,
	InvalidSteamID = 19,
	ServiceUnavailable = 20,
	NotLoggedOn = 21,
	Pending = 22,
	EncryptionFailure = 23,
	InsufficientPrivilege = 24,
	LimitExceeded = 25,
	Revoked = 26,
	Expired = 27,
	AlreadyRedeemed = 28,
	DuplicateRequest = 29,
	AlreadyOwned = 30,
	IPNotFound = 31,
	PersistFailed = 32,
	LockingFailed = 33,
	LogonSessionReplaced = 34,
	ConnectFailed = 35,
	HandshakeFailed = 36,
	IOFailure = 37,
	RemoteDisconnect = 38,
	ShoppingCartNotFound = 39,
	Blocked = 40,
	Ignored = 41,
	NoMatch = 42,
	AccountDisabled = 43,
	ServiceReadOnly = 44,
	AccountNotFeatured = 45,
	AdministratorOK = 46,
	ContentVersion = 47,
	TryAnotherCM = 48,
	PasswordRequiredToKickSession = 49,
	AlreadyLoggedInElsewhere = 50,
	Suspended = 51,
	Cancelled = 52,
	DataCorruption = 53,
	DiskFull = 54,
	RemoteCallFailed = 55,
	PasswordNotSetOrUnset = 56,
	ExternalAccountUnlinked = 57,
	PSNTicketInvalid = 58,
	ExternalAccountAlreadyLinked = 59,
	RemoteFileConflict = 60,
	IllegalPassword = 61,
	SameAsPreviousValue = 62,
	AccountLogonDenied = 63,
	CannotUseOldPassword = 64,
	InvalidLoginAuthCode = 65,
	AccountLogonDeniedNoMailSent = 66,
	HardwareNotCapableOfIPT = 67,
	IPTInitError = 68,
	ParentalControlRestricted = 69,
	FacebookQueryError = 70,
	ExpiredLoginAuthCode = 71,
	IPLoginRestrictionFailed = 72,
	AccountLocked = 73,
	AccountLogonDeniedVerifiedEmailRequired = 74,
	NoMatchingURL = 75,
	BadResponse = 76,
	RequirePasswordReEntry = 77,
	ValueOutOfRange = 78,
	UnexpectedError = 79,
	Disabled = 80,
	InvalidCEGSubmission = 81,
	RestrictedDevice = 82,
	RegionLocked = 83,
	RateLimitExceeded = 84,
	AccountLoginDeniedNeedTwoFactor = 85,
	ItemOrEntryHasBeenDeleted = 86,
	AccountLoginDeniedThrottle = 87,
	TwoFactorCodeMismatch = 88,
	TwoFactorActivationCodeMismatch = 89,
	AccountAssociatedToMultipleAccounts = 90,
	NotModified = 91,
	NoMobileDeviceAvailable = 92,
	TimeNotSynced = 93,
	SMSCodeFailed = 94,
	AccountLimitExceeded = 95,
	AccountActivityLimitExceeded = 96,
	PhoneActivityLimitExceeded = 97,
	RefundToWallet = 98,
	EmailSendFailure = 99,
	NotSettled = 100,
	NeedCaptcha = 101,
	GSLTDenied = 102,
	GSOwnerDenied = 103,
	InvalidItemType = 104,
	IPBanned = 105,
	GSLTExpired = 106,
	InsufficientFunds = 107,
	TooManyPending = 108,
	NoSiteLicensesFound = 109,
	WGNetworkSendExceeded = 110,
	AccountNotFriends = 111,
	LimitedUserAccount = 112,
	CantRemoveItem = 113,
	AccountDeleted = 114,
	ExistingUserCancelledLicense = 115,
	DeniedDueToCommunityCooldown = 116,
	NoLauncherSpecified = 117,
	MustAgreeToSSA = 118,
	ClientNoLongerSupported = 119,
	SteamRealmMismatch = 120,
	InvalidSignature = 121,
	ParseFailure = 122,
	NoVerifiedPhone = 123,
	InsufficientBattery = 124,
	ChargerRequired = 125,
	CachedCredentialInvalid = 126,
	PhoneNumberIsVOIP = 127,
}

impl From<i32> for EResult {
	fn from(value: i32) -> Self {
		match value {
			1 => EResult::OK,
			2 => EResult::Fail,
			3 => EResult::NoConnection,
			5 => EResult::InvalidPassword,
			6 => EResult::LoggedInElsewhere,
			7 => EResult::InvalidProtocolVer,
			8 => EResult::InvalidParam,
			9 => EResult::FileNotFound,
			10 => EResult::Busy,
			11 => EResult::InvalidState,
			12 => EResult::InvalidName,
			13 => EResult::InvalidEmail,
			14 => EResult::DuplicateName,
			15 => EResult::AccessDenied,
			16 => EResult::Timeout,
			17 => EResult::Banned,
			18 => EResult::AccountNotFound,
			19 => EResult::InvalidSteamID,
			20 => EResult::ServiceUnavailable,
			21 => EResult::NotLoggedOn,
			22 => EResult::Pending,
			23 => EResult::EncryptionFailure,
			24 => EResult::InsufficientPrivilege,
			25 => EResult::LimitExceeded,
			26 => EResult::Revoked,
			27 => EResult::Expired,
			28 => EResult::AlreadyRedeemed,
			29 => EResult::DuplicateRequest,
			30 => EResult::AlreadyOwned,
			31 => EResult::IPNotFound,
			32 => EResult::PersistFailed,
			33 => EResult::LockingFailed,
			34 => EResult::LogonSessionReplaced,
			35 => EResult::ConnectFailed,
			36 => EResult::HandshakeFailed,
			37 => EResult::IOFailure,
			38 => EResult::RemoteDisconnect,
			39 => EResult::ShoppingCartNotFound,
			40 => EResult::Blocked,
			41 => EResult::Ignored,
			42 => EResult::NoMatch,
			43 => EResult::AccountDisabled,
			44 => EResult::ServiceReadOnly,
			45 => EResult::AccountNotFeatured,
			46 => EResult::AdministratorOK,
			47 => EResult::ContentVersion,
			48 => EResult::TryAnotherCM,
			49 => EResult::PasswordRequiredToKickSession,
			50 => EResult::AlreadyLoggedInElsewhere,
			51 => EResult::Suspended,
			52 => EResult::Cancelled,
			53 => EResult::DataCorruption,
			54 => EResult::DiskFull,
			55 => EResult::RemoteCallFailed,
			56 => EResult::PasswordNotSetOrUnset,
			57 => EResult::ExternalAccountUnlinked,
			58 => EResult::PSNTicketInvalid,
			59 => EResult::ExternalAccountAlreadyLinked,
			60 => EResult::RemoteFileConflict,
			61 => EResult::IllegalPassword,
			62 => EResult::SameAsPreviousValue,
			63 => EResult::AccountLogonDenied,
			64 => EResult::CannotUseOldPassword,
			65 => EResult::InvalidLoginAuthCode,
			66 => EResult::AccountLogonDeniedNoMailSent,
			67 => EResult::HardwareNotCapableOfIPT,
			68 => EResult::IPTInitError,
			69 => EResult::ParentalControlRestricted,
			70 => EResult::FacebookQueryError,
			71 => EResult::ExpiredLoginAuthCode,
			72 => EResult::IPLoginRestrictionFailed,
			73 => EResult::AccountLocked,
			74 => EResult::AccountLogonDeniedVerifiedEmailRequired,
			75 => EResult::NoMatchingURL,
			76 => EResult::BadResponse,
			77 => EResult::RequirePasswordReEntry,
			78 => EResult::ValueOutOfRange,
			79 => EResult::UnexpectedError,
			80 => EResult::Disabled,
			81 => EResult::InvalidCEGSubmission,
			82 => EResult::RestrictedDevice,
			83 => EResult::RegionLocked,
			84 => EResult::RateLimitExceeded,
			85 => EResult::AccountLoginDeniedNeedTwoFactor,
			86 => EResult::ItemOrEntryHasBeenDeleted,
			87 => EResult::AccountLoginDeniedThrottle,
			88 => EResult::TwoFactorCodeMismatch,
			89 => EResult::TwoFactorActivationCodeMismatch,
			90 => EResult::AccountAssociatedToMultipleAccounts,
			91 => EResult::NotModified,
			92 => EResult::NoMobileDeviceAvailable,
			93 => EResult::TimeNotSynced,
			94 => EResult::SMSCodeFailed,
			95 => EResult::AccountLimitExceeded,
			96 => EResult::AccountActivityLimitExceeded,
			97 => EResult::PhoneActivityLimitExceeded,
			98 => EResult::RefundToWallet,
			99 => EResult::EmailSendFailure,
			100 => EResult::NotSettled,
			101 => EResult::NeedCaptcha,
			102 => EResult::GSLTDenied,
			103 => EResult::GSOwnerDenied,
			104 => EResult::InvalidItemType,
			105 => EResult::IPBanned,
			106 => EResult::GSLTExpired,
			107 => EResult::InsufficientFunds,
			108 => EResult::TooManyPending,
			109 => EResult::NoSiteLicensesFound,
			110 => EResult::WGNetworkSendExceeded,
			111 => EResult::AccountNotFriends,
			112 => EResult::LimitedUserAccount,
			113 => EResult::CantRemoveItem,
			114 => EResult::AccountDeleted,
			115 => EResult::ExistingUserCancelledLicense,
			116 => EResult::DeniedDueToCommunityCooldown,
			117 => EResult::NoLauncherSpecified,
			118 => EResult::MustAgreeToSSA,
			119 => EResult::ClientNoLongerSupported,
			120 => EResult::SteamRealmMismatch,
			121 => EResult::InvalidSignature,
			122 => EResult::ParseFailure,
			123 => EResult::NoVerifiedPhone,
			124 => EResult::InsufficientBattery,
			125 => EResult::ChargerRequired,
			126 => EResult::CachedCredentialInvalid,
			127 => EResult::PhoneNumberIsVOIP,
			_ => EResult::Invalid,
		}
	}
}
