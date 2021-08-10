use log::*;
use reqwest::{
	blocking::RequestBuilder,
	cookie::CookieStore,
	header::COOKIE,
	header::{HeaderMap, HeaderName, HeaderValue, SET_COOKIE},
	Url,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::iter::FromIterator;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::SteamGuardAccount;

lazy_static! {
	static ref STEAM_COOKIE_URL: Url = "https://steamcommunity.com".parse::<Url>().unwrap();
	static ref STEAM_API_BASE: String = "https://api.steampowered.com".into();
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
	pub success: bool,
	#[serde(default)]
	pub login_complete: bool,
	#[serde(default)]
	pub captcha_needed: bool,
	#[serde(default)]
	pub captcha_gid: String,
	#[serde(default)]
	pub emailsteamid: u64,
	#[serde(default)]
	pub emailauth_needed: bool,
	#[serde(default)]
	pub requires_twofactor: bool,
	#[serde(default)]
	pub message: String,
	// #[serde(rename = "oauth")]
	// oauth_raw: String,
	#[serde(default, deserialize_with = "oauth_data_from_string")]
	oauth: Option<OAuthData>,
	transfer_urls: Option<Vec<String>>,
	transfer_parameters: Option<LoginTransferParameters>,
}

/// For some reason, the `oauth` field in the login response is a string of JSON, not a JSON object.
/// Deserializes to `Option` because the `oauth` field is not always there.
fn oauth_data_from_string<'de, D>(deserializer: D) -> Result<Option<OAuthData>, D::Error>
where
	D: Deserializer<'de>,
{
	// for some reason, deserializing to &str doesn't work but this does.
	let s: String = Deserialize::deserialize(deserializer)?;
	let data: OAuthData = serde_json::from_str(s.as_str()).map_err(serde::de::Error::custom)?;
	Ok(Some(data))
}

impl LoginResponse {
	pub fn needs_transfer_login(&self) -> bool {
		self.transfer_urls.is_some() || self.transfer_parameters.is_some()
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginTransferParameters {
	steamid: String,
	token_secure: String,
	auth: String,
	remember_login: bool,
	webcookie: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RsaResponse {
	pub success: bool,
	pub publickey_exp: String,
	pub publickey_mod: String,
	pub timestamp: String,
	pub token_gid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthData {
	oauth_token: String,
	steamid: String,
	wgtoken: String,
	wgtoken_secure: String,
	#[serde(default)]
	webcookie: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
	#[serde(rename = "SessionID")]
	pub session_id: String,
	#[serde(rename = "SteamLogin")]
	pub steam_login: String,
	#[serde(rename = "SteamLoginSecure")]
	pub steam_login_secure: String,
	#[serde(default, rename = "WebCookie")]
	pub web_cookie: String,
	#[serde(rename = "OAuthToken")]
	pub token: String,
	#[serde(rename = "SteamID")]
	pub steam_id: u64,
}

pub fn get_server_time() -> i64 {
	let client = reqwest::blocking::Client::new();
	let resp = client
		.post("https://api.steampowered.com/ITwoFactorService/QueryTime/v0001")
		.body("steamid=0")
		.send();
	let value: serde_json::Value = resp.unwrap().json().unwrap();

	return String::from(value["response"]["server_time"].as_str().unwrap())
		.parse()
		.unwrap();
}

/// Provides raw access to the Steam API. Handles cookies, some deserialization, etc. to make it easier. It covers `ITwoFactorService` from the Steam web API, and some mobile app specific api endpoints.
#[derive(Debug)]
pub struct SteamApiClient {
	cookies: reqwest::cookie::Jar,
	client: reqwest::blocking::Client,
	pub session: Option<Session>,
}

impl SteamApiClient {
	pub fn new(session: Option<Session>) -> SteamApiClient {
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
			web_cookie: data.webcookie.clone(),
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
				format!("sessionid={}", session.session_id).as_str(),
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
			self.session = Some(self.build_session(&oauth));
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
				self.session = Some(self.build_session(&oauth));
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

	/// One of the endpoints that handles phone number things. Can check to see if phone is present on account, and maybe do some other stuff. It's not really super clear.
	///
	/// Host: steamcommunity.com
	/// Endpoint: POST /steamguard/phoneajax
	/// Requires `sessionid` cookie to be set.
	fn phoneajax(&self, op: &str, arg: &str) -> anyhow::Result<bool> {
		let mut params = hashmap! {
			"op" => op,
			"arg" => arg,
			"sessionid" => self.session.as_ref().unwrap().session_id.as_str(),
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
	/// Found on page: https://store.steampowered.com/phone/add
	pub fn phone_validate(&self, phone_number: String) -> anyhow::Result<bool> {
		let params = hashmap! {
			"sessionID" => "",
			"phoneNumber" => "",
		};

		todo!();
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
			"access_token" => self.session.as_ref().unwrap().token.clone(),
			"steamid" => self.session.as_ref().unwrap().steam_id.to_string(),
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

	///
	/// Host: api.steampowered.com
	/// Endpoint: POST /ITwoFactorService/FinalizeAddAuthenticator/v0001
	pub fn finalize_authenticator(
		&self,
		sms_code: String,
		code_2fa: String,
		time_2fa: i64,
	) -> anyhow::Result<FinalizeAddAuthenticatorResponse> {
		ensure!(matches!(self.session, Some(_)));
		let params = hashmap! {
			"steamid" => self.session.as_ref().unwrap().steam_id.to_string(),
			"access_token" => self.session.as_ref().unwrap().token.clone(),
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
			"steamid" => self.session.as_ref().unwrap().steam_id.to_string(),
			"steamguard_scheme" => "2".into(),
			"revocation_code" => revocation_code,
			"access_token" => self.session.as_ref().unwrap().token.to_string(),
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

#[test]
fn test_oauth_data_parse() {
	// This example is from a login response that did not contain any transfer URLs.
	let oauth: OAuthData = serde_json::from_str("{\"steamid\":\"78562647129469312\",\"account_name\":\"feuarus\",\"oauth_token\":\"fd2fdb3d0717bcd2220d98c7ec61c7bd\",\"wgtoken\":\"72E7013D598A4F68C7E268F6FA3767D89D763732\",\"wgtoken_secure\":\"21061EA13C36D7C29812CAED900A215171AD13A2\",\"webcookie\":\"6298070A226E5DAD49938D78BCF36F7A7118FDD5\"}").unwrap();

	assert_eq!(oauth.steamid, "78562647129469312");
	assert_eq!(oauth.oauth_token, "fd2fdb3d0717bcd2220d98c7ec61c7bd");
	assert_eq!(oauth.wgtoken, "72E7013D598A4F68C7E268F6FA3767D89D763732");
	assert_eq!(
		oauth.wgtoken_secure,
		"21061EA13C36D7C29812CAED900A215171AD13A2"
	);
	assert_eq!(oauth.webcookie, "6298070A226E5DAD49938D78BCF36F7A7118FDD5");
}

#[test]
fn test_login_response_parse() {
	let result = serde_json::from_str::<LoginResponse>(include_str!(
		"fixtures/api-responses/login-response1.json"
	));

	assert!(
		matches!(result, Ok(_)),
		"got error: {}",
		result.unwrap_err()
	);
	let resp = result.unwrap();

	let oauth = resp.oauth.unwrap();
	assert_eq!(oauth.steamid, "78562647129469312");
	assert_eq!(oauth.oauth_token, "fd2fdb3d0717bad2220d98c7ec61c7bd");
	assert_eq!(oauth.wgtoken, "72E7013D598A4F68C7E268F6FA3767D89D763732");
	assert_eq!(
		oauth.wgtoken_secure,
		"21061EA13C36D7C29812CAED900A215171AD13A2"
	);
	assert_eq!(oauth.webcookie, "6298070A226E5DAD49938D78BCF36F7A7118FDD5");
}

#[test]
fn test_login_response_parse_missing_webcookie() {
	let result = serde_json::from_str::<LoginResponse>(include_str!(
		"fixtures/api-responses/login-response-missing-webcookie.json"
	));

	assert!(
		matches!(result, Ok(_)),
		"got error: {}",
		result.unwrap_err()
	);
	let resp = result.unwrap();

	let oauth = resp.oauth.unwrap();
	assert_eq!(oauth.steamid, "92591609556178617");
	assert_eq!(oauth.oauth_token, "1cc83205dab2979e558534dab29f6f3aa");
	assert_eq!(oauth.wgtoken, "3EDA9DEF07D7B39361D95203525D8AFE82A");
	assert_eq!(oauth.wgtoken_secure, "F31641B9AFC2F8B0EE7B6F44D7E73EA3FA48");
	assert_eq!(oauth.webcookie, "");
}

#[derive(Debug, Clone, Deserialize)]
pub struct SteamApiResponse<T> {
	pub response: T,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddAuthenticatorResponse {
	/// Shared secret between server and authenticator
	#[serde(default)]
	pub shared_secret: String,
	/// Authenticator serial number (unique per token)
	#[serde(default)]
	pub serial_number: String,
	/// code used to revoke authenticator
	#[serde(default)]
	pub revocation_code: String,
	/// URI for QR code generation
	#[serde(default)]
	pub uri: String,
	/// Current server time
	#[serde(default, deserialize_with = "parse_json_string_as_number")]
	pub server_time: u64,
	/// Account name to display on token client
	#[serde(default)]
	pub account_name: String,
	/// Token GID assigned by server
	#[serde(default)]
	pub token_gid: String,
	/// Secret used for identity attestation (e.g., for eventing)
	#[serde(default)]
	pub identity_secret: String,
	/// Spare shared secret
	#[serde(default)]
	pub secret_1: String,
	/// Result code
	pub status: i32,
}

impl AddAuthenticatorResponse {
	pub fn to_steam_guard_account(&self) -> SteamGuardAccount {
		SteamGuardAccount {
			shared_secret: self.shared_secret.clone(),
			serial_number: self.serial_number.clone(),
			revocation_code: self.revocation_code.clone(),
			uri: self.uri.clone(),
			server_time: self.server_time,
			account_name: self.account_name.clone(),
			token_gid: self.token_gid.clone(),
			identity_secret: self.identity_secret.clone(),
			secret_1: self.secret_1.clone(),
			fully_enrolled: false,
			device_id: "".into(),
			session: None,
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
pub struct FinalizeAddAuthenticatorResponse {
	pub status: i32,
	#[serde(deserialize_with = "parse_json_string_as_number")]
	pub server_time: u64,
	pub want_more: bool,
	pub success: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveAuthenticatorResponse {
	pub success: bool,
}

fn parse_json_string_as_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
	D: Deserializer<'de>,
{
	// for some reason, deserializing to &str doesn't work but this does.
	let s: String = Deserialize::deserialize(deserializer)?;
	Ok(s.parse().unwrap())
}

#[test]
fn test_parse_add_auth_response() {
	let result = serde_json::from_str::<SteamApiResponse<AddAuthenticatorResponse>>(include_str!(
		"fixtures/api-responses/add-authenticator-1.json"
	));

	assert!(
		matches!(result, Ok(_)),
		"got error: {}",
		result.unwrap_err()
	);
	let resp = result.unwrap().response;

	assert_eq!(resp.server_time, 1628559846);
	assert_eq!(resp.shared_secret, "wGwZx=sX5MmTxi6QgA3Gi");
	assert_eq!(resp.revocation_code, "R123456");
}

#[test]
fn test_parse_add_auth_response2() {
	let result = serde_json::from_str::<SteamApiResponse<AddAuthenticatorResponse>>(include_str!(
		"fixtures/api-responses/add-authenticator-2.json"
	));

	assert!(
		matches!(result, Ok(_)),
		"got error: {}",
		result.unwrap_err()
	);
	let resp = result.unwrap().response;

	assert_eq!(resp.status, 29);
}
