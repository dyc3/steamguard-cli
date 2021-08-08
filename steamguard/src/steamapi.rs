use log::*;
use reqwest::{
	blocking::RequestBuilder,
	cookie::CookieStore,
	header::COOKIE,
	header::{HeaderMap, HeaderName, HeaderValue, SET_COOKIE},
	Url,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::iter::FromIterator;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

lazy_static! {
	static ref STEAM_COOKIE_URL: Url = "https://steamcommunity.com".parse::<Url>().unwrap();
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
	#[serde(rename = "WebCookie")]
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

/// Provides raw access to the Steam API. Handles cookies, some deserialization, etc. to make it easier.
#[derive(Debug)]
pub struct SteamApiClient {
	cookies: reqwest::cookie::Jar,
	client: reqwest::blocking::Client,
	pub session: Option<Session>,
}

impl SteamApiClient {
	pub fn new() -> SteamApiClient {
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
			session: None,
		}
	}

	fn build_session(&self, data: &OAuthData) -> Session {
		return Session {
			token: data.oauth_token.clone(),
			steam_id: data.steamid.parse().unwrap(),
			steam_login: format!("{}%7C%7C{}", data.steamid, data.wgtoken),
			steam_login_secure: format!("{}%7C%7C{}", data.steamid, data.wgtoken_secure),
			session_id: self.extract_session_id().unwrap(),
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

	pub fn request<U: reqwest::IntoUrl>(&self, method: reqwest::Method, url: U) -> RequestBuilder {
		self.cookies
			.add_cookie_str("mobileClientVersion=0 (2.1.3)", &STEAM_COOKIE_URL);
		self.cookies
			.add_cookie_str("mobileClient=android", &STEAM_COOKIE_URL);
		self.cookies
			.add_cookie_str("Steam_Language=english", &STEAM_COOKIE_URL);

		self.client
			.request(method, url)
			.header(COOKIE, self.cookies.cookies(&STEAM_COOKIE_URL).unwrap())
	}

	pub fn get<U: reqwest::IntoUrl>(&self, url: U) -> RequestBuilder {
		self.request(reqwest::Method::GET, url)
	}

	pub fn post<U: reqwest::IntoUrl>(&self, url: U) -> RequestBuilder {
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
