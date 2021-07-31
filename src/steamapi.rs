use std::collections::HashMap;
use reqwest::{Url, cookie::{CookieStore}, header::COOKIE, header::{SET_COOKIE, USER_AGENT}};
use rsa::{PublicKey, RsaPublicKey};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;
use log::*;

#[derive(Debug, Clone, Deserialize)]
struct LoginResponse {
	success: bool,
	#[serde(default)]
	login_complete: bool,
	// #[serde(default)]
	// oauth: String,
	#[serde(default)]
	captcha_needed: bool,
	#[serde(default)]
	captcha_gid: String,
	#[serde(default)]
	emailsteamid: u64,
	#[serde(default)]
	emailauth_needed: bool,
	#[serde(default)]
	requires_twofactor: bool,
	#[serde(default)]
	message: String,
	transfer_urls: Option<Vec<String>>,
	transfer_parameters: Option<LoginTransferParameters>,
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
struct RsaResponse {
	success: bool,
	publickey_exp: String,
	publickey_mod: String,
	timestamp: String,
	token_gid: String,
}

#[derive(Debug)]
pub enum LoginResult {
	Ok(Session),
	BadRSA,
	BadCredentials,
	NeedCaptcha{ captcha_gid: String },
	Need2FA,
	NeedEmail,
	TooManyAttempts,
	OtherFailure,
}

#[derive(Debug)]
pub struct UserLogin {
	pub username: String,
	pub password: String,
	pub captcha_required: bool,
	pub captcha_gid: String,
	pub captcha_text: String,
	pub twofactor_code: String,
	pub email_code: String,
	pub steam_id: u64,

	cookies: reqwest::cookie::Jar,
	// cookies: Arc<reqwest::cookie::Jar>,
	client: reqwest::blocking::Client,
}

impl UserLogin {
	pub fn new(username: String, password: String) -> UserLogin {
		return UserLogin {
			username,
			password,
			captcha_required: false,
			captcha_gid: String::from("-1"),
			captcha_text: String::from(""),
			twofactor_code: String::from(""),
			email_code: String::from(""),
			steam_id: 0,
			cookies: reqwest::cookie::Jar::default(),
			// cookies: Arc::<reqwest::cookie::Jar>::new(reqwest::cookie::Jar::default()),
			client: reqwest::blocking::ClientBuilder::new()
				.cookie_store(true)
				.build()
				.unwrap(),
		}
	}

	fn update_session(&self) {
		trace!("UserLogin::update_session");
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		self.cookies.add_cookie_str("mobileClientVersion=0 (2.1.3)", &url);
		self.cookies.add_cookie_str("mobileClient=android", &url);
		self.cookies.add_cookie_str("Steam_Language=english", &url);

		let resp = self.client
			.get("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client".parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			// .header(COOKIE, "mobileClientVersion=0 (2.1.3)")
			// .header(COOKIE, "mobileClient=android")
			// .header(COOKIE, "Steam_Language=english")
			.header(COOKIE, self.cookies.cookies(&url).unwrap())
			.send();
		trace!("{:?}", resp);

		trace!("cookies: {:?}", self.cookies);
	}

	pub fn login(&mut self) -> LoginResult {
		trace!("UserLogin::login");
		if self.captcha_required && self.captcha_text.len() == 0 {
			return LoginResult::NeedCaptcha{captcha_gid: self.captcha_gid.clone()};
		}

		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		if self.cookies.cookies(&url) == Option::None {
			self.update_session()
		}

		let mut params = HashMap::new();
		params.insert("donotcache", format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000));
		params.insert("username", self.username.clone());
		let resp = self.client
			.post("https://steamcommunity.com/login/getrsakey")
			.form(&params)
			.send()
			.unwrap();

		let encrypted_password: String;
		let rsa_timestamp: String;
		match resp.json::<RsaResponse>() {
			Ok(rsa_resp) => {
				rsa_timestamp = rsa_resp.timestamp.clone();
				encrypted_password = encrypt_password(rsa_resp, &self.password);
			}
			Err(error) => {
				error!("rsa error: {:?}", error);
				return LoginResult::BadRSA
			}
		}

		trace!("captchagid: {}", self.captcha_gid);
		trace!("captcha_text: {}", self.captcha_text);
		trace!("twofactorcode: {}", self.twofactor_code);
		trace!("emailauth: {}", self.email_code);
		let mut params = HashMap::new();
		params.insert("donotcache", format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000));
		params.insert("username", self.username.clone());
		params.insert("password", encrypted_password);
		params.insert("twofactorcode", self.twofactor_code.clone());
		params.insert("emailauth", self.email_code.clone());
		params.insert("captchagid", self.captcha_gid.clone());
		params.insert("captcha_text", self.captcha_text.clone());
		params.insert("rsatimestamp", rsa_timestamp);
		params.insert("remember_login", String::from("true"));
		params.insert("oauth_client_id", String::from("DE45CD61"));
		params.insert("oauth_scope", String::from("read_profile write_profile read_client write_client"));

		let login_resp: LoginResponse;
		match self.client
			.post("https://steamcommunity.com/login/dologin")
			.form(&params)
			.send() {
				Ok(resp) => {
					// https://stackoverflow.com/questions/49928648/rubys-mechanize-error-401-while-sending-a-post-request-steam-trade-offer-send
					let text = resp.text().unwrap();
					trace!("resp content: {}", text);
					match serde_json::from_str(text.as_str()) {
						Ok(lr) => {
							info!("login resp: {:?}", lr);
							login_resp = lr;
						}
						Err(error) => {
							debug!("login response did not have normal schema");
							error!("login parse error: {:?}", error);
							return LoginResult::OtherFailure;
						}
					}
				}
				Err(error) => {
					error!("login request error: {:?}", error);
					return LoginResult::OtherFailure;
				}
		}

		if login_resp.message.contains("too many login") {
			return LoginResult::TooManyAttempts;
		}

		if login_resp.message.contains("Incorrect login") {
			return LoginResult::BadCredentials;
		}

		if login_resp.captcha_needed {
			self.captcha_gid = login_resp.captcha_gid.clone();
			return LoginResult::NeedCaptcha{ captcha_gid: self.captcha_gid.clone() };
		}

		if login_resp.emailauth_needed {
			self.steam_id = login_resp.emailsteamid.clone();
			return LoginResult::NeedEmail;
		}

		if login_resp.requires_twofactor {
			return LoginResult::Need2FA;
		}

		if !login_resp.login_complete {
			return LoginResult::BadCredentials;
		}


		// transfer login parameters? Not completely sure what this is for.
		// i guess steam changed their authentication scheme slightly
		let oauth;
		match (login_resp.transfer_urls, login_resp.transfer_parameters) {
			(Some(urls), Some(params)) => {
				debug!("received transfer parameters, relaying data...");
				for url in urls {
					trace!("posting transfer to {}", url);
					let result = self.client
						.post(url)
						.json(&params)
						.send();
					trace!("result: {:?}", result);
					match result {
						Ok(resp) => {
							debug!("result status: {}", resp.status());
							self.save_cookies_from_response(&resp);
						}
						Err(e) => {
							error!("failed to transfer parameters: {:?}", e);
						}
					}
				}

				oauth = OAuthData {
					oauth_token: params.auth,
					steamid: params.steamid.parse().unwrap(),
					wgtoken: params.token_secure.clone(), // guessing
					wgtoken_secure: params.token_secure,
					webcookie: params.webcookie,
				};
			}
			_ => {
				error!("did not receive transfer_urls and transfer_parameters");
				return LoginResult::OtherFailure;
			}
		}

		// let oauth: OAuthData = serde_json::from_str(login_resp.oauth.as_str()).unwrap();
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = self.cookies.cookies(&url).unwrap();
		let all_cookies = cookies.to_str().unwrap();
		let mut session_id = String::from("");
		for cookie in all_cookies.split(";").map(|s| cookie::Cookie::parse(s).unwrap()) {
			if cookie.name() == "sessionid" {
				session_id = String::from(cookie.value());
			}
		}
		trace!("cookies {:?}", cookies);
		let session = self.build_session(oauth, session_id);

		return LoginResult::Ok(session);
	}

	fn build_session(&self, data: OAuthData, session_id: String) -> Session {
		return Session{
			token: data.oauth_token,
			steam_id: data.steamid,
			steam_login: format!("{}%7C%7C{}", data.steamid, data.wgtoken),
			steam_login_secure: format!("{}%7C%7C{}", data.steamid, data.wgtoken_secure),
			session_id: session_id,
			web_cookie: data.webcookie,
		};
	}

	fn save_cookies_from_response(&mut self, response: &reqwest::blocking::Response) {
		let set_cookie_iter = response.headers().get_all(SET_COOKIE);
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();

		for c in set_cookie_iter {
			c.to_str()
				.into_iter()
				.for_each(|cookie_str| {
					self.cookies.add_cookie_str(cookie_str, &url)
				});
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthData {
	oauth_token: String,
	steamid: u64,
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

	return String::from(value["response"]["server_time"].as_str().unwrap()).parse().unwrap();
}

fn encrypt_password(rsa_resp: RsaResponse, password: &String) -> String {
	let rsa_exponent = rsa::BigUint::parse_bytes(rsa_resp.publickey_exp.as_bytes(), 16).unwrap();
	let rsa_modulus = rsa::BigUint::parse_bytes(rsa_resp.publickey_mod.as_bytes(), 16).unwrap();
	let public_key = RsaPublicKey::new(rsa_modulus, rsa_exponent).unwrap();
	#[cfg(test)]
	let mut rng = rand::rngs::mock::StepRng::new(2, 1);
	#[cfg(not(test))]
	let mut rng = OsRng;
	let padding = rsa::PaddingScheme::new_pkcs1v15_encrypt();
	let encrypted_password = base64::encode(public_key.encrypt(&mut rng, padding, password.as_bytes()).unwrap());
	return encrypted_password;
}

#[test]
fn test_encrypt_password() {
	let rsa_resp = RsaResponse{
		success: true,
		publickey_exp: String::from("010001"),
		publickey_mod: String::from("98f9088c1250b17fe19d2b2422d54a1eef0036875301731f11bd17900e215318eb6de1546727c0b7b61b86cefccdcb2f8108c813154d9a7d55631965eece810d4ab9d8a59c486bda778651b876176070598a93c2325c275cb9c17bdbcacf8edc9c18c0c5d59bc35703505ef8a09ed4c62b9f92a3fac5740ce25e490ab0e26d872140e4103d912d1e3958f844264211277ee08d2b4dd3ac58b030b25342bd5c949ae7794e46a8eab26d5a8deca683bfd381da6c305b19868b8c7cd321ce72c693310a6ebf2ecd43642518f825894602f6c239cf193cb4346ce64beac31e20ef88f934f2f776597734bb9eae1ebdf4a453973b6df9d5e90777bffe5db83dd1757b"),
		timestamp: String::from("asdf"),
		token_gid: String::from("asdf"),
	};
	let result = encrypt_password(rsa_resp, &String::from("kelwleofpsm3n4ofc"));
	assert_eq!(result.len(), 344);
	assert_eq!(result, "RUo/3IfbkVcJi1q1S5QlpKn1mEn3gNJoc/Z4VwxRV9DImV6veq/YISEuSrHB3885U5MYFLn1g94Y+cWRL6HGXoV+gOaVZe43m7O92RwiVz6OZQXMfAv3UC/jcqn/xkitnj+tNtmx55gCxmGbO2KbqQ0TQqAyqCOOw565B+Cwr2OOorpMZAViv9sKA/G3Q6yzscU6rhua179c8QjC1Hk3idUoSzpWfT4sHNBW/EREXZ3Dkjwu17xzpfwIUpnBVIlR8Vj3coHgUCpTsKVRA3T814v9BYPlvLYwmw5DW3ddx+2SyTY0P5uuog36TN2PqYS7ioF5eDe16gyfRR4Nzn/7wA==");
}
