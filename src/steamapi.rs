use std::collections::HashMap;
use reqwest::{Url, cookie::CookieStore, header::COOKIE, header::USER_AGENT};
use rsa::{PublicKey, RSAPublicKey};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use serde::de::{Visitor};
use rand::rngs::OsRng;
use std::fmt;

#[derive(Debug, Clone, Deserialize)]
struct LoginResponse {
	success: bool,
	#[serde(default)]
	login_complete: bool,
	#[serde(default)]
	oauth: String,
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
	message: String,
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
	Ok{ session: Session },
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
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		self.cookies.add_cookie_str("mobileClientVersion=0 (2.1.3)", &url);
		self.cookies.add_cookie_str("mobileClient=android", &url);
		self.cookies.add_cookie_str("Steam_Language=english", &url);

		let _ = self.client
			.get("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client".parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			// .header(COOKIE, "mobileClientVersion=0 (2.1.3)")
			// .header(COOKIE, "mobileClient=android")
			// .header(COOKIE, "Steam_Language=english")
			.header(COOKIE, self.cookies.cookies(&url).unwrap())
			.send();
	}

	pub fn login(&self) -> LoginResult {
		if self.captcha_required && self.captcha_text.len() == 0 {
			return LoginResult::NeedCaptcha{captcha_gid: self.captcha_gid};
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
				// println!("rsa: {:?}", rsa_resp);
				let rsa_exponent = rsa::BigUint::parse_bytes(rsa_resp.publickey_exp.as_bytes(), 16).unwrap();
				let rsa_modulus = rsa::BigUint::parse_bytes(rsa_resp.publickey_mod.as_bytes(), 16).unwrap();
				let public_key = RSAPublicKey::new(rsa_modulus, rsa_exponent).unwrap();
				// println!("public key: {:?}", public_key);
				let mut rng = OsRng;
				let padding = rsa::PaddingScheme::new_pkcs1v15_encrypt();
				encrypted_password = base64::encode(public_key.encrypt(&mut rng, padding, self.password.as_bytes()).unwrap());
				println!("encrypted_password: {:?}", encrypted_password);
				rsa_timestamp = rsa_resp.timestamp;
			}
			Err(error) => {
				println!("rsa error: {:?}", error);
				return LoginResult::BadRSA
			}
		}

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
					// println!("login resp: {:?}", &resp.text());
					match resp.json::<LoginResponse>() {
						Ok(lr) => {
							println!("login resp: {:?}", lr);
							login_resp = lr;
						}
						Err(error) => {
							println!("login parse error: {:?}", error);
							return LoginResult::OtherFailure;
						}
					}
				}
				Err(error) => {
					println!("login request error: {:?}", error);
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
			self.captcha_gid = login_resp.captcha_gid;
			return LoginResult::NeedCaptcha{ captcha_gid: self.captcha_gid };
		}

		if login_resp.emailauth_needed {
			self.steam_id = login_resp.emailsteamid;
			return LoginResult::NeedEmail;
		}

		if login_resp.requires_twofactor {
			return LoginResult::Need2FA;
		}

		if !login_resp.login_complete {
			return LoginResult::BadCredentials;
		}

		let oauth: OAuthData = serde_json::from_str(login_resp.oauth).unwrap();
		let session = self.build_session(oauth);

		return LoginResult::Ok{session};
	}

	fn build_session(&self, data: OAuthData) -> Session {
		return Session{
			token: data.oauth_token,
			steam_id: data.steamid,
			steam_login: format!("{}%7C%7C{}", data.steamid, data.wgtoken),
			steam_login_secure: format!("{}%7C%7C{}", data.steamid, data.wgtoken_secure),
			session_id: todo!(),
			web_cookie: todo!(),
		};
	}
}

struct OAuthData {
	oauth_token: String,
	steamid: u64,
	wgtoken: String,
	wgtoken_secure: String,
	webcookie: String,
}

pub struct Session {
	pub session_id: String,
	pub steam_login: String,
	pub steam_login_secure: String,
	pub web_cookie: String,
	pub token: String,
	pub steam_id: u64,
}

pub fn get_server_time() -> i64 {
	let client = reqwest::blocking::Client::new();
	let resp = client
		.post("https://api.steampowered.com/ITwoFactorService/QueryTime/v0001")
		.body("steamid=0")
		.send();
	let value: serde_json::Value = resp.unwrap().json().unwrap();

	// println!("{}", value["response"]);

	return String::from(value["response"]["server_time"].as_str().unwrap()).parse().unwrap();
}
