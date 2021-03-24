use std::collections::HashMap;
use reqwest::{Url, cookie::CookieStore, header::COOKIE, header::USER_AGENT};
use rsa::{PublicKey, RSAPublicKey};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;

#[derive(Debug, Deserialize)]
struct LoginResponse {
	success: bool,
	login_complete: bool,
	oauth_data_string: String,
}

#[derive(Debug, Deserialize)]
struct RsaResponse {
	success: bool,
	publickey_exp: String,
	publickey_mod: String,
	timestamp: String,
	token_gid: String,
}

#[derive(Debug)]
pub enum LoginResult {
	Ok,
	BadRSA,
	BadCredentials,
	NeedCaptcha,
	Need2FA,
	NeedEmail,
	OtherFailure,
}

#[derive(Debug)]
pub struct UserLogin {
	pub username: String,
	pub password: String,
	pub captcha_text: String,
	pub twofactor_code: String,
	pub email_code: String,

	cookies: reqwest::cookie::Jar,
	// cookies: Arc<reqwest::cookie::Jar>,
	client: reqwest::blocking::Client,
}

impl UserLogin {
	pub fn new(username: String, password: String) -> UserLogin {
		return UserLogin {
			username,
			password,
			captcha_text: String::from(""),
			twofactor_code: String::from(""),
			email_code: String::from(""),
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
			}
			Err(error) => {
				println!("rsa error: {:?}", error);
				return LoginResult::BadRSA
			}
		}

		let mut params = HashMap::new();
		params.insert("donotcache", format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000));
		params.insert("username", self.username.clone());

		return LoginResult::OtherFailure
	}
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
