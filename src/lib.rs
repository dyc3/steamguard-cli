use std::{collections::HashMap, convert::TryInto, thread, time};
use anyhow::Result;
use confirmation::{Confirmation, ConfirmationType};
use hmacsha1::hmac_sha1;
use regex::Regex;
use reqwest::{Url, cookie::CookieStore, header::{COOKIE, USER_AGENT}};
use serde::{Serialize, Deserialize};
use log::*;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;

pub mod steamapi;
mod confirmation;

// const STEAMAPI_BASE: String = "https://api.steampowered.com";
// const COMMUNITY_BASE: String = "https://steamcommunity.com";
// const MOBILEAUTH_BASE: String = STEAMAPI_BASE + "/IMobileAuthService/%s/v0001";
// static MOBILEAUTH_GETWGTOKEN: String = MOBILEAUTH_BASE.Replace("%s", "GetWGToken");
// const TWO_FACTOR_BASE: String = STEAMAPI_BASE + "/ITwoFactorService/%s/v0001";
// static TWO_FACTOR_TIME_QUERY: String = TWO_FACTOR_BASE.Replace("%s", "QueryTime");

lazy_static! {
	static ref CONFIRMATION_REGEX: Regex = Regex::new("<div class=\"mobileconf_list_entry\" id=\"conf[0-9]+\" data-confid=\"(\\d+)\" data-key=\"(\\d+)\" data-type=\"(\\d+)\" data-creator=\"(\\d+)\"").unwrap();
	static ref CONFIRMATION_DESCRIPTION_REGEX: Regex = Regex::new("<div>((Confirm|Trade|Account recovery|Sell -) .+)</div>").unwrap();
}

extern crate hmacsha1;
extern crate base64;
extern crate cookie;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamGuardAccount {
	pub account_name: String,
	pub serial_number: String,
	pub revocation_code: String,
	pub shared_secret: String,
	pub token_gid: String,
	pub identity_secret: String,
	pub server_time: u64,
	pub uri: String,
	pub fully_enrolled: bool,
	pub device_id: String,
	#[serde(rename = "Session")]
	pub session: Option<steamapi::Session>,
}

fn build_time_bytes(mut time: i64) -> [u8; 8] {
	let mut bytes: [u8; 8] = [0; 8];
	for i in (0..8).rev() {
		bytes[i] = time as u8;
		time >>= 8;
	}
	return bytes
}

pub fn parse_shared_secret(secret: String) -> [u8; 20] {
	if secret.len() == 0 {
		panic!("unable to parse empty shared secret")
	}
	match base64::decode(secret) {
		Result::Ok(v) => {
			return v.try_into().unwrap()
		}
		_ => {
			panic!("unable to parse shared secret")
		}
	}
}

fn generate_confirmation_hash_for_time(time: i64, tag: &str, identity_secret: &String) -> String {
	let decode: &[u8] = &base64::decode(&identity_secret).unwrap();
	let time_bytes = build_time_bytes(time);
	let tag_bytes = tag.as_bytes();
	let array = [&time_bytes, tag_bytes].concat();
	let hash = hmac_sha1(decode, &array);
	let encoded = base64::encode(hash);
	return encoded;
}

impl SteamGuardAccount {
	pub fn new() -> Self {
		return SteamGuardAccount{
			account_name: String::from(""),
			serial_number: String::from(""),
			revocation_code: String::from(""),
			shared_secret: String::from(""),
			token_gid: String::from(""),
			identity_secret: String::from(""),
			server_time: 0,
			uri: String::from(""),
			fully_enrolled: false,
			device_id: String::from(""),
			session: Option::None,
		}
	}

	pub fn generate_code(&self, time: i64) -> String {
		let steam_guard_code_translations: [u8; 26] = [50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89];

		let time_bytes: [u8; 8] = build_time_bytes(time / 30i64);
		let shared_secret: [u8; 20] = parse_shared_secret(self.shared_secret.clone());
		// println!("time_bytes: {:?}", time_bytes);
		let hashed_data = hmacsha1::hmac_sha1(&shared_secret, &time_bytes);
		// println!("hashed_data: {:?}", hashed_data);
		let mut code_array: [u8; 5] = [0; 5];
		let b = (hashed_data[19] & 0xF) as usize;
		let mut code_point: i32 =
			((hashed_data[b] & 0x7F) as i32) << 24 |
			((hashed_data[b + 1] & 0xFF) as i32) << 16 |
			((hashed_data[b + 2] & 0xFF) as i32) << 8 |
			((hashed_data[b + 3] & 0xFF) as i32);

		for i in 0..5 {
			code_array[i] = steam_guard_code_translations[code_point as usize % steam_guard_code_translations.len()];
			code_point /= steam_guard_code_translations.len() as i32;
		}

		// println!("code_array: {:?}", code_array);

		return String::from_utf8(code_array.iter().map(|c| *c).collect()).unwrap()
	}

	fn get_confirmation_query_params(&self, tag: &str) -> HashMap<&str, String> {
		let session = self.session.clone().unwrap();
		let time = steamapi::get_server_time();
		let mut params = HashMap::new();
		params.insert("p", self.device_id.clone());
		params.insert("a", session.steam_id.to_string());
		params.insert("k", generate_confirmation_hash_for_time(time, tag, &self.identity_secret));
		params.insert("t", time.to_string());
		params.insert("m", String::from("android"));
		params.insert("tag", String::from(tag));
		return params;
	}

	fn build_cookie_jar(&self) -> reqwest::cookie::Jar {
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = reqwest::cookie::Jar::default();
		let session = self.session.clone().unwrap();
		let session_id = session.session_id;
		cookies.add_cookie_str("mobileClientVersion=0 (2.1.3)", &url);
		cookies.add_cookie_str("mobileClient=android", &url);
		cookies.add_cookie_str("Steam_Language=english", &url);
		cookies.add_cookie_str("dob=", &url);
		cookies.add_cookie_str(format!("sessionid={}", session_id).as_str(), &url);
		cookies.add_cookie_str(format!("steamid={}", session.steam_id).as_str(), &url);
		cookies.add_cookie_str(format!("steamLogin={}", session.steam_login).as_str(), &url);
		cookies.add_cookie_str(format!("steamLoginSecure={}", session.steam_login_secure).as_str(), &url);
		return cookies;
	}

	pub fn get_trade_confirmations(&self) -> Result<Vec<Confirmation>, anyhow::Error> {
		// uri: "https://steamcommunity.com/mobileconf/conf"
		// confirmation details:
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = self.build_cookie_jar();
		let client = reqwest::blocking::ClientBuilder::new()
			.cookie_store(true)
			.build()?;

		match client
			.get("https://steamcommunity.com/mobileconf/conf".parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			.header(COOKIE, cookies.cookies(&url).unwrap())
			.query(&self.get_confirmation_query_params("conf"))
			.send() {
				Ok(resp) => {
					trace!("{:?}", resp);
					let text = resp.text().unwrap();
					trace!("text: {:?}", text);
					println!("{}", text);
					// possible errors:
					//
					// Invalid authenticator:
					// <div>Invalid authenticator</div>
					// <div>It looks like your Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes. This could be caused by an inaccurate clock or bad timezone settings on your device. If your time settings are correct, it could be that a different device has been set up to provide the Steam Guard codes for your account, which means the authenticator on this device is no longer valid.</div>
					//
					// <div>Nothing to confirm</div>
					match CONFIRMATION_REGEX.captures(text.as_str()) {
						Some(caps) => {
							let conf_id = caps[1].parse()?;
							let conf_key = caps[2].parse()?;
							let conf_type = caps[3].try_into().unwrap_or(ConfirmationType::Unknown);
							let conf_creator = caps[4].parse()?;
							debug!("conf_id={} conf_key={} conf_type={:?} conf_creator={}", conf_id, conf_key, conf_type, conf_creator);
							return Ok(vec![Confirmation {
								id: conf_id,
								key: conf_key,
								conf_type: conf_type,
								creator: conf_creator,
								int_type: 0,
							}]);
						}
						_ => {
							info!("No confirmations");
							return Ok(vec![]);
						}
					};
				}
				Err(e) => {
					error!("error: {:?}", e);
					bail!(e);
				}
			}
	}

	/// Respond to a confirmation.
	///
	/// Host: https://steamcommunity.com
	/// Steam Endpoint: `POST /mobileconf/ajaxop`
	fn send_confirmation_ajax(&self, conf: Confirmation, operation: String) -> anyhow::Result<()> {
		ensure!(operation == "allow" || operation == "cancel");

		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = self.build_cookie_jar();
		let client = reqwest::blocking::ClientBuilder::new()
			.cookie_store(true)
			.build()?;

		let mut query_params = self.get_confirmation_query_params("conf");
		query_params.insert("op", operation);
		query_params.insert("cid", conf.id.to_string());
		query_params.insert("ck", conf.key.to_string());

		#[derive(Debug, Clone, Copy, Deserialize)]
		struct SendConfirmationResponse {
			pub success: bool
		}

		let resp: SendConfirmationResponse = client.get("https://steamcommunity.com/mobileconf/ajaxop".parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			.header(COOKIE, cookies.cookies(&url).unwrap())
			.query(&query_params)
			.send()?
			.json()?;

		ensure!(resp.success);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_code() {
		let mut account = SteamGuardAccount::new();
		account.shared_secret = String::from("zvIayp3JPvtvX/QGHqsqKBk/44s=");

		let code = account.generate_code(1616374841i64);
		assert_eq!(code, "2F9J5")
	}

	#[test]
	fn test_generate_confirmation_hash_for_time() {
		assert_eq!(generate_confirmation_hash_for_time(1617591917, "conf", &String::from("GQP46b73Ws7gr8GmZFR0sDuau5c=")), String::from("NaL8EIMhfy/7vBounJ0CvpKbrPk="));
	}
}
