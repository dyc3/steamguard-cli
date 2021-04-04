use std::{collections::HashMap, convert::TryInto, thread, time};
use hmacsha1::hmac_sha1;
use reqwest::{Url, cookie::CookieStore, header::{COOKIE, USER_AGENT}};
use serde::{Serialize, Deserialize};
use log::*;

pub mod steamapi;

// const STEAMAPI_BASE: String = "https://api.steampowered.com";
// const COMMUNITY_BASE: String = "https://steamcommunity.com";
// const MOBILEAUTH_BASE: String = STEAMAPI_BASE + "/IMobileAuthService/%s/v0001";
// static MOBILEAUTH_GETWGTOKEN: String = MOBILEAUTH_BASE.Replace("%s", "GetWGToken");
// const TWO_FACTOR_BASE: String = STEAMAPI_BASE + "/ITwoFactorService/%s/v0001";
// static TWO_FACTOR_TIME_QUERY: String = TWO_FACTOR_BASE.Replace("%s", "QueryTime");

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
	time /= 30i64;

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

		let time_bytes: [u8; 8] = build_time_bytes(time);
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
		params.insert("k", self.generate_confirmation_hash_for_time(time, tag));
		params.insert("t", time.to_string());
		params.insert("m", String::from("android"));
		params.insert("tag", String::from(tag));
		return params;
	}

	fn generate_confirmation_hash_for_time(&self, time: i64, tag: &str) -> String {
		let decode: &[u8] = &base64::decode(&self.identity_secret).unwrap();
		let time_bytes = build_time_bytes(time);
		let tag_bytes = tag.as_bytes();
		let array = [&time_bytes, tag_bytes].concat();
		let hash = hmac_sha1(decode, &array);
		let encoded = base64::encode(hash);
		return encoded;
	}

	pub fn get_trade_confirmations(&self) {
		// uri: "https://steamcommunity.com/mobileconf/conf"
		// confirmation details:
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = reqwest::cookie::Jar::default();
		let session_id = self.session.clone().unwrap().session_id;
		let cookie_val = format!("sessionid={}", session_id);
		cookies.add_cookie_str(cookie_val.as_str(), &url);
		let client = reqwest::blocking::ClientBuilder::new()
			.build()
			.unwrap();

		loop {
			match client
				.get("https://steamcommunity.com/mobileconf/conf".parse::<Url>().unwrap())
				.header("X-Requested-With", "com.valvesoftware.android.steam.community")
				.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
				.header(COOKIE, cookies.cookies(&url).unwrap())
				.query(&self.get_confirmation_query_params("conf"))
				.send() {
					Ok(resp) => {
						info!("{:?}", resp);
						break;
					}
					Err(e) => {
						error!("error: {:?}", e);
						thread::sleep(time::Duration::from_secs(3));
					}
				}
		}
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
}
