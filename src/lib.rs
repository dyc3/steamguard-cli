use std::convert::TryInto;
use serde::{Serialize, Deserialize};

mod steamapi;

// const STEAMAPI_BASE: String = "https://api.steampowered.com";
// const COMMUNITY_BASE: String = "https://steamcommunity.com";
// const MOBILEAUTH_BASE: String = STEAMAPI_BASE + "/IMobileAuthService/%s/v0001";
// static MOBILEAUTH_GETWGTOKEN: String = MOBILEAUTH_BASE.Replace("%s", "GetWGToken");
// const TWO_FACTOR_BASE: String = STEAMAPI_BASE + "/ITwoFactorService/%s/v0001";
// static TWO_FACTOR_TIME_QUERY: String = TWO_FACTOR_BASE.Replace("%s", "QueryTime");

extern crate hmacsha1;
extern crate base64;

#[derive(Debug, Serialize, Deserialize)]
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
