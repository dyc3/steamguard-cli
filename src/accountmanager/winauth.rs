//! Accounts exported from Winauth are in the following format:
//!
//! One account per line, with each account represented as a URL.
//!
//! ```ignore
//! otpauth://totp/Steam:<steamaccountname>?secret=<ABCDEFG1234_secret_dunno_what_for>&digits=5&issuer=Steam&deviceid=<URL_Escaped_device_name>&data=<url_encoded_data_json>
//! ```
//!
//! The `data` field is a URL encoded JSON object with the following fields:
//!
//! ```json
//! {"steamid":"<steam_id>","status":1,"shared_secret":"<shared_secret>","serial_number":"<serial_number>","revocation_code":"<revocation_code>","uri":"<uri>","server_time":"<server_time>","account_name":"<steam_login_name>","token_gid":"<token_gid>","identity_secret":"<identity_secret>","secret_1":"<secret_1>","steamguard_scheme":"2"}
//! ```

use anyhow::Context;
use log::*;
use reqwest::Url;

use super::migrate::ExternalAccount;

pub(crate) fn parse_winauth_exports(buf: Vec<u8>) -> anyhow::Result<Vec<ExternalAccount>> {
	let buf = String::from_utf8(buf)?;
	let mut accounts = Vec::new();
	for line in buf.split('\n') {
		if line.is_empty() {
			continue;
		}
		let url = Url::parse(line).context("parsing as winauth export URL")?;
		let mut query = url.query_pairs();
		let issuer = query
			.find(|(key, _)| key == "issuer")
			.context("missing issuer field")?
			.1;
		if issuer != "Steam" {
			debug!("skipping non-Steam account: {}", issuer);
			continue;
		}
		let data = query
			.find(|(key, _)| key == "data")
			.context("missing data field")?
			.1;

		trace!("data: {}", data);

		let mut deser = serde_json::Deserializer::from_str(&data);
		let account = serde_path_to_error::deserialize(&mut deser)?;
		accounts.push(account);
	}
	Ok(accounts)
}
