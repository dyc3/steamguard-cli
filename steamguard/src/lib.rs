use crate::confirmation::{ConfirmationListResponse, SendConfirmationResponse};
use crate::protobufs::service_twofactor::CTwoFactor_RemoveAuthenticator_Request;
use crate::steamapi::EResult;
use crate::{
	steamapi::twofactor::TwoFactorClient, token::TwoFactorSecret, transport::WebApiTransport,
};
pub use accountlinker::{AccountLinkError, AccountLinker, FinalizeLinkError};
use anyhow::Result;
pub use confirmation::{Confirmation, ConfirmationType};
use hmacsha1::hmac_sha1;
use log::*;
use reqwest::{
	cookie::CookieStore,
	header::{COOKIE, USER_AGENT},
	Url,
};
pub use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Read};
use token::Tokens;
pub use userlogin::{DeviceDetails, LoginError, UserLogin};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate maplit;

pub mod accountlinker;
mod api_responses;
mod confirmation;
pub mod protobufs;
mod secret_string;
pub mod steamapi;
pub mod token;
pub mod transport;
pub mod userlogin;

extern crate base64;
extern crate cookie;
extern crate hmacsha1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamGuardAccount {
	pub account_name: String,
	pub steam_id: u64,
	pub serial_number: String,
	#[serde(with = "secret_string")]
	pub revocation_code: SecretString,
	pub shared_secret: TwoFactorSecret,
	pub token_gid: String,
	#[serde(with = "secret_string")]
	pub identity_secret: SecretString,
	#[serde(with = "secret_string")]
	pub uri: SecretString,
	pub device_id: String,
	#[serde(with = "secret_string")]
	pub secret_1: SecretString,
	pub tokens: Option<Tokens>,
}

fn build_time_bytes(time: u64) -> [u8; 8] {
	time.to_be_bytes()
}

fn generate_confirmation_hash_for_time(
	time: u64,
	tag: &str,
	identity_secret: impl AsRef<[u8]>,
) -> String {
	let decode: &[u8] = &base64::decode(identity_secret).unwrap();
	let time_bytes = build_time_bytes(time);
	let tag_bytes = tag.as_bytes();
	let array = [&time_bytes, tag_bytes].concat();
	let hash = hmac_sha1(decode, &array);
	base64::encode(hash)
}

impl Default for SteamGuardAccount {
	fn default() -> Self {
		Self {
			account_name: String::from(""),
			steam_id: 0,
			serial_number: String::from(""),
			revocation_code: String::from("").into(),
			shared_secret: TwoFactorSecret::new(),
			token_gid: String::from(""),
			identity_secret: String::from("").into(),
			uri: String::from("").into(),
			device_id: String::from(""),
			secret_1: String::from("").into(),
			tokens: None,
		}
	}
}

impl SteamGuardAccount {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn from_reader<T>(r: T) -> anyhow::Result<Self>
	where
		T: Read,
	{
		Ok(serde_json::from_reader(r)?)
	}

	pub fn set_tokens(&mut self, tokens: Tokens) {
		self.tokens = Some(tokens);
	}

	pub fn is_logged_in(&self) -> bool {
		self.tokens.is_some()
	}

	pub fn generate_code(&self, time: u64) -> String {
		self.shared_secret.generate_code(time)
	}

	fn get_confirmation_query_params(&self, tag: &str, time: u64) -> HashMap<&str, String> {
		let mut params = HashMap::new();
		params.insert("p", self.device_id.clone());
		params.insert("a", self.steam_id.to_string());
		params.insert(
			"k",
			generate_confirmation_hash_for_time(time, tag, self.identity_secret.expose_secret()),
		);
		params.insert("t", time.to_string());
		params.insert("m", String::from("android"));
		params.insert("tag", String::from(tag));
		params
	}

	fn build_cookie_jar(&self) -> reqwest::cookie::Jar {
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = reqwest::cookie::Jar::default();
		// let session = self.session.as_ref().unwrap().expose_secret();
		let tokens = self.tokens.as_ref().unwrap();
		cookies.add_cookie_str("mobileClientVersion=0 (2.1.3)", &url);
		cookies.add_cookie_str("mobileClient=android", &url);
		cookies.add_cookie_str("Steam_Language=english", &url);
		cookies.add_cookie_str("dob=", &url);
		// cookies.add_cookie_str(format!("sessionid={}", session.session_id).as_str(), &url);
		cookies.add_cookie_str(format!("steamid={}", self.steam_id).as_str(), &url);
		cookies.add_cookie_str(
			format!(
				"steamLoginSecure={}||{}",
				self.steam_id,
				tokens.access_token().expose_secret()
			)
			.as_str(),
			&url,
		);
		cookies
	}

	pub fn get_trade_confirmations(&self) -> Result<Vec<Confirmation>, anyhow::Error> {
		// uri: "https://steamcommunity.com/mobileconf/conf"
		// confirmation details:
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = self.build_cookie_jar();
		let client = reqwest::blocking::ClientBuilder::new()
			.cookie_store(true)
			.build()?;

		let time = steamapi::get_server_time()?.server_time();
		let resp = client
			.get("https://steamcommunity.com/mobileconf/getlist".parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			.header(COOKIE, cookies.cookies(&url).unwrap())
			.query(&self.get_confirmation_query_params("conf", time))
			.send()?;

		trace!("{:?}", resp);
		let text = resp.text().unwrap();
		trace!("text: {:?}", text);
		trace!("{}", text);

		let body: ConfirmationListResponse = serde_json::from_str(text.as_str())?;
		ensure!(body.success);
		Ok(body.conf)
	}

	/// Respond to a confirmation.
	///
	/// Host: https://steamcommunity.com
	/// Steam Endpoint: `GET /mobileconf/ajaxop`
	fn send_confirmation_ajax(&self, conf: &Confirmation, operation: String) -> anyhow::Result<()> {
		ensure!(operation == "allow" || operation == "cancel");

		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = self.build_cookie_jar();
		let client = reqwest::blocking::ClientBuilder::new()
			.cookie_store(true)
			.build()?;

		let time = steamapi::get_server_time()?.server_time();
		let mut query_params = self.get_confirmation_query_params("conf", time);
		query_params.insert("op", operation);
		query_params.insert("cid", conf.id.to_string());
		query_params.insert("ck", conf.nonce.to_string());

		let resp = client.get("https://steamcommunity.com/mobileconf/ajaxop".parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			.header(COOKIE, cookies.cookies(&url).unwrap())
			.query(&query_params)
			.send()?;

		trace!("send_confirmation_ajax() response: {:?}", &resp);
		debug!(
			"send_confirmation_ajax() response status code: {}",
			&resp.status()
		);

		let raw = resp.text()?;
		debug!("send_confirmation_ajax() response body: {:?}", &raw);

		let body: SendConfirmationResponse = serde_json::from_str(raw.as_str())?;

		if !body.success {
			return Err(anyhow!("Server responded with failure."));
		}

		Ok(())
	}

	pub fn accept_confirmation(&self, conf: &Confirmation) -> anyhow::Result<()> {
		self.send_confirmation_ajax(conf, "allow".into())
	}

	pub fn deny_confirmation(&self, conf: &Confirmation) -> anyhow::Result<()> {
		self.send_confirmation_ajax(conf, "cancel".into())
	}

	/// Steam Endpoint: `GET /mobileconf/details/:id`
	pub fn get_confirmation_details(&self, conf: &Confirmation) -> anyhow::Result<String> {
		#[derive(Debug, Clone, Deserialize)]
		struct ConfirmationDetailsResponse {
			pub success: bool,
			pub html: String,
		}

		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = self.build_cookie_jar();
		let client = reqwest::blocking::ClientBuilder::new()
			.cookie_store(true)
			.build()?;

		let time = steamapi::get_server_time()?.server_time();
		let query_params = self.get_confirmation_query_params("details", time);

		let resp: ConfirmationDetailsResponse = client.get(format!("https://steamcommunity.com/mobileconf/details/{}", conf.id).parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			.header(COOKIE, cookies.cookies(&url).unwrap())
			.query(&query_params)
			.send()?
			.json()?;

		ensure!(resp.success);
		Ok(resp.html)
	}

	/// Removes the mobile authenticator from the steam account. If this operation succeeds, this object can no longer be considered valid.
	/// Returns whether or not the operation was successful.
	pub fn remove_authenticator(&self, revocation_code: Option<String>) -> anyhow::Result<bool> {
		ensure!(
			matches!(revocation_code, Some(_)) || !self.revocation_code.expose_secret().is_empty(),
			"Revocation code not provided."
		);
		let Some(tokens) = &self.tokens else {
			return Err(anyhow!("Tokens not set, login required"));
		};
		let mut client = TwoFactorClient::new(WebApiTransport::new());
		let mut req = CTwoFactor_RemoveAuthenticator_Request::new();
		req.set_revocation_code(
			revocation_code.unwrap_or(self.revocation_code.expose_secret().to_owned()),
		);
		let resp = client.remove_authenticator(req, tokens.access_token())?;
		if resp.result != EResult::OK {
			Err(anyhow!("Failed to remove authenticator: {:?}", resp.result))
		} else {
			Ok(true)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_confirmation_hash_for_time() {
		assert_eq!(
			generate_confirmation_hash_for_time(1617591917, "conf", "GQP46b73Ws7gr8GmZFR0sDuau5c="),
			String::from("NaL8EIMhfy/7vBounJ0CvpKbrPk=")
		);
	}
}
