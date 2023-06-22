use crate::protobufs::service_twofactor::{
	CTwoFactor_RemoveAuthenticator_Request, CTwoFactor_RemoveAuthenticator_Response,
};
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
use scraper::{Html, Selector};
pub use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryInto, io::Read};
use steamapi::SteamApiClient;
use token::Tokens;
pub use userlogin::{DeviceDetails, LoginError, UserLogin};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate maplit;

mod accountlinker;
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
	pub session: Option<secrecy::Secret<steamapi::Session>>,
}

fn build_time_bytes(time: u64) -> [u8; 8] {
	return time.to_be_bytes();
}

fn generate_confirmation_hash_for_time(time: u64, tag: &str, identity_secret: &String) -> String {
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
		return SteamGuardAccount {
			account_name: String::from(""),
			serial_number: String::from(""),
			revocation_code: String::from("").into(),
			shared_secret: TwoFactorSecret::new(),
			token_gid: String::from(""),
			identity_secret: String::from("").into(),
			uri: String::from("").into(),
			device_id: String::from(""),
			secret_1: String::from("").into(),
			tokens: None,
			session: None,
		};
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

	pub fn set_session(&mut self, session: steamapi::Session) {
		self.session = Some(session.into());
	}

	pub fn generate_code(&self, time: u64) -> String {
		return self.shared_secret.generate_code(time);
	}

	fn get_confirmation_query_params(&self, tag: &str, time: u64) -> HashMap<&str, String> {
		let session = self.session.as_ref().unwrap().expose_secret();
		let mut params = HashMap::new();
		params.insert("p", self.device_id.clone());
		params.insert("a", session.steam_id.to_string());
		params.insert(
			"k",
			generate_confirmation_hash_for_time(time, tag, &self.identity_secret.expose_secret()),
		);
		params.insert("t", time.to_string());
		params.insert("m", String::from("android"));
		params.insert("tag", String::from(tag));
		return params;
	}

	fn build_cookie_jar(&self) -> reqwest::cookie::Jar {
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = reqwest::cookie::Jar::default();
		let session = self.session.as_ref().unwrap().expose_secret();
		cookies.add_cookie_str("mobileClientVersion=0 (2.1.3)", &url);
		cookies.add_cookie_str("mobileClient=android", &url);
		cookies.add_cookie_str("Steam_Language=english", &url);
		cookies.add_cookie_str("dob=", &url);
		cookies.add_cookie_str(format!("sessionid={}", session.session_id).as_str(), &url);
		cookies.add_cookie_str(format!("steamid={}", session.steam_id).as_str(), &url);
		cookies.add_cookie_str(format!("steamLogin={}", session.steam_login).as_str(), &url);
		cookies.add_cookie_str(
			format!("steamLoginSecure={}", session.steam_login_secure).as_str(),
			&url,
		);
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

		let time = steamapi::get_server_time()?.server_time;
		let resp = client
			.get("https://steamcommunity.com/mobileconf/conf".parse::<Url>().unwrap())
			.header("X-Requested-With", "com.valvesoftware.android.steam.community")
			.header(USER_AGENT, "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
			.header(COOKIE, cookies.cookies(&url).unwrap())
			.query(&self.get_confirmation_query_params("conf", time))
			.send()?;

		trace!("{:?}", resp);
		let text = resp.text().unwrap();
		trace!("text: {:?}", text);
		trace!("{}", text);
		return parse_confirmations(text);
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

		let time = steamapi::get_server_time()?.server_time;
		let mut query_params = self.get_confirmation_query_params("conf", time);
		query_params.insert("op", operation);
		query_params.insert("cid", conf.id.to_string());
		query_params.insert("ck", conf.key.to_string());

		#[derive(Debug, Clone, Copy, Deserialize)]
		struct SendConfirmationResponse {
			pub success: bool,
		}

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

		let time = steamapi::get_server_time()?.server_time;
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

fn parse_confirmations(text: String) -> anyhow::Result<Vec<Confirmation>> {
	// possible errors:
	//
	// Invalid authenticator:
	// <div>Invalid authenticator</div>
	// <div>It looks like your Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes. This could be caused by an inaccurate clock or bad timezone settings on your device. If your time settings are correct, it could be that a different device has been set up to provide the Steam Guard codes for your account, which means the authenticator on this device is no longer valid.</div>
	//
	// <div>Nothing to confirm</div>

	let fragment = Html::parse_fragment(&text);
	let selector = Selector::parse(".mobileconf_list_entry").unwrap();
	let desc_selector = Selector::parse(".mobileconf_list_entry_description").unwrap();
	let mut confirmations = vec![];
	for elem in fragment.select(&selector) {
		let desc: String = elem
			.select(&desc_selector)
			.next()
			.unwrap()
			.text()
			.map(|t| t.trim())
			.filter(|t| t.len() > 0)
			.collect::<Vec<_>>()
			.join(" ");
		let conf = Confirmation {
			id: elem.value().attr("data-confid").unwrap().parse()?,
			key: elem.value().attr("data-key").unwrap().parse()?,
			conf_type: elem
				.value()
				.attr("data-type")
				.unwrap()
				.try_into()
				.unwrap_or(ConfirmationType::Unknown),
			creator: elem.value().attr("data-creator").unwrap().parse()?,
			description: desc,
		};
		confirmations.push(conf);
	}
	return Ok(confirmations);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_confirmation_hash_for_time() {
		assert_eq!(
			generate_confirmation_hash_for_time(
				1617591917,
				"conf",
				&String::from("GQP46b73Ws7gr8GmZFR0sDuau5c=")
			),
			String::from("NaL8EIMhfy/7vBounJ0CvpKbrPk=")
		);
	}

	#[test]
	fn test_parse_multiple_confirmations() {
		let text = include_str!("fixtures/confirmations/multiple-confirmations.html");
		let confirmations = parse_confirmations(text.into()).unwrap();
		assert_eq!(confirmations.len(), 5);
		assert_eq!(
			confirmations[0],
			Confirmation {
				id: 9890792058,
				key: 15509106087034649470,
				conf_type: ConfirmationType::MarketSell,
				creator: 3392884950693131245,
				description: "Sell - Summer 2021 - Horror $0.05 ($0.03) 2 minutes ago".into(),
			}
		);
		assert_eq!(
			confirmations[1],
			Confirmation {
				id: 9890791666,
				key: 2661901169510258722,
				conf_type: ConfirmationType::MarketSell,
				creator: 3392884950693130525,
				description: "Sell - Summer 2021 - Horror $0.05 ($0.03) 2 minutes ago".into(),
			}
		);
		assert_eq!(
			confirmations[2],
			Confirmation {
				id: 9890791241,
				key: 15784514761287735229,
				conf_type: ConfirmationType::MarketSell,
				creator: 3392884950693129565,
				description: "Sell - Summer 2021 - Horror $0.05 ($0.03) 2 minutes ago".into(),
			}
		);
		assert_eq!(
			confirmations[3],
			Confirmation {
				id: 9890790828,
				key: 5049250785011653560,
				conf_type: ConfirmationType::MarketSell,
				creator: 3392884950693128685,
				description: "Sell - Summer 2021 - Rogue $0.05 ($0.03) 2 minutes ago".into(),
			}
		);
		assert_eq!(
			confirmations[4],
			Confirmation {
				id: 9890790159,
				key: 6133112455066694993,
				conf_type: ConfirmationType::MarketSell,
				creator: 3392884950693127345,
				description: "Sell - Summer 2021 - Horror $0.05 ($0.03) 2 minutes ago".into(),
			}
		);
	}

	#[test]
	fn test_parse_phone_number_change() {
		let text = include_str!("fixtures/confirmations/phone-number-change.html");
		let confirmations = parse_confirmations(text.into()).unwrap();
		assert_eq!(confirmations.len(), 1);
		assert_eq!(
			confirmations[0],
			Confirmation {
				id: 9931444017,
				key: 9746021299562127894,
				conf_type: ConfirmationType::AccountRecovery,
				creator: 2861625242839108895,
				description: "Account recovery Just now".into(),
			}
		);
	}
}
