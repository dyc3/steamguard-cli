use std::collections::HashMap;
use reqwest::{Url, cookie::{CookieStore}, header::COOKIE};
use serde::Deserialize;
use serde_json::Value;
use steamguard::{SteamGuardAccount, steamapi::Session};
use log::*;

#[derive(Debug, Clone)]
pub struct AccountLinker {
	device_id: String,
	phone_number: String,
	pub account: SteamGuardAccount,
	client: reqwest::blocking::Client,
}

impl AccountLinker {
	pub fn new() -> AccountLinker {
		return AccountLinker{
			device_id: generate_device_id(),
			phone_number: String::from(""),
			account: SteamGuardAccount::new(),
			client: reqwest::blocking::ClientBuilder::new()
				.cookie_store(true)
				.build()
				.unwrap(),
		}
	}

	pub fn link(&self, session: &mut Session) {
		let mut params = HashMap::new();
		params.insert("access_token", session.token.clone());
		params.insert("steamid", session.steam_id.to_string());
		params.insert("device_identifier", self.device_id.clone());
		params.insert("authenticator_type", String::from("1"));
		params.insert("sms_phone_id", String::from("1"));
	}

	fn has_phone(&self, session: &Session) -> bool {
		return self._phoneajax(session, "has_phone", "null");
	}

	fn _phoneajax(&self, session: &Session, op: &str, arg: &str) -> bool {
		trace!("_phoneajax: op={}", op);
		let url = "https://steamcommunity.com".parse::<Url>().unwrap();
		let cookies = reqwest::cookie::Jar::default();
		cookies.add_cookie_str("mobileClientVersion=0 (2.1.3)", &url);
		cookies.add_cookie_str("mobileClient=android", &url);
		cookies.add_cookie_str("Steam_Language=english", &url);

		let mut params = HashMap::new();
		params.insert("op", op);
		params.insert("arg", arg);
		params.insert("sessionid", session.session_id.as_str());
		if op == "check_sms_code" {
			params.insert("checkfortos", "0");
			params.insert("skipvoip", "1");
		}

		let resp = self.client
			.post("https://steamcommunity.com/steamguard/phoneajax")
			.header(COOKIE, cookies.cookies(&url).unwrap())
			.send()
			.unwrap();

		let result: Value = resp.json().unwrap();
		if result["has_phone"] != Value::Null {
			trace!("found has_phone field");
			return result["has_phone"].as_bool().unwrap();
		} else if result["success"] != Value::Null {
			trace!("found success field");
			return result["success"].as_bool().unwrap();
		} else {
			trace!("did not find any expected field");
			return false;
		}
	}
}

fn generate_device_id() -> String {
	return format!("android:{}", uuid::Uuid::new_v4().to_string());
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddAuthenticatorResponse {
	pub response: SteamGuardAccount
}
