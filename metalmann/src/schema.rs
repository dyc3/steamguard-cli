use std::{collections::HashMap, io::{Write, Read}};
use anyhow::bail;
use log::*;
use reqwest::header::{HeaderMap, IF_MODIFIED_SINCE, LAST_MODIFIED};
use serde::{Serialize, Deserialize};
use chrono::{Utc, TimeZone};

use crate::{webapi, tf2meta::{Quality, ItemSlot}};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tf2Schema {
	pub items: Vec<Tf2SchemaItem>,
	pub last_modified: Option<chrono::DateTime<Utc>>,
}

impl Tf2Schema {
	pub fn write_to<T>(&self, w: T) -> anyhow::Result<()> where T: Write {
		Ok(serde_json::to_writer(w, self)?)
	}

	pub fn from_reader<T>(r: T) -> anyhow::Result<Self> where T: Read {
		Ok(serde_json::from_reader(r)?)
	}

	pub fn get_schema_item(&self, defindex: u32) -> Option<Tf2SchemaItem> {
		self.items.iter().find(|item| item.defindex == defindex).cloned()
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2SchemaItem {
	/// A string that defines the item in the items_game.txt
	pub name: String,
	/// The item's unique index, used to refer to instances of the item in GetPlayerItems.
	pub defindex: u32,
	pub proper_name: bool,
	pub item_slot: Option<ItemSlot>,
	pub image_url: Option<String>,
	pub image_url_large: Option<String>,
	/// The item's default quality value. See description of "qualities" above.
	pub item_quality: Quality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IEconItemsResponse<T> {
	pub(crate) result: T
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ResponseGetSchemaItems {
	status: u64,
	items: Vec<Tf2SchemaItem>,
	next: Option<u64>,
}

/// Endpoint: GET https://api.steampowered.com/IEconItems_440/GetSchemaItems/v0001/?key=<API key>
pub fn fetch_item_schema(if_modified_since: Option<chrono::DateTime<Utc>>) -> anyhow::Result<Tf2Schema> {
	debug!("fetch_item_schema");
	let mut next_item_start: Option<u64> = None;
	let mut schema = Tf2Schema { ..Default::default() };
	let apikey = webapi::get_web_api_key();
	if apikey.is_none() {
		bail!("missing api key, call metalmann::webapi::set_web_api_key() first")
	}
	let apikey = apikey.unwrap();

	loop {
		let mut url = "https://api.steampowered.com/IEconItems_440/GetSchemaItems/v0001/".parse::<reqwest::Url>().unwrap();
		url.set_query(Some(format!("key={}&language=en", &apikey).as_str()));
		if let Some(next) = next_item_start {
			url.query_pairs_mut().append_pair("start", next.to_string().as_str());
		}
		let client = reqwest::blocking::Client::default();
		let mut headers = HeaderMap::new();
		if let Some(t) = if_modified_since {
			headers.insert(IF_MODIFIED_SINCE, t.format("%a, %d %b %Y %H:%M:%S GMT").to_string().parse().unwrap());
		}
		let req = client.get(url).headers(headers).build()?;
		let resp = client.execute(req)?;
		debug!("response code: {}", resp.status());
		if resp.status() != 200 {
			warn!("failed to get schema with HTTP status code: {}", resp.status());
			break;
		}
		if let Some(last_mod) = resp.headers().get(LAST_MODIFIED) {
			debug!("parsing Last-Modified header");
			let t = Utc.datetime_from_str(last_mod.to_str()?, "%a, %d %b %Y %H:%M:%S GMT")?;
			schema.last_modified = Some(t.into());
		}
		let text = resp.text()?;
		let data: IEconItemsResponse<ResponseGetSchemaItems> = serde_json::from_str(text.as_str())?;
		let mut data = data.result;
		if data.status != 1 {
			debug!("got status: {}", data.status)
		}

		debug!("schema response contained {} items, appending", data.items.len());
		schema.items.append(&mut data.items);
		if data.next.is_none() {
			debug!("done getting item schema");
			break;
		}
		next_item_start = data.next;
	}

	Ok(schema)
}
