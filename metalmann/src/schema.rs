use std::{collections::HashMap, io::{Write, Read}};
use anyhow::bail;
use log::*;
use reqwest::header::{HeaderMap, IF_MODIFIED_SINCE, LAST_MODIFIED};
use serde::{Serialize, Deserialize};
use chrono::{Utc, TimeZone};

use crate::{webapi, tf2meta::{Quality, ItemSlot}};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tf2Schema {
	items: HashMap<u32, Tf2SchemaItem>,
	attributes: HashMap<u32, Tf2SchemaAttribute>,
	pub last_modified: Option<chrono::DateTime<Utc>>,
}

impl Tf2Schema {
	pub fn write_to<T>(&self, w: T) -> anyhow::Result<()> where T: Write {
		Ok(serde_json::to_writer(w, self)?)
	}

	pub fn from_reader<T>(r: T) -> anyhow::Result<Self> where T: Read {
		Ok(serde_json::from_reader(r)?)
	}

	pub fn get_item(&self, defindex: u32) -> Option<&Tf2SchemaItem> {
		let s = self.items.get(&defindex);
		if s.is_none() {
			debug!("schema lookup failed for defindex {}", defindex);
		}
		s
	}

	pub fn get_attribute(&self, defindex: u32) -> Option<&Tf2SchemaAttribute> {
		self.attributes.get(&defindex)
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
pub struct Tf2SchemaAttribute {
	/// A name describing the attribute (eg. "damage bonus" for damage increases found on weapons such as the Scotsman's Skullcutter, or "scattergun has knockback" for the Force-A-Nature's knockback)
	pub name: String,
	/// The attribute's unique index, used to refer to unique instances of the item with these attributes in GetPlayerItems.
	pub defindex: u32,
	// an underscore-based name for the attribute (eg. "mult_dmg" for the attribute whose name is "damage bonus")
	pub attribute_class: Option<String>,
	// The minimum value allowed for this attribute.
	pub minvalue: Option<i32>,
	// The maximum value allowed for this attribute.
	pub maxvalue: Option<i32>,
	// The tokenized string that describes the attribute.
	pub description_string: Option<String>,
	pub description_format: Option<String>,
	pub effect_type: String,
	pub hidden: bool,
	pub stored_as_integer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IEconItemsResponse<T> {
	pub(crate) result: T
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ResponseGetSchemaItems {
	status: u64,
	items: Vec<Tf2SchemaItem>,
	attributes: Option<Vec<Tf2SchemaAttribute>>,
	next: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ResponseGetSchemaOverview {
	status: u64,
	attributes: Vec<Tf2SchemaAttribute>,
}

/// Endpoints:
/// - https://api.steampowered.com/IEconItems_440/GetSchemaOverview/v1?key=<API key>
/// - GET https://api.steampowered.com/IEconItems_440/GetSchemaItems/v1/?key=<API key>
pub fn fetch_item_schema(if_modified_since: Option<chrono::DateTime<Utc>>) -> anyhow::Result<Tf2Schema> {
	debug!("fetch_item_schema");
	let mut next_item_start: Option<u64> = None;
	let mut schema = Tf2Schema { ..Default::default() };
	let apikey = webapi::get_web_api_key();
	if apikey.is_none() {
		bail!("missing api key, call metalmann::webapi::set_web_api_key() first")
	}
	let apikey = apikey.unwrap();

	debug!("fetching GetSchemaItems");

	loop {
		let mut url = "https://api.steampowered.com/IEconItems_440/GetSchemaItems/v1/".parse::<reqwest::Url>().unwrap();
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
		let data = data.result;
		if data.status != 1 {
			debug!("got status: {}", data.status)
		}

		debug!("schema response contained {} items, appending", data.items.len());
		let _ = data.items.iter().map(|item| schema.items.insert(item.defindex, item.clone()));

		if data.next.is_none() {
			debug!("done getting item schema");
			break;
		}
		next_item_start = data.next;
	}

	debug!("fetching GetSchemaOverview");
	let mut url = "https://api.steampowered.com/IEconItems_440/GetSchemaOverview/v1/".parse::<reqwest::Url>().unwrap();
	url.set_query(Some(format!("key={}&language=en", &apikey).as_str()));
	let client = reqwest::blocking::Client::default();
	let mut headers = HeaderMap::new();
	if let Some(t) = if_modified_since {
		headers.insert(IF_MODIFIED_SINCE, t.format("%a, %d %b %Y %H:%M:%S GMT").to_string().parse().unwrap());
	}
	let req = client.get(url).headers(headers).build()?;
	let resp = client.execute(req)?;
	let text = resp.text()?;
	let data: IEconItemsResponse<ResponseGetSchemaOverview> = serde_json::from_str(text.as_str())?;
	let data = data.result;
	if data.status != 1 {
		debug!("got status: {}", data.status)
	}

	debug!("schema response contained {} attributes, appending", data.attributes.len());
	let _ = data.attributes.iter().map(|attr| schema.attributes.insert(attr.defindex, attr.clone()));

	Ok(schema)
}
