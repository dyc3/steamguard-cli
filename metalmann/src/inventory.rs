use std::{collections::HashMap, io::{Write, Read}};

use anyhow::bail;
use chrono::{Utc, TimeZone};
use log::*;
use reqwest::header::{HeaderMap, IF_MODIFIED_SINCE, LAST_MODIFIED, EXPIRES};
use serde::{Serialize, Deserialize};

use crate::{webapi, schema::{IEconItemsResponse, Tf2Schema, Tf2SchemaItem}, tf2meta::{Quality, ItemSlot}, require_web_api_key};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2Inventory {
	#[serde(default)]
	pub steamid: u64,
	pub items: Vec<Tf2InventoryItem>,
	#[serde(default)]
	pub expires_at: Option<chrono::DateTime<Utc>>,
}

impl Tf2Inventory {
	pub fn write_to<T>(&self, w: T) -> anyhow::Result<()> where T: Write {
		Ok(serde_json::to_writer(w, self)?)
	}

	pub fn from_reader<T>(r: T) -> anyhow::Result<Self> where T: Read {
		Ok(serde_json::from_reader(r)?)
	}

	pub fn steamid(&self) -> u64 {
		self.steamid
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2InventoryItem {
	/// The unique ID of the specific item.
	pub id: u64,
	/// The ID of the item before it was customized, traded, or otherwise changed.
	pub original_id: u64,
	/// The defindex of the item, as found in the item array returned from GetSchema.
	pub defindex: u32,
	/// The arbitrary "level" value of the item as displayed in the inventory.
	pub level: u32,
	/// The number of "uses" an item has, generally only has a value in excess of '1' on "usable items", such as the Dueling Mini-Game.
	pub quantity: u32,
	pub origin: u32,
	pub quality: Quality,
	/// A boolean value that is true if the item cannot be traded. Assume false if not present.
	#[serde(default)]
	pub flag_cannot_trade: bool,
	/// A boolean value that is true if the item cannot be used in crafting. Assume false if not present.
	#[serde(default)]
	pub flag_cannot_craft: bool,
	pub custom_name: Option<String>,
	pub custom_desc: Option<String>,
	pub attributes: Option<Vec<Tf2InventoryItemAttribute>>,
}

impl Tf2InventoryItem {
	pub fn get_schema_item(&self, schema: &Tf2Schema) -> Option<Tf2SchemaItem> {
		schema.get_item(self.defindex).cloned()
	}

	pub fn is_weapon(&self, schema: &Tf2Schema) -> bool {
		matches!(self.get_schema_item(&schema).unwrap().item_slot, Some(ItemSlot::Primary | ItemSlot::Secondary | ItemSlot::Melee))
	}

	pub fn has_attribute(&self, defindex: u32) -> bool {
		if let Some(attrs) = self.attributes.as_ref() {
			return attrs.iter().find(|attr| attr.defindex == defindex).is_some()
		}
		false
	}

	pub fn get_attribute(&self, defindex: u32) -> Option<Tf2InventoryItemAttribute> {
		if let Some(attrs) = self.attributes.as_ref() {
			return attrs.iter().find(|attr| attr.defindex == defindex).cloned()
		}
		None
	}

	pub fn is_stattrak(&self) -> bool {
		return self.has_attribute(719)
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2InventoryItemAttribute {
	/// The index to the attributes definition in the schema, e.g. 133 for the medal number attribute for the Gentle Manne's Service Medal.
	defindex: u32,
	value: Option<serde_json::Value>,
	float_value: Option<f64>,
	account_info: Option<Tf2InventoryItemAttributeAccountInfo>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2InventoryItemAttributeAccountInfo {
	pub steamid: u64,
	pub personaname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ResponseGetPlayerItems {
	status: u32,
	items: Vec<Tf2InventoryItem>,
}

impl From<IEconItemsResponse<ResponseGetPlayerItems>> for Tf2Inventory {
	fn from(resp: IEconItemsResponse<ResponseGetPlayerItems>) -> Self {
		Tf2Inventory {
			steamid: Default::default(),
			items: resp.result.items,
			expires_at: Default::default(),
		}
	}
}

/// Endpoint: GET http://api.steampowered.com/IEconItems_440/GetPlayerItems/v1/
pub fn fetch_inventory(steamid: u64) -> anyhow::Result<Tf2Inventory, crate::errors::Error> {
	debug!("fetch_inventory");

	let apikey = require_web_api_key!();

	let mut url = "https://api.steampowered.com/IEconItems_440/GetPlayerItems/v1/".parse::<reqwest::Url>().unwrap();
	url.set_query(Some(format!("key={}&steamid={}", &apikey, steamid).as_str()));
	let client = reqwest::blocking::Client::default();
	let req = client.get(url).build()?;
	let resp = client.execute(req)?;
	debug!("response code: {}", resp.status());
	debug!("response header: {:?}", resp.headers());
	if resp.status() != 200 {
		return Err(crate::errors::Error::ApiError(format!("HTTP status code: {}", resp.status())));
	}
	let headers = resp.headers().clone();

	let text = resp.text()?;
	// println!("{}", text);
	let data: IEconItemsResponse<ResponseGetPlayerItems> = serde_json::from_str(text.as_str())?;
	let mut inventory: Tf2Inventory = data.into();
	inventory.steamid = steamid;
	if let Some(e) = headers.get(EXPIRES) {
		let value = e.to_str()
			.map_err(|err| crate::errors::Error::MalformedHeader { header: EXPIRES.to_owned(), value: e.to_owned(), source: err.into() })?;
		let t = Utc.datetime_from_str(value, "%a, %d %b %Y %H:%M:%S GMT")
			.map_err(|err| crate::errors::Error::MalformedHeader { header: EXPIRES.to_owned(), value: e.to_owned(), source: err.into() })?;
		inventory.expires_at = Some(t.into());
	}
	Ok(inventory)
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_parse_inventory_response() {
		let text = include_str!("fixtures/api-responses/GetPlayerItems-76561198054667933.json");
		let result = serde_json::from_str::<IEconItemsResponse<ResponseGetPlayerItems>>(text);
		assert!(matches!(result, Ok(_)), "got {:?}", result)
	}
}