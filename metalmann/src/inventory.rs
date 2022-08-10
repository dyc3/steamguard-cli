use std::{collections::HashMap, io::{Write, Read}};

use anyhow::bail;
use log::*;
use reqwest::header::{HeaderMap, IF_MODIFIED_SINCE, LAST_MODIFIED};
use serde::{Serialize, Deserialize};

use crate::{webapi, schema::{IEconItemsResponse, Tf2Schema, Tf2SchemaItem}, tf2meta::Quality};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2Inventory {
	pub items: Vec<Tf2InventoryItem>
}

impl Tf2Inventory {
	pub fn write_to<T>(&self, w: T) -> anyhow::Result<()> where T: Write {
		Ok(serde_json::to_writer(w, self)?)
	}

	pub fn from_reader<T>(r: T) -> anyhow::Result<Self> where T: Read {
		Ok(serde_json::from_reader(r)?)
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
	pub attributes: Option<Vec<Tf2InventoryItemAttributes>>,
}

impl Tf2InventoryItem {
	pub fn get_schema_item(&self, schema: &Tf2Schema) -> Option<Tf2SchemaItem> {
		schema.get_schema_item(self.defindex)
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2InventoryItemAttributes {
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
			items: resp.result.items
		}
	}
}

/// Endpoint: GET http://api.steampowered.com/IEconItems_440/GetPlayerItems/v0001/
pub fn fetch_inventory(steamid: u64) -> anyhow::Result<Tf2Inventory> {
	debug!("fetch_inventory");

	let apikey = webapi::get_web_api_key();
	if apikey.is_none() {
		bail!("missing api key, call metalmann::webapi::set_web_api_key() first")
	}
	let apikey = apikey.unwrap();

	let mut url = "https://api.steampowered.com/IEconItems_440/GetPlayerItems/v0001/".parse::<reqwest::Url>().unwrap();
	url.set_query(Some(format!("key={}&steamid={}", &apikey, steamid).as_str()));
	let client = reqwest::blocking::Client::default();
	let req = client.get(url).build()?;
	let resp = client.execute(req)?.error_for_status()?;
	debug!("response code: {}", resp.status());

	let text = resp.text()?;
	// println!("{}", text);
	let data: IEconItemsResponse<ResponseGetPlayerItems> = serde_json::from_str(text.as_str())?;
	Ok(data.into())
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