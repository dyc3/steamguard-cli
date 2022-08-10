use std::collections::HashMap;

use anyhow::bail;
use log::*;
use reqwest::header::{HeaderMap, IF_MODIFIED_SINCE, LAST_MODIFIED};
use serde::{Serialize, Deserialize};

use crate::{webapi, schema::IEconItemsResponse, tf2meta::Quality};

#[derive(Debug, Clone)]
pub struct Tf2Inventory {
	pub items: Vec<Tf2InventoryItem>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tf2InventoryItem {
	/// The unique ID of the specific item.
	id: u64,
	/// The ID of the item before it was customized, traded, or otherwise changed.
	original_id: u64,
	/// The defindex of the item, as found in the item array returned from GetSchema.
	defindex: u32,
	/// The arbitrary "level" value of the item as displayed in the inventory.
	level: u32,
	/// The number of "uses" an item has, generally only has a value in excess of '1' on "usable items", such as the Dueling Mini-Game.
	quantity: u32,
	origin: u32,
	quality: Quality,
	/// A boolean value that is true if the item cannot be traded. Assume false if not present.
	#[serde(default)]
	flag_cannot_trade: bool,
	/// A boolean value that is true if the item cannot be used in crafting. Assume false if not present.
	#[serde(default)]
	flag_cannot_craft: bool,
	custom_name: Option<String>,
	custom_desc: Option<String>,
	attributes: Option<Vec<Tf2InventoryItemAttributes>>,
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
	let resp = client.execute(req)?;
	debug!("response code: {}", resp.status());

	let text = resp.text()?;
	// println!("{}", text);
	let data: IEconItemsResponse<ResponseGetPlayerItems> = serde_json::from_str(text.as_str())?;
	let data = data.result;

	let inventory = Tf2Inventory {
		items: data.items
	};

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