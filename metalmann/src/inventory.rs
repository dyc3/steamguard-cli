use std::collections::HashMap;

use log::*;
use reqwest::header::{HeaderMap, IF_MODIFIED_SINCE, LAST_MODIFIED};
use serde::{Serialize, Deserialize};

pub struct PlayerInventory {
	items: Vec<Tf2InventoryItem>
}

#[derive(Serialize, Deserialize)]
pub struct Tf2InventoryItem {
	/// The unique ID of the specific item.
	id: i64,
	level: u32,
	flag_cannot_trade: bool,
	flag_cannot_craft: bool,
}

/// Endpoint: GET http://api.steampowered.com/IEconItems_440/GetPlayerItems/v0001/
pub fn fetch_inventory() {
	debug!("fetch_inventory");

}