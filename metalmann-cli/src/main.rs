use std::{fs::File, path::Path};

use log::*;
use clap::Parser;
use metalmann::inventory::Tf2Inventory;

mod cli;

fn main() -> anyhow::Result<()> {
	let args = cli::Args::parse();
	info!("{:?}", args);

	stderrlog::new()
		.verbosity(args.verbosity as usize)
		.module(module_path!())
		.module("metalmann")
		.init()
		.unwrap();

	metalmann::webapi::set_web_api_key(args.web_api_key);

	let schema = metalmann::schema::fetch_item_schema(None)?;
	// println!("{:?}", schema);
	println!("last modified: {:?}", schema.last_modified);

	let steamid = 76561198054667933;
	let inventory_cache_path = format!("{}/metalmann/inventory/", dirs::cache_dir().unwrap().to_str().unwrap());
	std::fs::create_dir_all(&inventory_cache_path)?;
	let inventory_cache_path = format!("{}/{}.json", inventory_cache_path, steamid);
	let inventory = match metalmann::inventory::fetch_inventory(steamid) {
		Ok(inv) => {
			debug!("writing inventory to cache");
			let cache_file = File::create(inventory_cache_path)?;
			inv.write_to(cache_file)?;
			debug!("done writing inventory to cache");
			inv
		},
		Err(err) => {
			warn!("failed to fetch inventory: {} - loading from cache", err);
			let cache_file = File::open(inventory_cache_path)?;
			Tf2Inventory::from_reader(cache_file)?
		}
	};
	info!("inventory has {} items", inventory.items.len());

	Ok(())
}

