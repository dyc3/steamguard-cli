use std::{fs::File, collections::HashMap};

use log::*;
use clap::Parser;
use metalmann::{inventory::Tf2Inventory, tf2meta::Quality};

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

	let valuable_uniques: Vec<u32> = vec![
		264, // Frying Pan
		474, // The Conscientious Objector
		939, // The Bat Outta Hell
	];

	info!("inventory has {} items", inventory.items.len());
	let inelligible_weapons = inventory.items.iter()
		.filter(|item| item.is_weapon(&schema) && (item.quality != Quality::Unique || item.flag_cannot_craft || item.flag_cannot_trade || schema.get_item(item.defindex).unwrap().name.starts_with("Festive")))
		.collect::<Vec<_>>();
	info!("inventory has {} inelligible weapons (not craftable, not tradable, festive, or not unique)", inelligible_weapons.len());
	let unique_weapons = inventory.items.iter()
		.filter(|item| item.quality == Quality::Unique && item.is_weapon(&schema))
		.collect::<Vec<_>>();
	info!("inventory has {} unique quality weapons", unique_weapons.len());
	let craftable_weapons = unique_weapons.iter().filter(|item| !item.flag_cannot_craft && !item.flag_cannot_trade).collect::<Vec<_>>();
	info!("inventory has {} weapons craftable into metal", craftable_weapons.len());
	let mut quantities = HashMap::new();
	for item in craftable_weapons {
		if valuable_uniques.contains(&item.defindex) {
			continue
		}
		if schema.get_item(item.defindex).unwrap().name.starts_with("Festive") {
			continue
		}
		quantities.entry(item.defindex).or_insert(Vec::new()).push(item)
	}
	for (defindex, items) in &quantities {
		let schemaitem = schema.get_item(*defindex).unwrap();
		println!("Item({}): {} - {}", defindex, schemaitem.name, items.len());
	}
	let mut dupes: HashMap<_, _> = quantities.iter().filter(|(defindex, items)| items.len() >= 2).collect();
	// // remove an instance so that we keep 1 of each weapon
	// for (defindex, items) in dupes.iter_mut() {
	// 	items.truncate(items.len() - 1);
	// }
	println!("Duplicates - safe to craft into metal");
	for (defindex, items) in &dupes {
		let schemaitem = schema.get_item(**defindex).unwrap();
		println!("Item({}): {} - {}", defindex, schemaitem.name, items.len());
	}


	Ok(())
}

