use std::{fs::File, collections::HashMap, time::Duration};

use log::*;
use clap::Parser;
use metalmann::{inventory::{Tf2Inventory, Tf2InventoryItem}, tf2meta::Quality, schema::Tf2Schema, crafting::Crafter};
use steamguard::{SteamGuardAccount, ExposeSecret};

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

	info!("loading steamguard account");
	let account_file = File::open(args.steamguard_account)?;
	let account = SteamGuardAccount::from_reader(account_file)?;
	let steamid = account.session.as_ref().unwrap().expose_secret().steam_id; // TODO: make steam id accessible from SteamGuardAccount, don't require going into session to grab it.
	info!("steamguard account loaded: {}, steadid: {}", account.account_name, steamid);

	let schema = load_schema(args.prefer_cached)?;
	info!("schema last modified: {:?}", schema.last_modified);

	let inventory = load_inventory(steamid, args.prefer_cached)?;

	let valuable_uniques: Vec<u32> = vec![
		264, // Frying Pan
		474, // The Conscientious Objector
		939, // The Bat Outta Hell
		851, // The AWPer Hand
		880, // The Freedom Staff
		574, // The Wanga Prick
		1127, // The Crossing Guard
		947, // The Quackenbirdt
	];

	info!("inventory has {} items", inventory.items.len());
	let inelligible_weapons = inventory.items.iter()
		.filter(|item| item.is_weapon(&schema) && (item.quality != Quality::Unique || item.flag_cannot_craft || item.flag_cannot_trade || schema.get_item(item.defindex).unwrap().name.starts_with("Festive")))
		.cloned()
		.collect::<Vec<_>>();
	info!("inventory has {} inelligible weapons (not craftable, not tradable, festive, or not unique)", inelligible_weapons.len());
	let unique_weapons = inventory.items.iter()
		.filter(|item| item.quality == Quality::Unique && item.is_weapon(&schema))
		.cloned()
		.collect::<Vec<_>>();
	info!("inventory has {} unique quality weapons", unique_weapons.len());
	let craftable_weapons = unique_weapons.iter()
		.filter(|item| !item.flag_cannot_craft && !item.flag_cannot_trade)
		.cloned()
		.collect::<Vec<_>>();
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
	let mut inelligible_dupes: HashMap<u32, Vec<Tf2InventoryItem>> = HashMap::new();
	for item in inelligible_weapons {
		inelligible_dupes.entry(item.defindex).or_insert(Vec::new()).push(item)
	}
	println!("Inelligible Duplicates - Makes unique weapons of the same kind elligible to craft");
	for (defindex, items) in &inelligible_dupes {
		let schemaitem = schema.get_item(*defindex).unwrap();
		for item in items {
			print!("Item({}): {} {} ", defindex, item.quality, schemaitem.name);
			if item.quality == Quality::Unique {
				if item.flag_cannot_craft {
					print!("uncraftable ");
				}
				else if item.flag_cannot_trade {
					print!("untradable ");
				}
			}
			println!();
		}
	}
	let mut dupes: HashMap<u32, Vec<Tf2InventoryItem>> = HashMap::new();
	for (defindex, items) in quantities.iter_mut() {
		if inelligible_dupes.contains_key(&defindex) {
			dupes.insert(*defindex, items.to_vec());
		} else {
			if items.len() >= 2 {
				items.truncate(items.len() - 1);
			}
			if items.len() > 1 {
				dupes.insert(*defindex, items.to_vec());
			}
		}
	}
	println!("Duplicates - safe to craft into metal");
	for (defindex, items) in &dupes {
		let schemaitem = schema.get_item(*defindex).unwrap();
		println!("Item({}): {} - {}", defindex, schemaitem.name, items.len());
	}


	println!("Group by same class");
	let craftables = dupes.into_values().into_iter().flatten().collect::<Vec<_>>();
	let mut grouped = HashMap::new();
	for item in craftables {
		let schemaitem = schema.get_item(item.defindex).unwrap();
		if let Some(used_by) = &schemaitem.used_by_classes {
			if used_by.len() > 1 {
				warn!("unsupported Item({}) {}, used by more than one class", item.defindex, schemaitem.name);
				continue
			}
			grouped.entry(used_by[0]).or_insert(Vec::new()).push(item);
		} else {
			warn!("unsupported Item({}) {}, used by all classes", item.defindex, schemaitem.name);
			continue;
		}
	}
	for (class, items) in &grouped {
		println!("Class({}): {}", class, items.len());
	}

	println!("Create pairs");
	let mut pairs: Vec<[Tf2InventoryItem; 2]> = Vec::new();
	for (_class, items) in grouped.into_iter() {
		for chunk in items.chunks_exact(2).into_iter() {
			let mut c = Vec::from(chunk).into_iter();
			let first = c.next().unwrap();
			let second = c.next().unwrap();
			pairs.push([first, second]);
		}
	}
	for pair in &pairs {
		for item in pair {
			let schemaitem = schema.get_item(item.defindex).unwrap();
			print!("Item({}) {} ", item.defindex, schemaitem.name);
		}
		println!()
	}

	if pairs.len() == 0 {
		warn!("No valid pairs to craft, aborting!");
		return Ok(());
	}

	// return Ok(());

	let mut crafter = Crafter::from_steam_guard_account(account, args.steam_account_password);
	crafter.init()?;
	crafter.set_game(440)?;
	std::thread::sleep(Duration::from_secs(5));
	crafter.gc_hello()?;
	std::thread::sleep(Duration::from_secs(5));
	crafter.craft_items(metalmann::crafting::ECraftingRecipe::SmeltClassWeapons, pairs[0].iter().map(|i| i.id).collect())?;
	std::thread::sleep(Duration::from_secs(120));

	Ok(())
}

/// Handles loading a user's inventory, or using a cached version.
fn load_inventory(steamid: u64, prefer_cached: bool) -> anyhow::Result<Tf2Inventory> {
	let inventory_cache_path = format!("{}/metalmann/inventory/", dirs::cache_dir().unwrap().to_str().unwrap());
	std::fs::create_dir_all(&inventory_cache_path)?;
	let inventory_cache_path = format!("{}/{}.json", inventory_cache_path, steamid);

	if prefer_cached {
		match File::open(&inventory_cache_path) {
			Ok(cache_file) => {
				return Ok(Tf2Inventory::from_reader(cache_file)?);
			}
			Err(err) => {
				warn!("Could not load inventory from cache: {}", err);
			}
		}
	}

	info!("Fetching inventory for {} from remote", steamid);
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
	Ok(inventory)
}

/// Handles loading the item schema, or using a cached version.
fn load_schema(prefer_cached: bool) -> anyhow::Result<Tf2Schema> {
	info!("loading item schema");
	let schema_cache_path = format!("{}/metalmann/", dirs::cache_dir().unwrap().to_str().unwrap());
	std::fs::create_dir_all(&schema_cache_path)?;
	let schema_cache_path = format!("{}/schema.json", schema_cache_path);
	let cached_schema = match File::open(&schema_cache_path) {
		Ok(schema_file) => {
			Some(Tf2Schema::from_reader(schema_file)?)
		}
		Err(_) => None,
	};

	let last_modified = match &cached_schema {
		Some(c) => c.last_modified,
		_ => None,
	};

	if prefer_cached && cached_schema.is_some() {
		info!("Using cached item schema");
		return Ok(cached_schema.unwrap());
	}

	let schema = match metalmann::schema::fetch_item_schema(last_modified) {
		Ok(s) => {
			let w = File::create(schema_cache_path)?;
			s.write_to(w)?;
			s
		},
		Err(err) => {
			if cached_schema.is_some() {
				warn!("failed to fetch schema: {} -- using cached version instead", err);
				cached_schema.unwrap()
			} else {
				error!("failed to fetch schema, and no cache exists: {}", err);
				return Err(err.into());
			}
		}
	};
	Ok(schema)
}

