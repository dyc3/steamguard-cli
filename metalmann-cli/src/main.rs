use log::*;
use clap::Parser;

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

	let inventory = metalmann::inventory::fetch_inventory(76561198054667933)?; // me, dyc3

	println!("{:?}", inventory);

	Ok(())
}

