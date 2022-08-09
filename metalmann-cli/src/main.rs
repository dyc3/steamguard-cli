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
	println!("{:?}", schema);

	Ok(())
}

