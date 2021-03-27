extern crate rpassword;
use io::Write;
use steamguard_cli::*;
use ::std::*;
use text_io::read;
use std::path::Path;
use clap::{App, Arg, crate_version};

mod steamapi;
mod accountmanager;

fn main() {
	let matches = App::new("steamguard-cli")
		.version(crate_version!())
		.bin_name("steamguard")
		.author("dyc3 (Carson McManus)")
		.about("Generate Steam 2FA codes and confirm Steam trades from the command line.")
		.arg(
			Arg::with_name("username")
				.long("username")
				.short("u")
				.help("Select the account you want by steam username. By default, the first account in the manifest is selected.")
		)
		.arg(
			Arg::with_name("all")
				.long("all")
				.short("a")
				.help("Select all accounts in the manifest.")
		)
		.arg(
			Arg::with_name("mafiles-path")
				.long("mafiles-path")
				.short("m")
				.default_value("~/maFiles")
				.help("Specify which folder your maFiles are in.")
		)
		.arg(
			Arg::with_name("passkey")
				.long("passkey")
				.short("p")
				.help("Specify your encryption passkey.")
		)
		.subcommand(
			App::new("trade")
				.about("Interactive interface for trade confirmations")
				.arg(
					Arg::with_name("accept-all")
					.short("a")
					.long("accept-all")
					.help("Accept all open trade confirmations. Does not open interactive interface.")
				)
		)
		.get_matches();

	println!("Hello, world!");

	// let server_time = steamapi::get_server_time();
	// println!("server time: {}", server_time);

	// let mut account = SteamGuardAccount::new();
	// account.shared_secret = parse_shared_secret(String::from("K5I0Fmm+sN0yF41vIslTVm+0nPE="));

	// let code = account.generate_code(server_time);
	// println!("{}", code);

	// print!("Username: ");
	// let _ = std::io::stdout().flush();
	// let username: String = read!("{}\n");
	// let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	// // println!("{}:{}", username, password);
	// let login = steamapi::UserLogin::new(username, password);
	// let result = login.login();
	// println!("result: {:?}", result);

	let path = Path::new("test_maFiles/manifest.json");
	let manifest = accountmanager::Manifest::load(path);
	println!("{:?}", manifest);
	match manifest {
		Ok(mut m) => {
			m.load_accounts();
			for account in m.accounts {
				println!("{:?}", account);
				let server_time = steamapi::get_server_time();
				let code = account.generate_code(server_time);
				println!("{}", code);
			}
		}
		Err(e) => {
			println!("{}", e)
		}
	}
}
