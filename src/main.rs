extern crate rpassword;
use io::Write;
use steamguard_cli::*;
use ::std::*;
use text_io::read;

mod steamapi;

fn main() {
	println!("Hello, world!");

	let server_time = steamapi::get_server_time();
	println!("server time: {}", server_time);

	let mut account = SteamGuardAccount::new();
	account.shared_secret = parse_shared_secret(String::from("K5I0Fmm+sN0yF41vIslTVm+0nPE="));

	let code = account.generate_code(server_time);
	println!("{}", code);

	print!("Username: ");
	let _ = std::io::stdout().flush();
	let username: String = read!("{}\n");
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	// println!("{}:{}", username, password);
	let login = steamapi::UserLogin::new(username, password);
	let result = login.login();
	println!("result: {:?}", result);
}
