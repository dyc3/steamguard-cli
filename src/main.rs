use steamguard_cli::*;

fn main() {
	println!("Hello, world!");

	let mut account = SteamGuardAccount::new();
	account.shared_secret = parse_shared_secret(String::from("K5I0Fmm+sN0yF41vIslTVm+0nPE="));

	let code = account.generate_code(93847539487i64);
	println!("{}", code)
}
