use secrecy::SecretString;
use steamguard::Confirmation;

pub(crate) struct ChoiceOption<'a> {
	pub(crate) id: &'a str,
	pub(crate) label: &'a str,
	pub(crate) is_default: bool,
}

pub(crate) trait PromptBackend: Send + Sync {
	fn prompt_text(&self, prompt_text: &str, allow_empty: bool) -> String;
	fn choose(&self, prompt_text: &str, choices: &[ChoiceOption<'_>]) -> String;
	fn select_confirmations(
		&self,
		confirmations: Vec<Confirmation>,
	) -> anyhow::Result<(Vec<Confirmation>, Vec<Confirmation>)>;
	fn prompt_secret(
		&self,
		prompt_text: &str,
		context: &str,
		allow_empty: bool,
	) -> anyhow::Result<SecretString>;
}
