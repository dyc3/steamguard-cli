use anyhow::Context;
use crossterm::{
	cursor,
	event::{Event, KeyCode, KeyEvent, KeyModifiers},
	execute,
	style::{Color, Print, PrintStyledContent, SetForegroundColor, Stylize},
	terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
	QueueableCommand,
};
use log::debug;
use secrecy::SecretString;
use std::collections::HashSet;
use std::io::{stderr, stdout, Write};
use std::sync::{Arc, OnceLock, RwLock};
use steamguard::Confirmation;

use crate::prompt_backend::{ChoiceOption, PromptBackend};

pub(crate) struct TuiPromptBackend;

impl PromptBackend for TuiPromptBackend {
	fn prompt_text(&self, prompt_text: &str, allow_empty: bool) -> String {
		if allow_empty {
			prompt_allow_empty_impl(prompt_text)
		} else {
			prompt_non_empty_impl(prompt_text)
		}
	}

	fn choose(&self, prompt_text: &str, choices: &[ChoiceOption<'_>]) -> String {
		prompt_choice_loop(prompt_text, choices)
	}

	fn select_confirmations(
		&self,
		confirmations: Vec<Confirmation>,
	) -> anyhow::Result<(Vec<Confirmation>, Vec<Confirmation>)> {
		prompt_confirmation_menu_impl(confirmations)
	}

	fn prompt_secret(
		&self,
		prompt_text: &str,
		context: &str,
		allow_empty: bool,
	) -> anyhow::Result<SecretString> {
		prompt_secret_impl(prompt_text, context, allow_empty)
	}
}

fn prompt_backend_cell() -> &'static RwLock<Arc<dyn PromptBackend>> {
	static PROMPT_BACKEND: OnceLock<RwLock<Arc<dyn PromptBackend>>> = OnceLock::new();
	PROMPT_BACKEND.get_or_init(|| RwLock::new(Arc::new(TuiPromptBackend)))
}

fn prompt_backend() -> Arc<dyn PromptBackend> {
	prompt_backend_cell()
		.read()
		.expect("failed to read prompt backend")
		.clone()
}

#[allow(dead_code)]
pub(crate) fn with_prompt_backend<R>(
	backend: Arc<dyn PromptBackend>,
	run: impl FnOnce() -> R,
) -> R {
	let previous = {
		let mut current = prompt_backend_cell()
			.write()
			.expect("failed to write prompt backend");
		std::mem::replace(&mut *current, backend)
	};

	let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
	*prompt_backend_cell()
		.write()
		.expect("failed to write prompt backend") = previous;

	match result {
		Ok(value) => value,
		Err(payload) => std::panic::resume_unwind(payload),
	}
}

/// Prompt the user for text input.
pub(crate) fn prompt() -> String {
	prompt_backend().prompt_text("", true)
}

fn prompt_impl() -> String {
	stdout().flush().expect("failed to flush stdout");
	stderr().flush().expect("failed to flush stderr");

	let mut line = String::new();
	while let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
		match code {
			KeyCode::Enter => {
				eprintln!();
				break;
			}
			KeyCode::Char(c) => {
				line.push(c);
				eprint!("{}", c);
				let _ = stderr().flush();
			}
			KeyCode::Backspace => {
				if !line.is_empty() {
					line.pop();

					eprint!("\x08 \x08");
					let _ = stderr().flush();
				}
			}
			_ => {}
		}
	}

	line
}

pub(crate) fn prompt_allow_empty(prompt_text: impl AsRef<str>) -> String {
	prompt_backend().prompt_text(prompt_text.as_ref(), true)
}

fn prompt_allow_empty_impl(prompt_text: &str) -> String {
	eprint!("{}", prompt_text);
	prompt_impl()
}

pub(crate) fn prompt_non_empty(prompt_text: impl AsRef<str>) -> String {
	prompt_backend().prompt_text(prompt_text.as_ref(), false)
}

fn prompt_non_empty_impl(prompt_text: &str) -> String {
	loop {
		eprint!("{}", prompt_text);
		let input = prompt_impl();
		if !input.is_empty() {
			return input;
		}
	}
}

/// Prompt the user for a single character response. Useful for asking yes or no questions.
///
/// `chars` should be all lowercase characters, with at most 1 uppercase character. The uppercase character is the default answer if no answer is provided.
/// The selected character returned will always be lowercase.
pub(crate) fn prompt_char(text: &str, chars: &str) -> char {
	let options = parse_prompt_char_options(chars);
	let choices = options
		.iter()
		.map(|option| ChoiceOption {
			id: &option.id,
			label: &option.label,
			is_default: option.is_default,
		})
		.collect::<Vec<_>>();

	let selected = prompt_backend().choose(text, &choices);
	let mut chars = selected.chars();
	let answer = chars
		.next()
		.expect("prompt backend returned an empty choice");
	assert!(
		chars.next().is_none(),
		"prompt backend returned a multi-character choice"
	);
	answer.to_ascii_lowercase()
}

fn prompt_choice_loop(text: &str, choices: &[ChoiceOption<'_>]) -> String {
	let choice_labels = choices
		.iter()
		.map(|choice| choice.label)
		.collect::<Vec<_>>()
		.join("");

	loop {
		let _ = stderr().queue(Print(format!("{} [{}] ", text, choice_labels)));
		let _ = stderr().flush();
		let input = prompt_impl();
		if let Ok(choice) = prompt_choice_impl(input, choices) {
			return choice;
		}
	}
}

fn prompt_choice_impl(input: impl Into<String>, choices: &[ChoiceOption<'_>]) -> anyhow::Result<String> {
	if choices.iter().filter(|choice| choice.is_default).count() > 1 {
		panic!("Invalid chars for prompt_char. Maximum 1 uppercase letter is allowed.");
	}

	let answer: String = input.into().to_ascii_lowercase();

	if answer.is_empty() {
		if let Some(default_choice) = choices.iter().find(|choice| choice.is_default) {
			return Ok(default_choice.id.to_owned());
		} else {
			bail!("no valid answer")
		}
	}

	if choices
		.iter()
		.any(|choice| choice.id.eq_ignore_ascii_case(&answer))
	{
		return Ok(answer);
	}

	bail!("no valid answer")
}

struct PromptCharOption {
	id: String,
	label: String,
	is_default: bool,
}

fn parse_prompt_char_options(chars: &str) -> Vec<PromptCharOption> {
	let options = chars
		.chars()
		.map(|choice| PromptCharOption {
			id: choice.to_ascii_lowercase().to_string(),
			label: choice.to_string(),
			is_default: choice.is_ascii_uppercase(),
		})
		.collect::<Vec<_>>();

	if options.iter().filter(|option| option.is_default).count() > 1 {
		panic!("Invalid chars for prompt_char. Maximum 1 uppercase letter is allowed.");
	}

	options
}

#[cfg(test)]
fn prompt_char_impl(input: impl Into<String>, chars: &str) -> anyhow::Result<char> {
	let options = parse_prompt_char_options(chars);
	let choices = options
		.iter()
		.map(|option| ChoiceOption {
			id: &option.id,
			label: &option.label,
			is_default: option.is_default,
		})
		.collect::<Vec<_>>();
	let answer = prompt_choice_impl(input, &choices)?;
	if answer.len() > 1 {
		bail!("answer too long")
	}
	Ok(answer.chars().next().expect("answer should not be empty"))
}

/// Returns a tuple of (accepted, denied). Ignored confirmations are not included.
pub(crate) fn prompt_confirmation_menu(
	confirmations: Vec<Confirmation>,
) -> anyhow::Result<(Vec<Confirmation>, Vec<Confirmation>)> {
	prompt_backend().select_confirmations(confirmations)
}

fn prompt_confirmation_menu_impl(
	confirmations: Vec<Confirmation>,
) -> anyhow::Result<(Vec<Confirmation>, Vec<Confirmation>)> {
	if confirmations.is_empty() {
		return Ok((vec![], vec![]));
	}

	let mut to_accept_idx: HashSet<usize> = HashSet::new();
	let mut to_deny_idx: HashSet<usize> = HashSet::new();

	execute!(stdout(), EnterAlternateScreen)?;
	crossterm::terminal::enable_raw_mode()?;

	let mut selected_idx = 0;

	loop {
		execute!(
			stdout(),
			Clear(ClearType::All),
			cursor::MoveTo(1, 1),
			PrintStyledContent(
				"arrow keys to select, [a]ccept, [d]eny, [i]gnore, [enter] confirm choices\n\n"
					.white()
			),
		)?;

		for (i, conf) in confirmations.iter().enumerate() {
			stdout().queue(Print("\r"))?;
			if selected_idx == i {
				stdout().queue(SetForegroundColor(Color::Yellow))?;
				stdout().queue(Print(" >"))?;
			} else {
				stdout().queue(SetForegroundColor(Color::White))?;
				stdout().queue(Print("  "))?;
			}

			if to_accept_idx.contains(&i) {
				stdout().queue(SetForegroundColor(Color::Green))?;
				stdout().queue(Print("[a]"))?;
			} else if to_deny_idx.contains(&i) {
				stdout().queue(SetForegroundColor(Color::Red))?;
				stdout().queue(Print("[d]"))?;
			} else {
				stdout().queue(Print("[ ]"))?;
			}

			if selected_idx == i {
				stdout().queue(SetForegroundColor(Color::Yellow))?;
			}

			stdout().queue(Print(format!(" {}\n", conf.description())))?;
		}

		stdout().flush()?;

		match crossterm::event::read()? {
			Event::Resize(_, _) => continue,
			Event::Key(KeyEvent {
				code: KeyCode::Char('a'),
				..
			}) => {
				to_accept_idx.insert(selected_idx);
				to_deny_idx.remove(&selected_idx);
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('d'),
				..
			}) => {
				to_accept_idx.remove(&selected_idx);
				to_deny_idx.insert(selected_idx);
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('i'),
				..
			}) => {
				to_accept_idx.remove(&selected_idx);
				to_deny_idx.remove(&selected_idx);
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('A'),
				..
			}) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.insert(i);
					to_deny_idx.remove(&i);
				});
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('D'),
				..
			}) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.remove(&i);
					to_deny_idx.insert(i);
				});
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('I'),
				..
			}) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.remove(&i);
					to_deny_idx.remove(&i);
				});
			}
			Event::Key(KeyEvent {
				code: KeyCode::Up, ..
			}) if selected_idx > 0 => {
				selected_idx -= 1;
			}
			Event::Key(KeyEvent {
				code: KeyCode::Down,
				..
			}) if selected_idx < confirmations.len() - 1 => {
				selected_idx += 1;
			}
			Event::Key(KeyEvent {
				code: KeyCode::Enter,
				..
			}) => {
				break;
			}
			Event::Key(KeyEvent {
				code: KeyCode::Esc, ..
			})
			| Event::Key(KeyEvent {
				code: KeyCode::Char('c'),
				modifiers: KeyModifiers::CONTROL,
			}) => {
				return Ok((vec![], vec![]));
			}
			_ => {}
		}
	}

	execute!(stdout(), LeaveAlternateScreen)?;
	crossterm::terminal::disable_raw_mode()?;

	Ok((
		to_accept_idx
			.iter()
			.map(|i| confirmations[*i].clone())
			.collect(),
		to_deny_idx
			.iter()
			.map(|i| confirmations[*i].clone())
			.collect(),
	))
}

pub(crate) fn pause() {
	pause_impl();
}

fn pause_impl() {
	let _ = write!(stderr(), "Press enter to continue...");
	let _ = stderr().flush();
	loop {
		match crossterm::event::read().expect("could not read terminal events") {
			Event::Key(KeyEvent {
				code: KeyCode::Enter,
				..
			}) => break,
			_ => continue,
		}
	}
}

pub(crate) fn prompt_secret_non_empty(
	prompt_text: &str,
	context: &str,
) -> anyhow::Result<SecretString> {
	prompt_backend().prompt_secret(prompt_text, context, false)
}

fn prompt_secret_impl(
	prompt_text: &str,
	context: &str,
	allow_empty: bool,
) -> anyhow::Result<SecretString> {
	loop {
		let raw = rpassword::prompt_password(prompt_text).with_context(|| context.to_owned())?;
		if allow_empty || !raw.is_empty() {
			return Ok(SecretString::new(raw));
		}
	}
}

pub(crate) fn prompt_passkey() -> anyhow::Result<SecretString> {
	debug!("prompting for passkey");
	prompt_secret_non_empty("Enter encryption passkey: ", "prompting for passkey")
}

pub(crate) fn prompt_password() -> anyhow::Result<SecretString> {
	debug!("prompting for password");
	prompt_secret_non_empty("Password: ", "prompting for password")
}

#[cfg(test)]
mod prompt_char_tests {
	use super::*;

	#[test]
	fn test_gives_answer() {
		let answer = prompt_char_impl("y", "yn").unwrap();
		assert_eq!(answer, 'y');
	}

	#[test]
	fn test_gives_default() {
		let answer = prompt_char_impl("", "Yn").unwrap();
		assert_eq!(answer, 'y');
	}

	#[test]
	fn test_should_not_give_default() {
		let answer = prompt_char_impl("n", "Yn").unwrap();
		assert_eq!(answer, 'n');
	}

	#[test]
	fn test_should_not_give_invalid() {
		let answer = prompt_char_impl("g", "yn");
		assert!(answer.is_err());
		let answer = prompt_char_impl("n", "yn").unwrap();
		assert_eq!(answer, 'n');
	}

	#[test]
	fn test_should_not_give_multichar() {
		let answer = prompt_char_impl("yy", "yn");
		assert!(answer.is_err());
	}
}
