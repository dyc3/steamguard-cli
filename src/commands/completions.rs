use clap::CommandFactory;

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Generate shell completions")]
pub struct CompletionsCommand {
	#[clap(
		short,
		long,
		value_enum,
		help = "The shell to generate completions for."
	)]
	pub shell: Shell,
}

impl ConstCommand for CompletionsCommand {
	fn execute(&self) -> anyhow::Result<()> {
		let mut app = Args::command_for_update();
		clap_complete::generate(self.shell, &mut app, "steamguard", &mut std::io::stdout());
		Ok(())
	}
}
