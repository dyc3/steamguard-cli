use anyhow::Context;
use log::*;
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Clone, Parser, Default)]
pub struct GuiCommand;

impl GuiCommand {
	pub(crate) fn execute<T>(
		self,
		transport: T,
		manager: AccountManager,
		args: &GlobalArgs,
	) -> anyhow::Result<()>
	where
		T: Transport + 'static,
	{
		info!("Starting GUI");

		let native_options = eframe::NativeOptions {
			initial_window_size: Some([400.0, 300.0].into()),
			min_window_size: Some([300.0, 220.0].into()),
			..Default::default()
		};
		let args = args.clone();
		if let Err(e) = eframe::run_native(
			"steamguard",
			native_options,
			Box::new(|cc| Box::new(Gui::new(cc, transport, manager, self, args))),
		) {
			error!("Failed to start gui: {}", e);
		}

		Ok(())
	}
}

struct Gui<T> {
	transport: T,
	manager: AccountManager,
	args: GuiCommand,
	globalargs: GlobalArgs,

	selected_account: usize,
}

impl<'g, T> Gui<T> {
	fn new(
		_ctx: &eframe::CreationContext<'_>,
		transport: T,
		manager: AccountManager,
		args: GuiCommand,
		globalargs: GlobalArgs,
	) -> Self {
		let first_entry = manager.iter().next().unwrap().account_name.clone();

		Self {
			transport,
			manager,
			args,
			globalargs,

			selected_account: 0,
		}
	}
}

impl<'g, T> eframe::App for Gui<T>
where
	T: Transport,
{
	fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
		egui::CentralPanel::default().show(ctx, |ui| {
			let selected_account = self
				.manager
				.iter()
				.nth(self.selected_account)
				.unwrap()
				.account_name
				.clone();
			egui::ComboBox::from_label("Account")
				.selected_text(&selected_account)
				.show_ui(ui, |ui| {
					for (i, entry) in self.manager.iter().enumerate() {
						ui.selectable_value(
							&mut self.selected_account,
							i,
							entry.account_name.clone(),
						);
					}
				});
		});
	}
}
