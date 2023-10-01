use std::collections::HashMap;

use anyhow::Context;
use log::*;
use serde::{Deserialize, Serialize};
use steamguard::{Confirmation, Confirmer, ConfirmerError};

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
		T: Transport + Clone + Send + 'static,
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
	mfa_codes: HashMap<usize, String>,
	confirmations: Arc<Mutex<HashMap<usize, Result<Vec<Confirmation>, ConfirmerError>>>>,

	confirmations_job: Option<std::thread::JoinHandle<Result<Vec<Confirmation>, ConfirmerError>>>,
}

impl<'g, T> Gui<T> {
	fn new(
		_ctx: &eframe::CreationContext<'_>,
		transport: T,
		manager: AccountManager,
		args: GuiCommand,
		globalargs: GlobalArgs,
	) -> Self {
		Self {
			transport,
			manager,
			args,
			globalargs,

			selected_account: Default::default(),
			mfa_codes: Default::default(),
			confirmations: Default::default(),

			confirmations_job: None,
		}
	}
}

impl<'g, T> eframe::App for Gui<T>
where
	T: Transport + Clone + Send + 'static,
{
	fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
		egui::CentralPanel::default().show(ctx, |ui| {
			let selected_account_name = self
				.manager
				.iter()
				.nth(self.selected_account)
				.unwrap()
				.account_name
				.clone();
			egui::ComboBox::from_label("Account")
				.selected_text(&selected_account_name)
				.show_ui(ui, |ui| {
					for (i, entry) in self.manager.iter().enumerate() {
						ui.selectable_value(
							&mut self.selected_account,
							i,
							entry.account_name.clone(),
						);
					}
				});

			let account = self
				.manager
				.get_or_load_account(&selected_account_name)
				.unwrap();
			let mut code = account.lock().unwrap().generate_code(
				std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
			);

			egui::TextEdit::singleline(&mut code)
				.interactive(false)
				.show(ui);

			ui.add(egui::Separator::default());

			if ui.button("Check Confirmations").clicked() {
				let transport = self.transport.clone();
				let account = account.clone();
				let ctx = ctx.clone();
				self.confirmations_job = Some(std::thread::spawn(move || {
					let result = job_fetch_confirmations(transport, account);
					ctx.request_repaint();
					result
				}));
			}

			if self
				.confirmations_job
				.as_ref()
				.is_some_and(|j| j.is_finished())
			{
				debug!("confirmations job finished");
				let job = self.confirmations_job.take().unwrap();
				let confirmations = job.join().unwrap();
				self.confirmations
					.lock()
					.unwrap()
					.insert(self.selected_account, confirmations);
			} else if self.confirmations_job.is_some() {
				ui.spinner();
			} else {
				let confirmations = self.confirmations.lock().unwrap();
				if let Some(confirmations) = confirmations.get(&self.selected_account) {
					match confirmations {
						Ok(confirmations) => {
							if !confirmations.is_empty() {
								for confirmation in confirmations {
									ui.label(format!("{:?}", confirmation));
								}
							} else {
								ui.label("No confirmations");
							}
						}
						Err(e) => {
							ui.label(format!("Error: {}", e));
						}
					}
				}
			}
		});
	}
}

fn job_fetch_confirmations<T>(
	transport: T,
	account: Arc<Mutex<SteamGuardAccount>>,
) -> Result<Vec<Confirmation>, ConfirmerError>
where
	T: Transport + Clone,
{
	let account = account.lock().unwrap();
	let confirmer = Confirmer::new(transport.clone(), &account);
	confirmer.get_trade_confirmations()
}
