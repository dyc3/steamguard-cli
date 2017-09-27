using Newtonsoft.Json;
using SteamAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SteamGuard
{
	public static class Program
	{
		public const string defaultSteamGuardPath = "~/maFiles";

		public static string SteamGuardPath { get; set; } = defaultSteamGuardPath;
		public static Manifest Manifest { get; set; }
		public static SteamGuardAccount[] SteamGuardAccounts { get; set; }
		public static bool Verbose { get; set; } = false;

		/// <summary>
		///   The main entry point for the application
		/// </summary>
		[STAThread]
		public static void Main(string[] args)
		{
			string action = "";
			string user = "";
			string passkey = "";

			// Parse cli arguments
			for (int i = 0; i < args.Length; i++)
			{
				if (args[i].StartsWith("-"))
				{
					// TODO: there's gotta be some framework or tool or something for this
					if (args[i] == "-v" || args[i] == "--verbose")
					{
						Verbose = true;
					}
					else if (args[i] == "-m" || args[i] == "--mafiles-path")
					{
						i++;
						if (i < args.Length)
						{
							SteamGuardPath = args[i];
						}
						else
						{
							Console.WriteLine($"Expected path after {args[i-1]}");
							return;
						}
					}
					else if (args[i] == "-p" || args[i] == "--passkey")
					{
						i++;
						if (i < args.Length)
						{
							passkey = args[i];
						}
						else
						{
							Console.WriteLine($"Expected encryption passkey after {args[i-1]}");
							return;
						}
					}
					else if (args[i] == "--help" || args[i] == "-h")
					{
						ShowHelp();
						return;
					}
				}
				else // Parse as action or username
				{
					if (string.IsNullOrEmpty(action))
					{
						if (args[i] == "add" || args[i] == "setup")
						{
							action = "setup";
						}
						else if (args[i] == "trade")
						{
							action = "trade";
						}
						else if (args[i] == "encrypt")
						{
							action = "encrypt";
						}
						else if (args[i] == "decrypt")
						{
							action = "decrypt";
						}
						else if (args[i] == "remove")
						{
							action = "remove";
						}
						else if (args[i] == "2fa" || args[i] == "code" || args[i] == "generate-code")
						{
							action = "generate-code";
						}
						else if (args[i] == "accept-all")
						{
							action = "accept-all";
						}
						else if (string.IsNullOrEmpty(user))
						{
							user = args[i];
						}
					}
					else if (string.IsNullOrEmpty(user))
					{
						user = args[i];
					}
				}
			}

			if (string.IsNullOrEmpty(action))
			{
				action = "generate-code";
			}

			// Do some configuring
			SteamGuardPath = SteamGuardPath.Replace("~", Environment.GetEnvironmentVariable("HOME"));
			if (!Directory.Exists(SteamGuardPath))
			{
				if (SteamGuardPath == defaultSteamGuardPath.Replace("~", Environment.GetEnvironmentVariable("HOME")))
				{
					if (Verbose) Console.WriteLine("warn: {0} does not exist, creating...", SteamGuardPath);
					Directory.CreateDirectory(SteamGuardPath);
				}
				else
				{
					Console.WriteLine("error: {0} does not exist.", SteamGuardPath);
					return;
				}
			}

			if (Verbose)
			{
				Console.WriteLine($"Action: {action}");
				Console.WriteLine($"User: {user}");
				Console.WriteLine($"Passkey: {passkey}");
				Console.WriteLine($"maFiles path: {SteamGuardPath}");
			}

			// Perform desired action
			switch (action)
			{
				case "generate-code":
					GenerateCode(user, passkey);
					break;
				case "encrypt": // Can also be used to change passkey
					Console.WriteLine(Encrypt(passkey));
					break;
				case "decrypt":
					Console.WriteLine(Decrypt(passkey));
					break;
				case "setup":
					Setup(user, passkey);
					break;
				case "trade":
					Trade(user, passkey);
					break;
				case "accept-all":
					AcceptAllTrades(user, passkey);
					break;
				default:
					Console.WriteLine("error: Unknown action: {0}", action);
					return;
			}
		}

		static void ShowHelp()
		{
			var descPadding = 26;
			var descWidth = Console.BufferWidth - descPadding;
			if (descWidth < 20)
				descWidth = 20;

			var flags = new Dictionary<string, string>
			{
				{ "-h, --help", "Display this help message." },
				{ "-v, --verbose", "Display some extra information when the program is running." },
				{ "-m, --mafiles-path", "Specify which folder your maFiles are in. Ex: ~/maFiles" },
				{ "-p, --passkey", "Specify your encryption passkey." },
			};
			var actions = new Dictionary<string, string>
			{
				{ "generate-code", "Generate a Steam Guard code for the specified user (if any) and exit. (default)" },
				{ "encrypt", "Encrypt your maFiles or change your encryption passkey." },
				{ "decrypt", "Remove encryption from your maFiles." },
				{ "code", "Same as generate-code" },
				{ "2fa", "Same as generate-code" },
				{ "add", "Set up Steam Guard for 2 factor authentication." },
				{ "setup", "Same as add" },
				{ "trade", "Opens an interactive prompt to handle trade confirmations." },
				{ "accept-all", "Accepts all trade confirmations." }
			};

			Console.WriteLine($"steamguard-cli - v{Assembly.GetExecutingAssembly().GetName().Version}");
			Console.WriteLine("usage: steamguard ACTION [STEAM USERNAME] [OPTIONS]...");
			Console.WriteLine();
			foreach (var flag in flags)
			{
				// word wrap the descriptions, if needed
				var desc = flag.Value;
				if (desc.Length > descWidth)
				{
					var sb = new StringBuilder();
					for (int i = 0; i < desc.Length; i += descWidth)
					{
						if (i > 0)
							sb.Append("".PadLeft((flag.Key.StartsWith("--") ? 5 : 2) + descPadding));
						sb.AppendLine(desc.Substring(i, i + descWidth > desc.Length ? desc.Length - i : descWidth).Trim());
					}
					desc = sb.ToString().TrimEnd('\n');
				}
				Console.WriteLine($"{(flag.Key.StartsWith("--") ? "     " : "  " )}{flag.Key.PadRight(descPadding)}{desc}");
			}
			Console.WriteLine();
			Console.WriteLine("Actions:");
			foreach (var action in actions)
			{
				// word wrap the descriptions, if needed
				var desc = action.Value;
				if (desc.Length > descWidth)
				{
					var sb = new StringBuilder();
					for (int i = 0; i < desc.Length; i += descWidth)
					{
						if (i > 0)
							sb.Append("".PadLeft(descPadding + 2));
						sb.AppendLine(desc.Substring(i, i + descWidth > desc.Length ? desc.Length - i : descWidth).Trim());
					}
					desc = sb.ToString().TrimEnd('\n');
				}
				Console.WriteLine($"  {action.Key.PadRight(descPadding)}{desc}");
			}
		}

		static void GenerateCode(string user = "", string passkey = "")
		{
			if (Verbose) Console.WriteLine("Aligning time...");
			TimeAligner.AlignTime();
			if (Verbose) Console.WriteLine("Opening manifest...");
			Manifest = Manifest.GetManifest(true);
			if (Verbose) Console.WriteLine("Reading accounts from manifest...");
			if (Manifest.Encrypted)
			{
				if (string.IsNullOrEmpty(passkey))
				{
					passkey = Manifest.PromptForPassKey();
				}
				SteamGuardAccounts = Manifest.GetAllAccounts(passkey);
			}
			else
			{
				SteamGuardAccounts = Manifest.GetAllAccounts();
			}
			if (SteamGuardAccounts.Length == 0)
			{
				Console.WriteLine("error: No accounts read.");
				return;
			}
			if (Verbose) Console.WriteLine("Selecting account...");
			string code = "";
			for (int i = 0; i < SteamGuardAccounts.Length; i++)
			{
				SteamGuardAccount account = SteamGuardAccounts[i];
				if (user != "")
				{
					if (account.AccountName.ToLower() == user.ToLower())
					{
						if (Verbose) Console.WriteLine("Generating Code...");
						code = account.GenerateSteamGuardCode();
						break;
					}
				}
				else
				{
					if (Verbose) Console.WriteLine("Generating Code for {0}...", account.AccountName);
					code = account.GenerateSteamGuardCode();
					break;
				}
			}
			if (code != "")
				Console.WriteLine(code);
			else
				Console.WriteLine("error: No Steam accounts found in {0}", SteamGuardAccounts);
		}

		static bool Encrypt(string passkey = "")
		{
			// NOTE: in this context, `passkey` refers to the old passkey, if there was one
			if (Verbose) Console.WriteLine("Opening manifest...");
			Manifest = Manifest.GetManifest(true);
			if (Verbose) Console.WriteLine("Reading accounts from manifest...");
			if (Manifest.Encrypted)
			{
				if (string.IsNullOrEmpty(passkey))
				{
					passkey = Manifest.PromptForPassKey();
				}
				SteamGuardAccounts = Manifest.GetAllAccounts(passkey);
			}
			else
			{
				SteamGuardAccounts = Manifest.GetAllAccounts();
			}

			string newPassKey = Manifest.PromptSetupPassKey();

			for (int i = 0; i < SteamGuardAccounts.Length; i++)
			{
				var account = SteamGuardAccounts[i];
				var salt = Manifest.GetRandomSalt();
				var iv = Manifest.GetInitializationVector();
				bool success = Manifest.SaveAccount(account, true, newPassKey, salt, iv);
				if (Verbose) Console.WriteLine("Encrypted {0}: {1}", account.AccountName, success);
				if (!success) return false;
			}
			return true;
		}

		static bool Decrypt(string passkey = "")
		{
			if (Verbose) Console.WriteLine("Opening manifest...");
			Manifest = Manifest.GetManifest(true);
			if (Verbose) Console.WriteLine("Reading accounts from manifest...");
			if (Manifest.Encrypted)
			{
				if (string.IsNullOrEmpty(passkey))
				{
					passkey = Manifest.PromptForPassKey();
				}
				SteamGuardAccounts = Manifest.GetAllAccounts(passkey);
			}
			else
			{
				if (Verbose) Console.WriteLine("Decryption not required.");
				return true;
			}

			for (int i = 0; i < SteamGuardAccounts.Length; i++)
			{
				var account = SteamGuardAccounts[i];
				bool success = Manifest.SaveAccount(account, false);
				if (Verbose) Console.WriteLine("Decrypted {0}: {1}", account.AccountName, success);
				if (!success) return false;
			}
			return true;
		}

		static void Setup(string username = "", string passkey = "")
		{
			if (Verbose) Console.WriteLine("Opening manifest...");
			Manifest = Manifest.GetManifest(true);

			if (string.IsNullOrWhiteSpace(username))
			{
				Console.Write("Username: ");
				username = Console.ReadLine();
			}
			Console.Write("Password: ");
			var password = Utils.ReadLineSecure();

			UserLogin login = new UserLogin(username, password);
			string emailCode = null, twoFactorCode = null;
			while (true)
			{
				login.EmailCode = emailCode;
				login.TwoFactorCode = twoFactorCode;
				Console.Write($"Logging in {username}... ");
				LoginResult loginResult = login.DoLogin();
				Console.WriteLine(loginResult);
				if (loginResult == LoginResult.NeedEmail)
				{
					Console.Write("Email code: ");
					emailCode = Console.ReadLine();
					continue;
				}
				else if (loginResult == LoginResult.Need2FA)
				{
					Console.Write("2FA code: ");
					twoFactorCode = Console.ReadLine();
					continue;
				}
				if (!login.LoggedIn) return;
				break;
			}

			AuthenticatorLinker linker = new AuthenticatorLinker(login.Session);
			AuthenticatorLinker.LinkResult linkResult = AuthenticatorLinker.LinkResult.GeneralFailure;

			do
			{
				linkResult = linker.AddAuthenticator();
				Console.WriteLine($"Link result: {linkResult}");
				switch (linkResult)
				{
					case AuthenticatorLinker.LinkResult.MustProvidePhoneNumber:
						var phonenumber = "";
						do
						{
							Console.WriteLine("Enter your mobile phone number in the following format: +{cC} phoneNumber. EG, +1 123-456-7890");
							phonenumber = Console.ReadLine();
							phonenumber = FilterPhoneNumber(phonenumber);
							linker.PhoneNumber = phonenumber;
						} while (!PhoneNumberOkay(phonenumber));
						break;
					case AuthenticatorLinker.LinkResult.MustRemovePhoneNumber:
						linker.PhoneNumber = null;
						break;
					case AuthenticatorLinker.LinkResult.AwaitingFinalization:
						break;
					case AuthenticatorLinker.LinkResult.GeneralFailure:
						Console.WriteLine("error: Unable to add your phone number. Steam returned GeneralFailure");
						return;
					case AuthenticatorLinker.LinkResult.AuthenticatorPresent:
						Console.WriteLine("An authenticator is already present.");
						Console.WriteLine("If you have the revocation code (Rxxxxx), this program can remove it for you.");
						Console.Write("Would you like to remove the current authenticator using your revocation code? (y/n) ");
						var answer = Console.ReadLine();
						if (answer != "y")
							continue;
						Console.Write("Revocation code (Rxxxxx): ");
						var revocationCode = Console.ReadLine();
						var account = new SteamGuardAccount();
						account.Session = login.Session;
						account.RevocationCode = revocationCode;
						if (account.DeactivateAuthenticator())
							Console.WriteLine("Successfully deactivated the current authenticator.");
						else
							Console.WriteLine("Deactivating the current authenticator was unsuccessful.");
						continue;
					default:
						Console.WriteLine($"error: Unexpected linker result: {linkResult}");
						return;
				}
			} while (linkResult != AuthenticatorLinker.LinkResult.AwaitingFinalization);

			string passKey = null;
			if (Manifest.Entries.Count == 0)
			{
				Console.WriteLine("Looks like we are setting up your first account.");
				passKey = Manifest.PromptSetupPassKey(true);
			}
			else if (Manifest.Entries.Count > 0 && Manifest.Encrypted)
			{
				if (string.IsNullOrEmpty(passkey))
				{
					passkey = Manifest.PromptForPassKey();
				}
			}

			//Save the file immediately; losing this would be bad.
			if (!Manifest.SaveAccount(linker.LinkedAccount, passKey != null, passKey))
			{
				Manifest.RemoveAccount(linker.LinkedAccount);
				Console.WriteLine("Unable to save mobile authenticator file. The mobile authenticator has not been linked.");
				return;
			}

			Console.WriteLine(
				$"The Mobile Authenticator has not yet been linked. Before finalizing the authenticator, please write down your revocation code: {linker.LinkedAccount.RevocationCode}");

			AuthenticatorLinker.FinalizeResult finalizeResponse = AuthenticatorLinker.FinalizeResult.GeneralFailure;
			do
			{
				Console.Write("Please input the SMS message sent to your phone number: ");
				string smsCode = Console.ReadLine();

				finalizeResponse = linker.FinalizeAddAuthenticator(smsCode);
				if (Verbose) Console.WriteLine(finalizeResponse);

				switch (finalizeResponse)
				{
					case AuthenticatorLinker.FinalizeResult.BadSMSCode:
						continue;

					case AuthenticatorLinker.FinalizeResult.UnableToGenerateCorrectCodes:
						Console.WriteLine(
							"Unable to generate the proper codes to finalize this authenticator. The authenticator should not have been linked.");
						Console.WriteLine(
							$"In the off-chance it was, please write down your revocation code, as this is the last chance to see it: {linker.LinkedAccount.RevocationCode}");
						Manifest.RemoveAccount(linker.LinkedAccount);
						return;

					case AuthenticatorLinker.FinalizeResult.GeneralFailure:
						Console.WriteLine("Unable to finalize this authenticator. The authenticator should not have been linked.");
						Console.WriteLine(
							$"In the off-chance it was, please write down your revocation code, as this is the last chance to see it: {linker.LinkedAccount.RevocationCode}");
						Manifest.RemoveAccount(linker.LinkedAccount);
						return;
				}
			} while (finalizeResponse != AuthenticatorLinker.FinalizeResult.Success);

			//Linked, finally. Re-save with FullyEnrolled property.
			Manifest.SaveAccount(linker.LinkedAccount, passKey != null, passKey);
			Console.WriteLine(
				$"Mobile authenticator successfully linked. Please actually write down your revocation code: {linker.LinkedAccount.RevocationCode}");
		}

		public static string FilterPhoneNumber(string phoneNumber)
			=> phoneNumber.Replace("-", "").Replace("(", "").Replace(")", "");

		public static bool PhoneNumberOkay(string phoneNumber)
		{
			if (phoneNumber == null || phoneNumber.Length == 0) return false;
			if (phoneNumber[0] != '+') return false;
			return true;
		}

		static void Trade(string user = "", string passkey = "")
		{
			if (Verbose) Console.WriteLine("Opening manifest...");
			Manifest = Manifest.GetManifest(true);
			if (Verbose) Console.WriteLine("Reading accounts from manifest...");
			if (Manifest.Encrypted)
			{
				if (string.IsNullOrEmpty(passkey))
				{
					passkey = Manifest.PromptForPassKey();
				}
				SteamGuardAccounts = Manifest.GetAllAccounts(passkey);
			}
			else
			{
				SteamGuardAccounts = Manifest.GetAllAccounts();
			}
			if (SteamGuardAccounts.Length == 0)
			{
				Console.WriteLine("error: No accounts read.");
				return;
			}

			foreach (var account in SteamGuardAccounts)
			{
				if (user != "")
					if (!string.Equals(account.AccountName, user, StringComparison.CurrentCultureIgnoreCase))
						break;

				processConfirmations(account);
			}
		}

		enum TradeAction
		{
			Accept = 1,
			Deny = 0,
			Ignore = -1
		}

		static void processConfirmations(SteamGuardAccount account)
		{
			if (Verbose) Console.WriteLine("Refeshing Session...");
			if (account.RefreshSession())
			{
				if (Verbose) Console.WriteLine("Session refreshed");
				Manifest.SaveAccount(account, Manifest.Encrypted);
			}
			else
			{
				if (Verbose) Console.WriteLine("Failed to refresh session");
				Console.WriteLine("Your Steam credentials have expired. For trade and market confirmations to work properly, please login again.");
				string username = account.AccountName;
				Console.WriteLine($"Username: {username}");
				Console.Write("Password: ");
				var password = Console.ReadLine();

				UserLogin login = new UserLogin(username, password);
				Console.Write($"Logging in {username}... ");
				LoginResult loginResult = login.DoLogin();
				if (loginResult == LoginResult.Need2FA && !string.IsNullOrEmpty(account.SharedSecret))
				{
					// if we need a 2fa code, and we can generate it, generate a 2fa code and log in.
					if (Verbose) Console.WriteLine(loginResult);
					TimeAligner.AlignTime();
					login.TwoFactorCode = account.GenerateSteamGuardCode();
					if (Verbose) Console.Write($"Logging in {username}... ");
					loginResult = login.DoLogin();
				}
				Console.WriteLine(loginResult);
				if (loginResult == LoginResult.LoginOkay)
				{
					account.Session = login.Session;
				}

				if (account.RefreshSession())
				{
					if (Verbose) Console.WriteLine("Session refreshed");
					Manifest.SaveAccount(account, Manifest.Encrypted);
				}
				else
				{
					Console.WriteLine("Failed to refresh session, aborting...");
					return;
				}
			}
			Console.WriteLine("Retrieving trade confirmations...");
			var tradesTask = account.FetchConfirmationsAsync();
			tradesTask.Wait();
			var trades = tradesTask.Result;
			var tradeActions = new TradeAction[trades.Length];
			for (var i = 0; i < tradeActions.Length; i++)
			{
				tradeActions[i] = TradeAction.Ignore;
			}
			if (trades.Length == 0)
			{
				Console.WriteLine($"No trade confirmations for {account.AccountName}.");
				return;
			}
			var selected = 0;
			var colorAccept = ConsoleColor.Green;
			var colorDeny = ConsoleColor.Red;
			var colorIgnore = ConsoleColor.Gray;
			var colorSelected = ConsoleColor.Yellow;
			var confirm = false;

			do
			{
				Console.Clear();
				if (selected >= trades.Length)
					selected = trades.Length - 1;
				else if (selected < 0)
					selected = 0;
				Console.ResetColor();
				Console.WriteLine($"Trade confirmations for {account.AccountName}...");
				Console.WriteLine("No action will be made without your confirmation.");
				Console.WriteLine("[a]ccept   [d]eny   [i]gnore  [enter] Confirm  [q]uit"); // accept = 1, deny = 0, ignore = -1
				Console.WriteLine();

				for (var t = 0; t < trades.Length; t++)
				{
					ConsoleColor itemColor;
					switch (tradeActions[t])
					{
						case TradeAction.Accept:
							itemColor = colorAccept;
							break;
						case TradeAction.Deny:
							itemColor = colorDeny;
							break;
						case TradeAction.Ignore:
							itemColor = colorIgnore;
							break;
						default:
							throw new ArgumentOutOfRangeException();
					}

					Console.ForegroundColor = t == selected ? colorSelected : itemColor;

					Console.WriteLine($"  [{t}] [{tradeActions[t]}] {trades[t].Description}");
				}
				var key = Console.ReadKey();
				switch (key.Key)
				{
					case ConsoleKey.UpArrow:
					case ConsoleKey.W:
						selected--;
						break;
					case ConsoleKey.DownArrow:
					case ConsoleKey.S:
						selected++;
						break;
					case ConsoleKey.A:
						tradeActions[selected] = TradeAction.Accept;
						break;
					case ConsoleKey.D:
						tradeActions[selected] = TradeAction.Deny;
						break;
					case ConsoleKey.I:
						tradeActions[selected] = TradeAction.Ignore;
						break;
					case ConsoleKey.Enter:
						confirm = true;
						break;
					case ConsoleKey.Escape:
					case ConsoleKey.Q:
						Console.ResetColor();
						Console.WriteLine("Quitting...");
						return;
					default:
						break;
				}
			} while (!confirm);
			Console.ResetColor();
			Console.WriteLine();
			Console.WriteLine("Processing...");
			for (var t = 0; t < trades.Length; t++)
			{
				bool success = false;
				switch (tradeActions[t])
				{
					case TradeAction.Accept:
						if (Verbose) Console.Write($"Accepting {trades[t].Description}...");
						success = account.AcceptConfirmation(trades[t]);
						break;
					case TradeAction.Deny:
						if (Verbose) Console.Write($"Denying {trades[t].Description}...");
						success = account.AcceptConfirmation(trades[t]);
						break;
					case TradeAction.Ignore:
						if (Verbose) Console.Write($"Ignoring {trades[t].Description}...");
						success = true;
						break;
					default:
						throw new ArgumentOutOfRangeException();
				}
				if (Verbose) Console.WriteLine(success);
			}
			Console.WriteLine("Done.");
		}

		static void AcceptAllTrades(string user = "", string passkey = "")
		{
			if (Verbose) Console.WriteLine("Opening manifest...");
			Manifest = Manifest.GetManifest(true);
			if (Verbose) Console.WriteLine("Reading accounts from manifest...");
			if (Manifest.Encrypted)
			{
				if (string.IsNullOrEmpty(passkey))
				{
					passkey = Manifest.PromptForPassKey();
				}
				SteamGuardAccounts = Manifest.GetAllAccounts(passkey);
			}
			else
			{
				SteamGuardAccounts = Manifest.GetAllAccounts();
			}
			if (SteamGuardAccounts.Length == 0)
			{
				Console.WriteLine("error: No accounts read.");
				return;
			}

			for (int i = 0; i < SteamGuardAccounts.Length; i++)
			{
				SteamGuardAccount account = SteamGuardAccounts[i];
				if ((user != "" && account.AccountName.ToLower() == user.ToLower()) || user == "")
				{
					Console.WriteLine($"Accepting Confirmations on {account.AccountName}");
					if (Verbose) Console.WriteLine("Refeshing Session...");
					account.RefreshSession();
					if (Verbose) Console.WriteLine("Fetching Confirmations...");
					var tradesTask = account.FetchConfirmationsAsync();
					tradesTask.Wait();
					Confirmation[] confirmations = tradesTask.Result;
					if (Verbose) Console.WriteLine("Accepting Confirmations...");
					account.AcceptMultipleConfirmations(confirmations);
					if (user != "")
					{
						break;
					}
				}
			}
		}
	}
}
