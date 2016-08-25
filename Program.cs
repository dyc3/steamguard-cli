using Newtonsoft.Json;
using SteamAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

public static class Program
{
    const string defaultSteamGuardPath = "~/maFiles";

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
        string action = "generate-code";

        string user = "";

        // Parse cli arguments
        if (args.Contains("--help") || args.Contains("-h"))
        {
            Console.WriteLine($"steamguard-cli - v{Assembly.GetExecutingAssembly().GetName().Version}");
            Console.WriteLine();
            Console.WriteLine("--help, -h                   Display this help message.");
            Console.WriteLine("--verbose, -v                Display some extra information when the program is running.");
            Console.WriteLine("--user, -u                   Specify an account for which to generate a Steam Gaurd code.");
            Console.WriteLine("                             Otherwise, the first account will be selected.");
            Console.WriteLine("--generate-code              Generate a Steam Guard code and exit. (default)");
            Console.WriteLine("--encrypt                    Encrypt your maFiles or change your encryption passkey.");
            Console.WriteLine("--decrypt                    Remove encryption from your maFiles.");
	        Console.WriteLine("--trade                      List all trade confirmations across all accounts, or of the user\n" +
	                          "                             specified with --user");
            return;
        }
        Verbose = args.Contains("-v") || args.Contains("--verbose");
        // Actions
        if (args.Contains("--generate-code"))
        {
            action = "generate-code";
        }
        else if (args.Contains("--encrypt"))
        {
            action = "encrypt";
        }
        else if (args.Contains("--decrypt"))
        {
            action = "decrypt";
        }
        else if (args.Contains("--setup"))
        {
            action = "setup";
        }
	    else if (args.Contains("--trade"))
        {
	        action = "trade";
        }
        // Misc
        if (args.Contains("--user") || args.Contains("-u"))
        {
            int u = Array.IndexOf(args, "--user");
            if (u == -1)
            {
                u = Array.IndexOf(args, "-u");
            }
            try
            {
                user = args[u + 1];
            }
            catch (IndexOutOfRangeException)
            {
                Console.WriteLine("error: Account name must be supplied after --user or -u.");
                return;
            }
            if (Verbose) Console.WriteLine("Generating Steam Gaurd code for account \"{0}\"", user);
        }

        // Do some configure
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
        if (Verbose) Console.WriteLine("maFiles path: {0}", SteamGuardPath);

        if (Verbose) Console.WriteLine("Action: {0}", action);
        // Perform desired action
        switch (action)
        {
            case "generate-code":
                GenerateCode(user);
                break;
            case "encrypt": // Can also be used to change passkey
                Console.WriteLine(Encrypt());
                break;
            case "decrypt":
                Console.WriteLine(Decrypt());
                break;
            case "setup":
                throw new NotSupportedException();
                break;
		    case "trade":
		        TradeList(user);
		        break;
            default:
                Console.WriteLine("error: Unknown action: {0}", action);
                return;
        }
    }

    static void GenerateCode(string user = "")
    {
        if (Verbose) Console.WriteLine("Aligning time...");
        TimeAligner.AlignTime();
        if (Verbose) Console.WriteLine("Opening manifest...");
        Manifest = Manifest.GetManifest(true);
        if (Verbose) Console.WriteLine("Reading accounts from manifest...");
        if (Manifest.Encrypted)
        {
            string passkey = Manifest.PromptForPassKey();
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

    static bool Encrypt()
    {
        if (Verbose) Console.WriteLine("Opening manifest...");
        Manifest = Manifest.GetManifest(true);
        if (Verbose) Console.WriteLine("Reading accounts from manifest...");
        if (Manifest.Encrypted)
        {
            string passkey = Manifest.PromptForPassKey();
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

    static bool Decrypt()
    {
        if (Verbose) Console.WriteLine("Opening manifest...");
        Manifest = Manifest.GetManifest(true);
        if (Verbose) Console.WriteLine("Reading accounts from manifest...");
        if (Manifest.Encrypted)
        {
            string passkey = Manifest.PromptForPassKey();
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

	static void TradeList(string user = "")
	{
		if (Verbose) Console.WriteLine("Opening manifest...");
		Manifest = Manifest.GetManifest(true);
		if (Verbose) Console.WriteLine("Reading accounts from manifest...");
		if (Manifest.Encrypted)
		{
			string passkey = Manifest.PromptForPassKey();
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
			if (user != "")
			{
				if (account.AccountName.ToLower() == user.ToLower())
				{
					showTradeConfirmations(account);
					break;
				}
			}
			else
			{
				showTradeConfirmations(account);
			}
		}
	}

	static void showTradeConfirmations(SteamGuardAccount account)
	{
		Console.WriteLine($"Checking trade confirmations for {account.AccountName}...");
		if (Verbose) Console.WriteLine("Refeshing Session...");
		account.RefreshSession();

		Confirmation[] trades = account.FetchConfirmations();
		foreach (var trade in trades)
		{
			Console.WriteLine($"ID: {trade.ID} Key: {trade.Key} Description: {trade.Description}");
		}
	}
}
