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
        string action = "";
        string user = "";

	    // Parse cli arguments
	    for (int i = 0; i < args.Length; i++)
	    {
		    if (args[i].StartsWith("-"))
		    {
			    if (args[i] == "-v" || args[i] == "--verbose")
			    {
				    Verbose = true;
			    }
			    else if (args[i] == "-m" || args[i] == "--mafiles-path")
			    {
				    i++;
				    if (i < args.Length)
				    	SteamGuardPath = args[i];
				    else
				    {
					    Console.WriteLine($"Expected path after {args[i-1]}");
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
				    if (args[i] == "add")
				    {
					    action = "setup";
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
				    continue;
			    }
			    // its a username
			    if (string.IsNullOrEmpty(user))
				    user = args[i];
		    }
	    }

	    if (string.IsNullOrEmpty(action))
		    action = "generate-code";

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

	    if (Verbose) Console.WriteLine($"Action: {action}");
	    if (Verbose) Console.WriteLine($"User: {user}");
	    if (Verbose) Console.WriteLine($"maFiles path: {SteamGuardPath}");
	    return;

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
            default:
                Console.WriteLine("error: Unknown action: {0}", action);
                return;
        }
    }

	static void ShowHelp()
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
}
