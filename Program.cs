using Newtonsoft.Json;
using SteamAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        string user = "";

        // Parse cli arguments
        if (args.Contains("--help") || args.Contains("-h"))
        {
            Console.WriteLine("steamguard-cli - v0.0");
            Console.WriteLine();
            Console.WriteLine("--help, -h         Display this help message.");
            Console.WriteLine("--verbose, -v      Display some extra information when the program is running.");
            Console.WriteLine("--user, -u         Specify an account for which to generate a Steam Gaurd code.");
            Console.WriteLine("                   Otherwise, the first account will be selected.");
            return;
        }
        Verbose = args.Contains("-v") || args.Contains("--verbose");
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

        // Generate the code
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
}
