using System;
using System.Text;
using System.Linq;
using System.IO;

public static class Program
{
    const string defaultSteamGuardPath = "~/maFiles";

    public static string SteamGuardPath { get; set; } = defaultSteamGuardPath;

    /// <summary>
    ///   The main entry point for the application
    /// </summary>
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Contains("--help") || args.Contains("-h"))
        {
            Console.WriteLine("steamguard-cli - v0.0");
            Console.WriteLine();
            Console.WriteLine("--help, -h   Display this help message.");
            return;
        }

        SteamGuardPath = SteamGuardPath.Replace("~", Environment.GetEnvironmentVariable("HOME"));
        if (!Directory.Exists(SteamGuardPath))
        {
            if (SteamGuardPath == defaultSteamGuardPath.Replace("~", Environment.GetEnvironmentVariable("HOME")))
            {
                Console.WriteLine("warn: {0} does not exist, creating...", SteamGuardPath);
                Directory.CreateDirectory(SteamGuardPath);
            }
            else
            {
                Console.WriteLine("error: {0} does not exist.", SteamGuardPath);
                return;
            }
        }
    }
}
