using System;
using System.Text;
using System.Linq;

public static class Program
{
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
            return 0;
        }
        return 1;
    }
}
