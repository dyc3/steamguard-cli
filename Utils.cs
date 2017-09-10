using System;
using System.Diagnostics;

namespace SteamGuard
{
	public static class Utils
	{
		public static string ReadLineSecure()
		{
			// Have bash handle the password input, because apparently it's impossible in C#,
			// and we don't need to worry about windows compatibility.
			string bash_cmd = @"read -s -p ""Password: "" password; echo $password";
			Process p = new Process();
			p.StartInfo.UseShellExecute = false;
			p.StartInfo.FileName = "bash";
			p.StartInfo.Arguments = string.Format("-c '{0}'", bash_cmd);
			p.StartInfo.RedirectStandardOutput = true;
			p.Start();

			p.WaitForExit();
			Console.WriteLine();
			return p.StandardOutput.ReadToEnd().Trim();
		}
	}
}
