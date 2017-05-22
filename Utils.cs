using System;

namespace SteamGuard
{
	public static class Utils
	{
		public static string ReadLineSecure()
		{
			string text = "";
			ConsoleKeyInfo key;
			int cursorIndex = 0;
			do
			{
				key = Console.ReadKey(true);
				if ((int)key.Key >= 65 && (int)key.Key <= 90)
				{
					text.Insert(cursorIndex, key.KeyChar.ToString());
					cursorIndex++;
				}
				else if (key.Key == ConsoleKey.Backspace && cursorIndex > 0)
				{
					text.Remove(cursorIndex - 1, 1);
					cursorIndex--;
				}
				else if (key.Key == ConsoleKey.RightArrow)
				{
					cursorIndex++;
				}
				else if (key.Key == ConsoleKey.LeftArrow)
				{
					cursorIndex--;
				}

				if (cursorIndex < 0)
				{
					cursorIndex = 0;
				}
				else if (cursorIndex > text.Length)
				{
					cursorIndex = text.Length - 1;
				}
			} while (key.Key != ConsoleKey.Enter);
			return text;
		}
	}
}
