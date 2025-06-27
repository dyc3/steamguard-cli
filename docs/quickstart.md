# Quickstart

steamguard-cli is a command-line tool, and as such, it is meant to be used in a terminal. This guide will show you how to get started with steamguard-cli.

## Windows

1. Download `steamguard.exe` from the [releases page][releases].
2. Place `steamguard.exe` in a folder of your choice. For this example, we will use `%USERPROFILE%\Desktop`.
3. Open Powershell or Command Prompt. The prompt should be at `%USERPROFILE%` (eg. `C:\Users\<username>`).
4. Use `cd` to change directory into the folder where you placed `steamguard.exe`. For this example, it would be `cd Desktop`.
5. You should now be able to run `steamguard.exe` by typing `.\steamguard.exe --help` and pressing enter.

## Linux

### Ubuntu/Debian

1. Download the `.deb` from the [releases page][releases].
2. Open a terminal and run this to install it:
```bash
sudo dpkg -i ./steamguard-cli_<version>_amd64.deb
```

### Other Linux

1. Download `steamguard` from the [releases page][releases]
2. Make it executable, and move `steamguard` to `/usr/local/bin` or any other directory in your `$PATH`.
```bash
chmod +x ./steamguard
sudo mv ./steamguard /usr/local/bin
```
3. You should now be able to run `steamguard` by typing `steamguard --help` and pressing enter.

# Importing existing maFiles from Steam Desktop Authenticator

If you have used [Steam Desktop Authenticator][SDA] before, you can use your existing maFiles into steamguard-cli, and they will be automatically upgraded for use with steamguard-cli.

1. Make a backup of your `maFiles` folder.
2. Place your `maFiles` folder in the following directory:
	- Linux:
		- `~/.config/steamguard-cli/maFiles/`
	- Windows:
		- `%APPDATA%\steamguard-cli\maFiles\`
3. Run `steamguard` from your terminal.


### Importing individual maFiles from Steam Desktop Authenticator

It's also possible to import a single maFile from Steam Desktop Authenticator and add it to your existing manifest.

```bash
steamguard import --sda <path to maFile>
```

[SDA]: https://github.com/Jessecar96/SteamDesktopAuthenticator
[releases]: http://github.com/dyc3/steamguard-cli/releases
