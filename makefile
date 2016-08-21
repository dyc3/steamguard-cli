all: Program.cs
	nuget restore SteamAuth/SteamAuth/SteamAuth.sln
	mcs -target:library -out:build/libSteamAuth.so -r:SteamAuth/SteamAuth/packages/Newtonsoft.Json.7.0.1/lib/net45/Newtonsoft.Json.dll SteamAuth/SteamAuth/APIEndpoints.cs SteamAuth/SteamAuth/AuthenticatorLinker.cs SteamAuth/SteamAuth/Confirmation.cs SteamAuth/SteamAuth/SessionData.cs SteamAuth/SteamAuth/SteamGuardAccount.cs SteamAuth/SteamAuth/SteamWeb.cs SteamAuth/SteamAuth/TimeAligner.cs SteamAuth/SteamAuth/UserLogin.cs SteamAuth/SteamAuth/Util.cs SteamAuth/SteamAuth/Properties/AssemblyInfo.cs
	mcs -out:build/steamguard -r:build/libSteamAuth.so -r:SteamAuth/SteamAuth/packages/Newtonsoft.Json.7.0.1/lib/net45/Newtonsoft.Json.dll Program.cs
