$(eval SHELL:=/bin/bash)

all: Program.cs
	mkdir -p build/
	nuget restore SteamAuth/SteamAuth/SteamAuth.sln
	$(eval NEWTONSOFT_JSON_PATH=$(shell find -name Newtonsoft.Json.dll | grep \/net45\/ | sort -t. -k 1,1n -k 2,2n -k 3,3n -k 4,4n | tail -n 1))
	mcs -target:library -out:build/SteamAuth.dll -r:$(NEWTONSOFT_JSON_PATH) SteamAuth/SteamAuth/APIEndpoints.cs SteamAuth/SteamAuth/AuthenticatorLinker.cs SteamAuth/SteamAuth/Confirmation.cs SteamAuth/SteamAuth/SessionData.cs SteamAuth/SteamAuth/SteamGuardAccount.cs SteamAuth/SteamAuth/SteamWeb.cs SteamAuth/SteamAuth/TimeAligner.cs SteamAuth/SteamAuth/UserLogin.cs SteamAuth/SteamAuth/Util.cs SteamAuth/SteamAuth/Properties/AssemblyInfo.cs
	cp $(NEWTONSOFT_JSON_PATH) build/
	mcs -out:build/steamguard -r:build/SteamAuth.dll -r:build/Newtonsoft.Json.dll -r:/usr/lib/mono/4.5/System.Security.dll Program.cs Manifest.cs AssemblyInfo.cs Utils.cs

run:
	build/steamguard -v

clean:
	rm -r build/

install:
	cp build/steamguard /usr/local/bin/
	cp build/Newtonsoft.Json.dll /usr/local/bin/
	cp build/SteamAuth.dll /usr/local/bin/
	cp bash-tab-completion /etc/bash_completion.d/steamguard

uninstall:
	rm -f /usr/local/bin/steamguard
	rm -f /usr/local/bin/Newtonsoft.Json.dll
	rm -f /usr/local/bin/SteamAuth.dll
	rm -f /etc/bash_completion.d/steamguard
