#!/usr/bin/env python3
#test script

import json
import subprocess
import os
import sys

path = subprocess.check_output([
    "zenity",
    "--file-selection",
    "--title=Выбери .maFile",
    "--filename=" + os.path.expanduser("~/Рабочий стол/"), #"~/Рабочий стол/" > "~/Desktop/"
    "--file-filter=maFile (*.maFile) | *.maFile"
], text=True).strip()

if not path:
    sys.exit(0)

with open(path, "r", encoding="utf-8") as f:
    src = json.load(f)

steam_id = str(src["steam_id"])

dst = {
    "shared_secret": src["shared_secret"],
    "serial_number": src["steam_id"],
    "revocation_code": src["revocation_code"],
    "uri": src["uri"],
    "account_name": src["account_name"],
    "token_gid": src["token_gid"],
    "identity_secret": src["identity_secret"],
    "secret_1": src["secret_1"],
    "device_id": src["device_id"],
    "fully_enrolled": True,
    "Session": {
        "SessionID": "xxxxxxxxxxxxxxxxx",
        "AccessToken": src["tokens"]["access_token"],
        "RefreshToken": src["tokens"]["refresh_token"],
        "SteamID": steam_id,
        "SteamLoginSecure": "76561198930741722%7C%7EeyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MDAwMl8yNzZCOEY1Ml9DQkFGMSIsICJzdWIiOiAiNzY1NjExOTg5MzA3NDE3MjIiLCAiYXVkIjogWyAid2ViOnN0b3JlIiBdLCAiZXhwIjogMTczMDkxODQ0MSwgIm5iZiI6IDE3MjIxOTEwNTMsICJpYXQiOiAxNzMwODMxMDUzLCAianRpIjogIjBGRTZfMjU0QjAzN0ZfREI3MDIiLCAib2F0IjogMTczMDgzMTA1MywgInJ0X2V4cCI6IDE3NDg4MjY5MjcsICJwZXIiOiAwLCAiaXBfc3ViamVjdCI6ICIxNTQuMTk1LjE0My4yMzIiLCAiaXBfY29uZmlybWVyIjogIjE1NC4xOTUuMTQzLjIzMiIgfQ.l8VIo84hrIRCVQYepXjoQSou4GKR_gUA5LgSl3xsvJxlYU4N4HkrQhKNs6UqiQuvIt0L8CCiLNmxqcXq4eRpCQ"
    }
}

new_path = os.path.join(
    os.path.dirname(path),
    "new_" + os.path.basename(path)
)

with open(new_path, "w", encoding="utf-8") as f:
    json.dump(dst, f, indent=2, ensure_ascii=False)
