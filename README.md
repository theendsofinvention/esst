
[![master](https://ci.appveyor.com/api/projects/status/auuv6038yd4x1242/branch/master?svg=true&passingText=master%20-%20OK&failingText=master%20-%20Fails)](https://ci.appveyor.com/project/132nd-etcher/esst/branch/master)
[![develop](https://ci.appveyor.com/api/projects/status/auuv6038yd4x1242/branch/develop?svg=true&passingText=develop%20-%20OK&failingText=develop%20-%20Fails)](https://ci.appveyor.com/project/132nd-etcher/esst/branch/develop)

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e0b191c3a7b64c3d907297375a120804)](https://www.codacy.com/app/132nd-etcher/ESST?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=132nd-vWing/ESST&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/e0b191c3a7b64c3d907297375a120804)](https://www.codacy.com/app/132nd-etcher/ESST?utm_source=github.com&utm_medium=referral&utm_content=132nd-vWing/ESST&utm_campaign=Badge_Coverage)

# ESST

ESST stands for Etcher's Server Startup Tool.

## Important

* Before running ESST, you need to configure and start a multiplayer server at least once.
* If you want to deactivate the dedicated server feature, open `Saved Games\DCS\Config\dedicated.lua` and set `["enabled"] = false`

## Modified files
* The following DCS files are added or modified:
	* `Saved Games\DCS\Config\dedicated.lua`: used to control the dedicated server behaviour.  Set `["enabled"] = false` to revert to standard DCS behaviour.
	* `Saved Games\DCS\Scripts\ESSTGameGUI.lua`: this file controls the hooks for the DCS API and runs a UDP socket and is automatically added by ESST.
	* `C:\DCS World\MissionEditor\modules\me_authorization.lua`: this file is edited to allow DCS to start directly in multiplayer server mode

**NOTE**: all files that are modified by ESST are backed-up before edition.

## Functionalities

The main functionnalities are:

* Auto start and auto-restart DCS
* Discord bot able to send and receive commands
	* Upload a Mission file to Discord to send it to the server
	* Load missions
	* Restart the server
	* CPU usage alerts
	* Server status
* Automatic download and activation of a mission file from a Github repository latest release

### How it works

The tool is composed of three main parts:

* The DCS server manager: this is responsible for spawning (or connecting to) a DCS.exe process. It will also try it's  best to keep it alive, and restart it in case it crashes. This has been made possible by [Ciribob](https://forums.eagle.ru/member.php?u=112175) and [his method to auto-start a server](https://forums.eagle.ru/showthread.php?t=160829).
* A UDP socket: this little one is responsible for enabling communication between DCS and ESST. Messages are sent back and forth between the two of them. DCS sends regular updates with the status of the server, the connected players list, etc., while ESST can send command to DCS, for example asking it to exit gracefully before a restart (this is achieved by installing a script in `Saved Games\DCS\Scripts\ESSTGameGUI.lua`).
* A Discord bot: this is a two communication between ESST and a Discord channel on the Wing's server. ESST publishes updates about the server status, and members of the server are able to send commands to the dedicated server via the same channel.

### Discord bot commands

To see a list of commands available, type `!help` in the Discord channel.

Along with the Discord commands that allow to **upload missions file via drag-and-drop into a Discord channel**, ESST also 

## Installation

**Note:** Since DCS is a 64 bit application, it is *strongly* recommended to have a 64 bits Python executable as well.

**Note:** ESST will only run with Python 3.6 and newer.

If you are able to get a working virtual environment on your own, feel free to skip the next step.

### Create a virtual env

1. Download and install [Miniconda 64 bit](https://conda.io/miniconda.html)
2. Start a command prompt in the "Scripts" folder of your Miniconda installation
3. Type: `conda create -n ESST python=3.6`
4. When Conda asks for confirmation, say yes.
5. Activate your virtual environment with `activate ESST`
6. The prompt will now have the `(ESST)` prefix, indicating your virtual environment is activated

**IMPORTANT**: Remember to *ALWAYS* activate your environment before running the `esst` script,  otherwise Windows will not be able to find the script.

## Initial setup

### Create a Discord bot

First, you'll need to create a Discord application:

1. Go to [https://discordapp.com/developers/applications/me](https://discordapp.com/developers/applications/me) and click "New app"
2. Give it a name and click "Create app"
3. Click "Create a bot" and confirm
4. Under "App bot", next to "token", click "click to reveal" and note the token. This will be your **bot token**
5. Next, under "App details", copy your **Client ID**
6. Got to [https://discordapp.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&scope=bot](https://discordapp.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&scope=bot), replacing "YOUR_CLIENTID" in the URL with your actual **ClientID**
7. Add the bot to the server of your choice
8. On the server, make sure the bot has the right to manage channels, to be able to create its channel if needed. If you prefer not to give this role to the bot, you will need to create the channel indicated in `DISCORD_CHANNEL` config value

**IMPORTANT**: the bot can only be added to **ONE** server for the time being.

### Install ESST

Using a command prompt with your venv activcated, run the following command:

```batch
pip install esst
```

This will install ESST in your venv.

### Disable Windows crash dialog

When the DCS application crashes, Windows will by default show a dialog, which will prevent ESST from restarting DCS.
To disable that dialog, open an elevated command prompt and execute the following commands:

```batch
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
```

```batch
reg add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
```

### Create the configuration file

Create a file named `esst.ini` .

The location of `esst.ini` can be one of:
* Arbitrary, and indicated in the `ESST_INI` environment variable
* In your user directory (`c:\users\<your name>\esst.ini`)
* In the directory of your choosing (that directory will have to be the working directory when you run ESST)

A standard configuration file looks like this:

```ini
[main]
DEBUG = true (optional, default: false)
SAVED_GAMES_DIR = C:\path\to\Saved Games\DCS

[discord]
bot_name = My slick bot
channel = Some Discord Channel
token = DISCORD_TOKEN
motd = Hi guys!

[dcs]
PATH = C:\path\to\DCS World\bin\dcs.exe
SERVER_NAME = My awesome server
SERVER_PASSWORD = SERVER_SECRET_PASSWORD
SERVER_MAX_PLAYERS = 64
DCS_SERVER_STARTUP_TIME = 60 (optional, defaults: 120)
DCS_PING_INTERVAL = 20 (optional, default: 30)

[auto_mission] (optional)
github_owner = 132nd-vWing
github_token = SECRET_GITHUB_TOKEN (optional)
github_repo = 132nd-Virtual-Wing-Training-Mission-Tblisi
```

#### OS environment variables as config
**Note:** all config values can be set either in the INI file, or in the environment. The value `PATH` in the example below can be set in the environment as `DCS_PATH`.
```ini
[dcs]
PATH = C:\path\to\DCS World\bin\dcs.exe
```

The `[main]` section has no prefix.

**Note**: case in the INI file does not matter, but environment variables *must* be upper-case.


#### [main]
* `debug`: if true, debug messages will be printed on the console
* `SAVED_GAMES_DIR `: path to the `DCS`folder in `Saved Games`

#### [discord]
* `bot_name`: the name of your bot
* `channel`: channel name to use on the server (it will be created by the bot if it doesn't exist)
* `token`: the token of your Discord bot

#### [dcs]
* `path`: path to the DCS executable (`dcs.exe`)
* `server_name`: the name of the DCS multiplayer server
* `server_password`: the password for the DCS multiplayer server
* `server_max_players`: maximum amount of players allowed on the server
* `dcs_server_startup_time`: this is the maximum amount of time allowed between the moment the `DCS.exe` process is running and the moment when an actual multiplayer server is running. If that time is exceeded, an alert will be sent on Discord
* `dcs_ping_interval`: this is the maximum amount of time between pings over which the server will be considered unresponsive and will be restarted (pings are sent to ESST by DCS every 5 seconds).

#### [auto_mission]
Those settings are optional. If provided, ESST will automatically download the first `*.miz` asset from the latest release of a Github repository, allowing you to simply upload your missions to Github, and have ESST grab the latest version at startup.

* `github_owner`: owner (organization or user) of the repository
* `github_repo`: name of the repository
* `github_token`: your personal Github token; this is provided to bypass the Github API rate-limitation error, but it's totally optional

## Running ESST

Simply type `esst`at the command prompt, with your venv activated.

### Example batch file

```batch
@echo off
echo waiting 30 seconds
ping 127.0.0.1 -n 30 > nul
call activate ESST
cd C:\Utils\ESST
pip install --upgrade --no-cache esst
esst
pause
```

This batch file will:
1. Pause for 30 seconds (so you can run when the computer starts)
2. Activate a virtual environment named `ESST` (note that `Miniconda\Scripts` must be in the `PATH` for this to work)
3. Change the working directory to `C:\Utils\ESST`, assuming that's where your `esst.ini` file is located
4. Grabe the latest version of ESST
5. Run ESST
6. Pause the script, to show the potential errors

## Log files

ESST writes two log files, both located in `Saved Games\DCS\Logs`.

* `esst.log` is the log for the main application
*  `esst-gamegui.log` is the log for the `ESSTGameGUI.lua` script

# Credits

* [Ciribob](https://forums.eagle.ru/member.php?u=112175)
* [Pikey](https://forums.eagle.ru/member.php?u=62835)