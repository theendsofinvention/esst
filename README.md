# ESST

ESST stands for Etcher's Server Startup Tool.

## Functionalities

The tool is composed of three main parts:

* The DCS server manager: this is responsible for spawning (or connecting to) a DCS.exe process. It will also try it's
 best to keep it alive, and restart it in case it crashes
* A UDP socket: this little one is responsible for enabling communication between DCS and ESST. Messages are sent back
and forth between the two of them. DCS sends regular updates with the status of the server, the connected players
list, etc., while ESST can send command to DCS, for example asking it to exit gracefully before a restart.
* A Discord bot: this is a two communication between ESST and a Discord channel on the Wing's server. ESST publishes
updates about the server status, and members of the server are able to send commands to the dedicated server via the
same channel.

## Initial setup

First, you'll need to create a Discord application:

1. Go to [https://discordapp.com/developers/applications/me](https://discordapp.com/developers/applications/me)