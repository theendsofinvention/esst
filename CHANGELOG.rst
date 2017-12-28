Changelog
=========


0.1.75 (2017-12-28)
-------------------

Fix
~~~
- Fix crash when URVoiceService was already running. [132nd-etcher]

  fix #71


0.1.74 (2017-12-28)
-------------------

New
~~~
- Add config option to control ATIS creation. [132nd-etcher]

Changes
~~~~~~~
- Dev add base classes to export Sentry context. [132nd-etcher]
- Update example config file. [132nd-etcher]
- "dcs_path" config value now points to the root of the DCS
  installation. [132nd-etcher]

Fix
~~~
- Fix a very, very unlikely bug in the DCS loop. [132nd-etcher]

  fix #59
- Rotate logs before the start of DCS. [132nd-etcher]

  fix #62
- Ensure MissionEditor.lua content doesn't change at each run. [132nd-
  etcher]
- Fix erroneous message on server reboot without connect players.
  [132nd-etcher]
- Read "dcs_can_start" value from config at startup. [132nd-etcher]


0.1.73 (2017-12-26)
-------------------

Fix
~~~
- Fix bug when using the "!mission load" command without a mission
  name/number. [132nd-etcher]


0.1.71 (2017-12-26)
-------------------

Fix
~~~
- Infer METAR and ATIS at DCS startup (default mission) [132nd-etcher]


0.1.69 (2017-12-26)
-------------------

Fix
~~~
- Fix issue when setting CPU priority for a closed DCS process. [132nd-
  etcher]

  fix #70


0.1.68 (2017-12-26)
-------------------

Fix
~~~
- Make information identifiers more clear to the ear. [132nd-etcher]


0.1.67 (2017-12-25)
-------------------

New
~~~
- Add "!atis" command for Discord. [132nd-etcher]
- Manage ATIS for all airfields in Caucasus. [132nd-etcher]


0.1.63 (2017-12-20)
-------------------

Fix
~~~
- Fix !server graph returning "None" [132nd-etcher]

  fix #65


0.1.61 (2017-12-20)
-------------------

Fix
~~~
- Fix auto-mission being downloaded in ESST dir (thus not being
  available for loading) [132nd-etcher]

  fix #66


0.1.60 (2017-12-20)
-------------------

Fix
~~~
- Add a catch in the DCS affinity setter for when the DCS process does
  not exist. [132nd-etcher]

  fix #67


0.1.59 (2017-12-20)
-------------------

Changes
~~~~~~~
- Allow for disabling high CPU usage output. [132nd-etcher]


0.1.58 (2017-12-17)
-------------------

Changes
~~~~~~~
- Add an example config file. [132nd-etcher]
- Esst log files are now saved in ESST folder. [132nd-etcher]

Fix
~~~
- Fix loading of wrong mission. [132nd-etcher]


0.1.57 (2017-12-17)
-------------------

Changes
~~~~~~~
- Linting. [132nd-etcher]


0.1.56 (2017-12-04)
-------------------

Fix
~~~
- Fix server graph reporting DCS CPU usage on all cores. [132nd-etcher]

  Since DCS is single-threaded, that was basically useless info. ESST now reports usage from a single core.
- Server graph reporting free memory instead of used memory. [132nd-
  etcher]
- Fix server lag due to socket timeout. [132nd-etcher]

Other
~~~~~
- Add: DCS log rotation. [132nd-etcher]

  fix #52


0.1.54 (2017-11-26)
-------------------

New
~~~
- Add CPU priority and affinity management for DCS process. [132nd-
  etcher]
- Added support for multiple admin roles. [132nd-etcher]


0.1.53 (2017-11-26)
-------------------

Fix
~~~
- Ignore HTTPException from Discord client (just restart it) [132nd-
  etcher]


0.1.52 (2017-10-17)
-------------------

New
~~~
- Add "!dcs log" command to retrieve DCS log file from Discord. [132nd-
  etcher]


0.1.51 (2017-10-17)
-------------------

Changes
~~~~~~~
- Deactivate DCS version check at startup. [132nd-etcher]

  Allow DCS update on the server while I'm away


0.1.50 (2017-10-17)
-------------------

Fix
~~~
- Download auto mission to a separate file. [132nd-etcher]

  Auto mission should not overwrite a mission with the same name already present on the server; that way, weather and other edits are kept separate
  closes #49
- Fix process polling. [132nd-etcher]

  ESST would crash while iterating over process when stumbling upon a recently closed process
  closes #48


0.1.49 (2017-10-15)
-------------------

New
~~~
- Added "!mission delete" and "!mission load" by index. [132nd-etcher]


0.1.47 (2017-09-30)
-------------------

Changes
~~~~~~~
- Manage DCS version 1.5.7.10175. [132nd-etcher]


0.1.46 (2017-09-14)
-------------------

Changes
~~~~~~~
- Add support for DCS 1.5.7.9459. [132nd-etcher]
- Add feedback when trying to start unmanaged DCS version. [132nd-
  etcher]

  closes #46

Fix
~~~
- Fix loading of unchanged missions. [132nd-etcher]

  closes #42
- Accept lower case ICAO codes. [132nd-etcher]

  closes #43


0.1.45 (2017-09-06)
-------------------

Fix
~~~
- "!report" command help text. [132nd-etcher]

  closes #38
- Fixed invalid commands still being executed. [132nd-etcher]

  closes #39
- Fix remove_files config default value. [132nd-etcher]


0.1.43 (2017-09-04)
-------------------

New
~~~
- Add a routine to clean folders of old files. [132nd-etcher]

  closes #23


0.1.42 (2017-09-04)
-------------------

New
~~~
- Add options to "!server graph" commands. [132nd-etcher]

  It's now possible to specify the time delta
- Collect network stats (all NICs combined) [132nd-etcher]

  closes #36

Changes
~~~~~~~
- Remove "!server show-cpu --graph" command. [132nd-etcher]

Other
~~~~~
- Fix fix "!server status" showing weird values for mem perc. [132nd-
  etcher]


0.1.41 (2017-09-03)
-------------------

Fix
~~~
- Don't reload the same mission without change. [132nd-etcher]


0.1.40 (2017-09-03)
-------------------

Fix
~~~
- Fixed protected modules method registering as available chat commands.
  [132nd-etcher]
- Fix "-h" command not registering correctly. [132nd-etcher]


0.1.39 (2017-09-03)
-------------------

New
~~~
- Add "!server graph" command. [132nd-etcher]

  closes #8


0.1.37 (2017-09-03)
-------------------

New
~~~
- Add !report command. [132nd-etcher]

  closes #35


0.1.36 (2017-09-03)
-------------------

Fix
~~~
- Fix regular member having access to the upload mission function.
  [132nd-etcher]


0.1.34 (2017-09-03)
-------------------

New
~~~
- Add "!esst changelog" command. [132nd-etcher]

Fix
~~~
- Fixed Internet connection check being a bit of an arse. [132nd-etcher]
- Fix ESST not sending the exit to DCS via socket (thus killing the
  process for no reason) [132nd-etcher]


0.1.33 (2017-09-03)
-------------------

New
~~~
- Implement roles and permissions. [132nd-etcher]

  closes #33


0.1.32 (2017-09-03)
-------------------

New
~~~
- Add timestamp to discord messages. [132nd-etcher]

  closes #27
- Add "!server ip" command. [132nd-etcher]

  closes #29
- Add feedback to server reboot command. [132nd-etcher]

  closes #26
- Add a YAML dict config to Config() [132nd-etcher]

  closes #25

Fix
~~~
- Do not spam sockets when DCS isn't running in dedicated mode. [132nd-
  etcher]

  closes #19


0.1.29 (2017-08-27)
-------------------

Fix
~~~
- Fix downloading mission from Discord. [132nd-etcher]
- Fix downloading latest mission from Github. [132nd-etcher]
- Fix Discord bot reacting on its own message. [132nd-etcher]


0.1.28 (2017-08-27)
-------------------

New
~~~
- Add support for DCS 1.5.7.8899. [132nd-etcher]

Fix
~~~
- Fix mission switching while DCS is running. [132nd-etcher]
- Add connected player check on "!server reboot" command. [132nd-etcher]
- Dev fix strip_suffix in MissionPath. [132nd-etcher]


0.1.26 (2017-08-27)
-------------------

New
~~~
- Add DCS version to backup files (so updating DCS will generate a new
  backup) [132nd-etcher]

  closes #22
- Add safety check to prevent server restart/kill while players are
  connected. [132nd-etcher]

  closes #18
- Add config option for the grace timeout when DCS closes itself.
  [132nd-etcher]
- Add "!server reboot" command. [132nd-etcher]

  closes #2
- Add "!server show-cpu" command. [132nd-etcher]
- Add "!server status" command. [132nd-etcher]
- Add "!mission load" command. [132nd-etcher]
- Add "!mission download" command. [132nd-etcher]
- Add "!mission weather" command. [132nd-etcher]
- Add command to retrieve log file from Discord. [132nd-etcher]
- Send message when players join/leave. [132nd-etcher]
- Send message when server is ready. [132nd-etcher]
- Config: add config values to omit components at startup. [132nd-
  etcher]
- Config: add config value for DCS CPU usage check interval. [132nd-
  etcher]

Changes
~~~~~~~
- Allow to set both time and weather via the "!mission load" command.
  [132nd-etcher]

  closes #17
- All missions that are edited by ESST will have the "_ESST" suffix
  added to them. [132nd-etcher]
- Update Discord chat commands. [132nd-etcher]

  closes #5
  closes #6
- Dev update discord logging handler. [132nd-etcher]
- Change DCS CPU monitoring mechanism. [132nd-etcher]
- Global CTX object. [132nd-etcher]

Fix
~~~
- Fix capitalization of messages sent to Discord. [132nd-etcher]
- Fix fallback of Discord message queue watcher. [132nd-etcher]
- Fix exit mechanism. [132nd-etcher]

Other
~~~~~
- Add two exception catch in discord_bot. [132nd-etcher]
- Wip. [132nd-etcher]
- This is getting solid. [132nd-etcher]
- Working on it. [132nd-etcher]


0.1.25 (2017-08-22)
-------------------
- Update changelog. [132nd-etcher]
- Update requirements. [132nd-etcher]
- Fix initialization of Discord, DCS and socket when deactivated.
  [132nd-etcher]
- Add Sentry. [132nd-etcher]
- Add SentryContextProvider. [132nd-etcher]
- Make Context a sentry context provider. [132nd-etcher]
- Make config object a context provider for Sentry. [132nd-etcher]
- Add config option for Sentry DSN. [132nd-etcher]
- Add raven dependency. [132nd-etcher]
- Fix wrong logging level in log files. [132nd-etcher]
- Add comment for future reference with OpenAlpha of DCS. [132nd-etcher]
- Update README. [132nd-etcher]
- Update readme. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.22 (2017-08-20)
-------------------
- Update changelog. [132nd-etcher]
- Noqa. [132nd-etcher]
- Remove trailing white space. [132nd-etcher]
- Remove unused imports. [132nd-etcher]
- Add package data to setup.py. [132nd-etcher]
- Fix __set_weather. [132nd-etcher]
- Fix game_gui template. [132nd-etcher]
- Fix dcs restart not showing server status. [132nd-etcher]
- Move dedicated template to its own file. [132nd-etcher]
- Let discord bot restart itself in case of aiohttp error. [132nd-
  etcher]
- Fix performance hit on server. [132nd-etcher]
- Update mission weather management. [132nd-etcher]

  Fixes #12
- No more threads, only asyncio (sic) [132nd-etcher]

  Closes #10


0.1.21 (2017-08-19)
-------------------
- Fix server not restarting when not responding. [132nd-etcher]
- Add requirements. [132nd-etcher]
- Add wheel tag. [132nd-etcher]
- Remove print statement. [132nd-etcher]
- Add epab config. [132nd-etcher]


0.1.20 (2017-08-15)
-------------------
- Removed duplicate output. [132nd-etcher]
- Increase timeout to 30sec when closing DCS. [132nd-etcher]
- Added auto building of metar at mission load. [132nd-etcher]
- Fixed restart command. [132nd-etcher]
- Using context instead of queues for inter-processes communication.
  [132nd-etcher]
- Made auto metar command async compatible. [132nd-etcher]
- Created async_run module. [132nd-etcher]
- Renamed hook options. [132nd-etcher]
- Using click context as message passing mechanism. [132nd-etcher]
- Fixed EMFT running in verbose mode. [132nd-etcher]
- Fixed updating METAR for a running mission. [132nd-etcher]
- Passing metar string to set_active_mission to update status. [132nd-
  etcher]
- Added DCS version check. [132nd-etcher]
- Added click ctx object as abstract prop of Discord bot. [132nd-etcher]
- Removed Discord messages aggregation as it was causing bugs. [132nd-
  etcher]


0.1.19 (2017-08-14)
-------------------
- Reduced the amount of spam. [132nd-etcher]


0.1.18 (2017-08-14)
-------------------
- Added version in default MOTD. [132nd-etcher]


0.1.17 (2017-08-14)
-------------------
- Fixed DCS resetting the metar upon restart. [132nd-etcher]


0.1.16 (2017-08-14)
-------------------
- I'm tired. [132nd-etcher]


0.1.15 (2017-08-14)
-------------------
- Added dependency to EMFT. [132nd-etcher]


0.1.14 (2017-08-14)
-------------------
- Added help for the METAR command. [132nd-etcher]
- Removed useless CPU usage check at process startup. [132nd-etcher]
- Reset Status on DCS restart. [132nd-etcher]
- Fixed Discord output format. [132nd-etcher]
- Added command to change the weather of the active mission. [132nd-
  etcher]
- Fix "!dcs load" command. [132nd-etcher]
- Update gitignore. [132nd-etcher]
- Added util class to run external processes. [132nd-etcher]
- Added missing vars in Status. [132nd-etcher]
- Fixed server startup monitoring. [132nd-etcher]


0.1.13 (2017-08-14)
-------------------
- Published with https://stackedit.io/ [132nd-etcher]
- Added monitoring of multiplayer startup and made timeout configurable.
  [132nd-etcher]
- Trvia removed unused piece of code. [132nd-etcher]
- Group close Discord message together to reduce spamming. [132nd-
  etcher]
- Fixed DCS exit so it doesn't try if the process does not exist.
  [132nd-etcher]
- Moved installation steps outside of DCS threads and made them
  optional. [132nd-etcher]
- Pass context to all threads. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.12 (2017-08-14)
-------------------
- Cleaned up Discord help text. [132nd-etcher]
- Added a delay during execution of commands in dcs module. [132nd-
  etcher]
- Moved GameGUI hook installation do DCS. [132nd-etcher]
- Added a title to the console. [132nd-etcher]
- Set "not running" as the default starting status for DCS app. [132nd-
  etcher]
- Fix player name for the server. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.11 (2017-08-13)
-------------------
- Fix player name for the server. [132nd-etcher]


0.1.10 (2017-08-13)
-------------------
- Published with https://stackedit.io/ [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.9 (2017-08-13)
------------------
- Switched to a way more sensible way to start the dedi remotely.
  [132nd-etcher]
- Fixed call to main classes (minor) [132nd-etcher]
- Added delay in "while True" loops to allow for GIL yield. [132nd-
  etcher]
- Fixed socket thread starting up bonkers. [132nd-etcher]
- Auto_mission is now optional. [132nd-etcher]
- Made MOTD for Discord a config value. [132nd-etcher]


0.1.8 (2017-08-13)
------------------
- Fix wrong variable name in server status. [132nd-etcher]


0.1.7 (2017-08-13)
------------------
- Fix time display in status command. [132nd-etcher]

  fixes #1
- Fixed __main__ not catching KeyboardInterrupt. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.6 (2017-08-13)
------------------
- Removed not so useful call to an error prone function. [132nd-etcher]

  This would crash ESST if the server is killed during startup
- Fixed mouse offset for multiplayer button again, this one should be
  safe enough. [132nd-etcher]


0.1.5 (2017-08-13)
------------------
- Fixed height of "Multi player" button being a tight off. [132nd-
  etcher]


0.1.4 (2017-08-13)
------------------
- Fixed yet another dependency. [132nd-etcher]


0.1.3 (2017-08-13)
------------------
- Forgot yet another dependency. [132nd-etcher]


0.1.2 (2017-08-13)
------------------
- Fixed packaging (dummy me) [132nd-etcher]


0.1.1 (2017-08-13)
------------------
- Fixed missing dependency to click. [132nd-etcher]
- Fixed Discord gateway error while sending message. [132nd-etcher]


0.1.0 (2017-08-13)
------------------
- Initial commit. [132nd-etcher]
- Initial commit. [132nd-etcher]