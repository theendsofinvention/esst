Changelog
=========


0.1.22 (2017-08-20)
-------------------
- Add package data to setup.py. [132nd-etcher]
- Fix __set_weather. [132nd-etcher]
- Fix game_gui template. [132nd-etcher]
- Fix dcs restart not showing server status. [132nd-etcher]
- Trivia (pep8 formatting) [132nd-etcher]
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
- Fix server not restarting when not responding. [132nd-etcher]
- Add requirements. [132nd-etcher]
- Add wheel tag. [132nd-etcher]
- Remove print statement. [132nd-etcher]
- Add epab config. [132nd-etcher]


0.1.20 (2017-08-15)
-------------------
- Removed Discord messages aggregation as it was causing bugs added DCS
  version check fixed updating METAR for a running mission fixed EMFT
  running in verbose mode made auto metar command async compatible using
  context instead of queues for inter-processes communication fixed
  restart command added auto building of metar at mission load increase
  timeout to 30sec when closing DCS. [132nd-etcher]
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
- Reduced the amount of spam. [132nd-etcher]


0.1.18 (2017-08-14)
-------------------
- Added version in default MOTD. [132nd-etcher]
- Added version in default MOTD. [132nd-etcher]


0.1.17 (2017-08-14)
-------------------
- Fixed DCS resetting the metar upon restart. [132nd-etcher]
- Fixed DCS resetting the metar upon restart. [132nd-etcher]


0.1.16 (2017-08-14)
-------------------
- I'm tired. [132nd-etcher]
- I'm tired. [132nd-etcher]


0.1.15 (2017-08-14)
-------------------
- Added dependency to EMFT. [132nd-etcher]
- Added dependency to EMFT. [132nd-etcher]


0.1.14 (2017-08-14)
-------------------
- Fixed server startup monitoring added missing vars in Status added
  util class to run external processes update gitignore fix "!dcs load"
  command added command to change the weather of the active mission
  fixed Discord output format reset Status on DCS restart trivial fixes
  trivial fixes added help for the METAR command. [132nd-etcher]
- Added help for the METAR command. [132nd-etcher]
- Removed useless CPU usage check at process startup. [132nd-etcher]
- Trivial fixes. [132nd-etcher]
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
- Added monitoring of multiplayer startup and made timeout configurable
  fixed DCS exit so it doesn't try if the process does not exist moved
  installation steps outside of DCS threads and made them optionalpass
  context to all threads group close Discord message together to reduce
  spamming. [132nd-etcher]
- Merge remote-tracking branch 'origin/develop' into develop. [132nd-
  etcher]
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
- Merge remote-tracking branch 'origin/master' into develop. [132nd-
  etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.12 (2017-08-14)
-------------------
- Fix player name for the server set "not running" as the default
  starting status for DCS app added a title to the console moved GameGUI
  hook installation do DCS added a delay during execution of commands in
  dcs module cleaned up Discord help text. [132nd-etcher]
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
- Fix player name for the server. [132nd-etcher]


0.1.10 (2017-08-13)
-------------------
- Update README. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]
- Merge branch 'develop' [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.9 (2017-08-13)
------------------
- Made MOTD for Discord a config value auto_mission is now optional
  fixed socket thread starting up bonkers added delay in "while True"
  loops to allow for GIL yield switched to a way more sensible way to
  start the dedi remotely. [132nd-etcher]
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
- Fix wrong variable name in server status. [132nd-etcher]


0.1.7 (2017-08-13)
------------------
- Fix time display in status command fixed __main__ not catching
  KeyboardInterrupt added README. [132nd-etcher]
- Fix time display in status command. [132nd-etcher]

  fixes #1
- Fixed __main__ not catching KeyboardInterrupt. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]


0.1.6 (2017-08-13)
------------------
- Removed not so useful call to an error prone function fixed mouse
  offset for multiplayer button again, this one should be safe enough.
  [132nd-etcher]
- Removed not so useful call to an error prone function. [132nd-etcher]

  This would crash ESST if the server is killed during startup
- Fixed mouse offset for multiplayer button again, this one should be
  safe enough. [132nd-etcher]


0.1.5 (2017-08-13)
------------------
- Fixed height of "Multi player" button being a tight off. [132nd-
  etcher]
- Fixed height of "Multi player" button being a tight off. [132nd-
  etcher]


0.1.4 (2017-08-13)
------------------
- Fixed yet another dependency. [132nd-etcher]
- Fixed yet another dependency. [132nd-etcher]


0.1.3 (2017-08-13)
------------------
- Forgot yet another dependency. [132nd-etcher]
- Forgot yet another dependency. [132nd-etcher]


0.1.2 (2017-08-13)
------------------
- Fixed packaging (dummy me) [132nd-etcher]
- Fixed packaging (dummy me) [132nd-etcher]


0.1.1 (2017-08-13)
------------------
- Fixed missing dependency to click fixed Discord gateway error while
  sending message. [132nd-etcher]
- Fixed missing dependency to click. [132nd-etcher]
- Fixed Discord gateway error while sending message. [132nd-etcher]


0.1.0 (2017-08-13)
------------------
- Initial commit. [132nd-etcher]
- Initial commit. [132nd-etcher]