Changelog
=========
(unreleased)
------------
Fix
~~~
- Fix "!dcs status" command error. [etcher]
  The command will show "unknown" instead of crashing in case a given
  value is missing.
2018.10.23.2 (2018-10-23)
-------------------------
Fix
~~~
- Fix typo in config (#42) [etcher]
  * fix: fix config value for DCS grace period.
  DCS 'start_grace_period' and 'close_grace_period' were swapped in the
  config.
2018.10.23.1 (2018-10-23)
-------------------------
- Build(deps): bump numpy from 1.15.2 to 1.15.3. [dependabot[bot]]
  Bumps [numpy](http://www.numpy.org) from 1.15.2 to 1.15.3.
- Build(deps): bump elib-wx from 2018.10.14.2 to 2018.10.22.2.
  [dependabot[bot]]
  Bumps [elib-wx](https://github.com/etcher-be/elib_wx) from 2018.10.14.2 to 2018.10.22.2.
  - [Release notes](https://github.com/etcher-be/elib_wx/releases)
  - [Commits](https://github.com/etcher-be/elib_wx/compare/2018.10.14.2...2018.10.22.2)
2018.10.21.1 (2018-10-21)
-------------------------
- Build(deps-dev): bump epab from 2018.10.17.1 to 2018.10.21.1.
  [dependabot[bot]]
  Bumps [epab](https://github.com/132nd-etcher/EPAB) from 2018.10.17.1 to 2018.10.21.1.
  - [Release notes](https://github.com/132nd-etcher/EPAB/releases)
  - [Changelog](https://github.com/etcher-be/epab/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/132nd-etcher/EPAB/compare/2018.10.19.1a2+dependabot/pip/elib-run-2018.10.17.1...2018.10.21.1)
2018.10.19.1 (2018-10-19)
-------------------------
New
~~~
- Elib_config, elib_wx, elib_miz (#26) [etcher]
  * chg: dev: use single LOGGER object
  * chg: dev: move FS to root package
  * chg: dev: sanitize ATIS package
  * fix: fix bug in history graph
  Sometimes the processes pool from concurrent.futures would break.
  The fix is to simply re-instantiate it each time.
  * chg: dev: sanitize Sentry package
  * chg: switch to TOML config
  fixes #19
  * fix: fix deleted 3rd party library ipgetter
  The library was used to obtain the external IP. Switched to simple
  requests + https://www.ipify.org/.
  * chg: dev: update reqs
  * chg: dev: move basic FS utils funcs
  * fix: prevent start when WAN unavailable
  Simply adds a check at ESST startup.
  If no WAN connection is available, ESST will simply not start.
  * chg: dev: trivia
  * chg: dev: linting
  * fix: dev: pylint fix
  * fix: dev: fix mypy
  * chg: dev: add comments for later
  * chg: dev: remove irrelevant comments
  * chg: dev: sanitize elib_config_import
  * fix: dev: format Discord logger records
  * fix: fix CPU affinity warning message
  * fix: fix repeated message when DCS is blocked
  When starting DCS is block for any reason (no WAN connection, mission
  currently loading, ...), a message is shown on the Discord channel).
  Due to a bug, that message might have been repeated multiple times.
  fixes #23
  * chg: switch to elib_wx (and elib_miz)
  This allows ESST to understand North American weather, and work
  with pretty much all the different METARs formats out there.
  WARNING: this feature has been tested in and out programatically
  and to the best of my ability, but real-world testing is sorely needed.
  Tread with care.
  fixes #17
  * new: add a command to preview the weather
  The new "!weather show" command allows for sneak-peak into real-life
  weather without applying them to MIZ files.
  Example: "!weather show KLAS"
  This commands output the METAR string, a textual description of the
  real-life weather (as described by the METAR string), and an example
  of a DCS weather as it would be generated from that METAR.
  fixes #18
  * new: add "--dcs" switch to "!mission weather"
  In regular mode, "!mission weather" will print a textual description
  of the weather in the running mission.
  With the "--dcs" switch, ESST will print the weather as it actually is
  in DCS, outputting the raw values for all managed weather parameters
  (such as wind direction at 2000m in DCS format, fog visibility, etc.).
  * chg: dev: add LUA code for later
  #20
  * fix: dev: linting
  * fix: dev: remove unused file
  * chg: dev: update reqs
  * fix: dev: update reqs
  * fix: fix error in "!atis showfor" command
  If no weather information is available, ESST will say so instead of
  throwing an error.
  * fix: dev: linting
  * fix: fix DCS server config
  Please have a look at the [dcs_server] section (and its subsections)
  in your "esst.toml" file. Updated values will be shown in
  "esst.toml.example" after the first run of ESST.
  * fix: fix historygraph
  Made the function synchronous for the time being.
  * chg: dev: update reqs
  * fix: dev: close historygraph plot
2018.10.01.1 (2018-10-01)
-------------------------
Fix
~~~
- Monkeypatch gtts (#22) [etcher]
  * update reqs (elib->gtts)
2018.09.22.1 (2018-09-22)
-------------------------
Changes
~~~~~~~
- Vendor avwx (#16) [etcher]
  * fix: fix "!atis show" note
  * update reqs
  * chg: dev: update reqs
  * chg: dev: update reqs again
2018.09.16.2 (2018-09-16)
-------------------------
New
~~~
- Add NTTR airports (#14) [etcher]
  * new: dev: add NTTR airports to db
  * chg: move ATIS file in "atis" folder
  * chg: rename "!atis frequencies" to "!atis show"
  * chg: rename "!atis show" to "!atis showfor"
  * chg: add ICAO prefix to '!atis show'
2018.09.16.1 (2018-09-16)
-------------------------
Changes
~~~~~~~
- Update emiz (#13) [etcher]
  * fix: dev: fix tests nuking my config all the time
  * chg: dev: update reqs
2018.09.15.2 (2018-09-15)
-------------------------
Changes
~~~~~~~
- Randomize socket port (#9) [etcher]
  * chg: dev: update reqs
  * fix: dev: fix tests nuking my config all the time
  * chg: randomly assign socket ports
  This should allow for multiple instances of ESST to coexist on the same
  system for the time being.
  * chg: dev: linting
  * fix: dev: sanitize ports range
2018.09.15.1 (2018-09-15)
-------------------------
Changes
~~~~~~~
- Add dcs server options (#8) [etcher]
  * chg: added a bunch of DCS server options
  Here's the list with given defaults:
  (example config file section)
  dcs_server:
      name = ''
      max_players = '30'
      startup_time = '120'
      event_role = 'true'
      require_pure_clients = 'false'
      allow_ownship_export = 'true'
      allow_object_export = 'true'
      password = ''
      pause_on_load = 'false'
      pause_without_clients = 'false'
      event_connect = 'true'
      allow_sensor_export = 'true'
      is_public = 'true'
      event_ejecting = 'false'
      event_kill = 'false'
      event_takeoff = 'false'
      client_outbound_limit = '0'
      event_crash = 'false'
      client_inbound_limit = '0'
      resume_mode = '1'
2018.09.09.2 (2018-09-09)
-------------------------
Fix
~~~
- Fix pyinstaller data files. [etcher]
2018.09.09.1 (2018-09-09)
-------------------------
Fix
~~~
- Get DCS version (#6) [etcher]
  * update gitignore
  * fix the issue with getting the DCS version
  * disable "remov old files" functionality
  There's an issue with parsedatetime & pyinstaller, and I needed to
  freeze. I'll re-implement without parsedatetime.
  * add pyproject.toml (newer EPAB)
  * update reqs
  * linting
  * update .gitignore
  * update reqs
2018.06.15.2 (2018-06-15)
-------------------------
Fix
~~~
- Fix auto start (#115) [132nd-etcher]
  * update me_auth template
  * update .gitignore
  * update reqs
  * mypy fixes
  * update reqs
  * linting
  * update reqs
  * fix missing dependency
2018.06.15.1 (2018-06-15)
-------------------------
- Feature/fix auto start (#114) [132nd-etcher]
  * update me_auth template
  * update .gitignore
  * update reqs
  * mypy fixes
  * update reqs
  * linting
  * update reqs
2018.05.13.1 (2018-05-13)
-------------------------
Changes
~~~~~~~
- Change Kutaisi runway heading from 25 to 26 (#113) [132nd-etcher]
2018.04.28.1 (2018-04-28)
-------------------------
Fix
~~~
- Fix pagefile issue when probing for dcs.exe (#111) [132nd-etcher]
  * ignore log files
  * fix pagefile saturation issue
  * linting
  * unignore pipfile.lock
  * fix setup.py fir pip 10.0.0
2018.4.5.1 (2018-04-05)
-----------------------
Changes
~~~~~~~
- Atis freqs (#109) [132nd-etcher]
  * ignore main.html
  * change all ATIS frequencies from .400 to .300
  * fix Maykop location
2018.4.2.1 (2018-04-02)
-----------------------
New
~~~
- Add full ATIS speech to "!atis show" command. [132nd-etcher]
  fix #77
- Implemented !esst restart command. [132nd-etcher]
- Add config option to control ATIS creation. [132nd-etcher]
- Add "!atis" command for Discord. [132nd-etcher]
- Manage ATIS for all airfields in Caucasus. [132nd-etcher]
- Add CPU priority and affinity management for DCS process. [132nd-
  etcher]
- Added support for multiple admin roles. [132nd-etcher]
- Add "!dcs log" command to retrieve DCS log file from Discord. [132nd-
  etcher]
- Added "!mission delete" and "!mission load" by index. [132nd-etcher]
- Add a routine to clean folders of old files. [132nd-etcher]
  closes #23
- Add options to "!server graph" commands. [132nd-etcher]
  It's now possible to specify the time delta
- Collect network stats (all NICs combined) [132nd-etcher]
  closes #36
- Add "!server graph" command. [132nd-etcher]
  closes #8
- Add !report command. [132nd-etcher]
  closes #35
- Add "!esst changelog" command. [132nd-etcher]
- Implement roles and permissions. [132nd-etcher]
  closes #33
- Add timestamp to discord messages. [132nd-etcher]
  closes #27
- Add "!server ip" command. [132nd-etcher]
  closes #29
- Add feedback to server reboot command. [132nd-etcher]
  closes #26
- Add a YAML dict config to Config() [132nd-etcher]
  closes #25
- Add support for DCS 1.5.7.8899. [132nd-etcher]
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
- Atis multiprocessing (#93) [132nd-etcher]
  * reduce ATIS generation time
  Down from ~40 seconds to ~3 seconds
  * update reqs
  * update reqs
- Dev add base classes to export Sentry context. [132nd-etcher]
- Update example config file. [132nd-etcher]
- "dcs_path" config value now points to the root of the DCS
  installation. [132nd-etcher]
- Allow for disabling high CPU usage output. [132nd-etcher]
- Add an example config file. [132nd-etcher]
- Esst log files are now saved in ESST folder. [132nd-etcher]
- Linting. [132nd-etcher]
- Deactivate DCS version check at startup. [132nd-etcher]
  Allow DCS update on the server while I'm away
- Manage DCS version 1.5.7.10175. [132nd-etcher]
- Add support for DCS 1.5.7.9459. [132nd-etcher]
- Add feedback when trying to start unmanaged DCS version. [132nd-
  etcher]
  closes #46
- Remove "!server show-cpu --graph" command. [132nd-etcher]
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
- Emiz error (#107) [132nd-etcher]
  * ignore pytest cache
  * update reqs
  * fix error in fs_paths
- Atis speech (#99) [132nd-etcher]
  * fix ICAO included in the start of the ATIS speech
  * fix ATIS speech
  * remove debug code
  * add current version as Sentry release
  * fix "!atis show" command
  fix #97
  * update reqs
  fix #98
  fix #100
  * simplify generate_atis
  * linting
- Fix saved games folder (#91) [132nd-etcher]
  * major refactor
  * linting
  * variant should return absolute path
  * remove unnecessary else clauses
  * fix tests
  * linting
  * fix a few issues with the historygraph
  * ignore test files
  * simplify historygraph
  * linting
  * remove useless try block
  * slight refac of fs_paths init
  * fix tests
  * reduce complexity
  * linting
  fix #89
- Show correct ATIS identification letter with "!atis show <ICAO>"
  [132nd-etcher]
  fix #76
- Fix wrong ATIS for UGKS. [132nd-etcher]
  fix #72
- Fix DCS API hook for 1.5.8. [132nd-etcher]
  "!dcs status" command will work again, as will the "soft kill" command used to restart DCS
- Fix affinity & priority setting bug when DCS does not exist. [132nd-
  etcher]
- Fix bound socket issue at start. [132nd-etcher]
- Auto-mission name. [132nd-etcher]
- Fix crash when URVoiceService was already running. [132nd-etcher]
  fix #71
- Fix a very, very unlikely bug in the DCS loop. [132nd-etcher]
  fix #59
- Rotate logs before the start of DCS. [132nd-etcher]
  fix #62
- Ensure MissionEditor.lua content doesn't change at each run. [132nd-
  etcher]
- Fix erroneous message on server reboot without connect players.
  [132nd-etcher]
- Read "dcs_can_start" value from config at startup. [132nd-etcher]
- Fix bug when using the "!mission load" command without a mission
  name/number. [132nd-etcher]
- Infer METAR and ATIS at DCS startup (default mission) [132nd-etcher]
- Fix issue when setting CPU priority for a closed DCS process. [132nd-
  etcher]
  fix #70
- Make information identifiers more clear to the ear. [132nd-etcher]
- Fix !server graph returning "None" [132nd-etcher]
  fix #65
- Fix auto-mission being downloaded in ESST dir (thus not being
  available for loading) [132nd-etcher]
  fix #66
- Add a catch in the DCS affinity setter for when the DCS process does
  not exist. [132nd-etcher]
  fix #67
- Fix loading of wrong mission. [132nd-etcher]
- Fix server graph reporting DCS CPU usage on all cores. [132nd-etcher]
  Since DCS is single-threaded, that was basically useless info. ESST now reports usage from a single core.
- Server graph reporting free memory instead of used memory. [132nd-
  etcher]
- Fix server lag due to socket timeout. [132nd-etcher]
- Ignore HTTPException from Discord client (just restart it) [132nd-
  etcher]
- Download auto mission to a separate file. [132nd-etcher]
  Auto mission should not overwrite a mission with the same name already present on the server; that way, weather and other edits are kept separate
  closes #49
- Fix process polling. [132nd-etcher]
  ESST would crash while iterating over process when stumbling upon a recently closed process
  closes #48
- Fix loading of unchanged missions. [132nd-etcher]
  closes #42
- Accept lower case ICAO codes. [132nd-etcher]
  closes #43
- "!report" command help text. [132nd-etcher]
  closes #38
- Fixed invalid commands still being executed. [132nd-etcher]
  closes #39
- Fix remove_files config default value. [132nd-etcher]
- Don't reload the same mission without change. [132nd-etcher]
- Fixed protected modules method registering as available chat commands.
  [132nd-etcher]
- Fix "-h" command not registering correctly. [132nd-etcher]
- Fix regular member having access to the upload mission function.
  [132nd-etcher]
- Fixed Internet connection check being a bit of an arse. [132nd-etcher]
- Fix ESST not sending the exit to DCS via socket (thus killing the
  process for no reason) [132nd-etcher]
- Do not spam sockets when DCS isn't running in dedicated mode. [132nd-
  etcher]
  closes #19
- Fix downloading mission from Discord. [132nd-etcher]
- Fix downloading latest mission from Github. [132nd-etcher]
- Fix Discord bot reacting on its own message. [132nd-etcher]
- Fix mission switching while DCS is running. [132nd-etcher]
- Add connected player check on "!server reboot" command. [132nd-etcher]
- Dev fix strip_suffix in MissionPath. [132nd-etcher]
- Fix capitalization of messages sent to Discord. [132nd-etcher]
- Fix fallback of Discord message queue watcher. [132nd-etcher]
- Fix exit mechanism. [132nd-etcher]
Other
~~~~~
- Linting. [132nd-etcher]
- Remove versioneer. [132nd-etcher]
- Add: DCS log rotation. [132nd-etcher]
  fix #52
- Fix fix "!server status" showing weird values for mem perc. [132nd-
  etcher]
- Add two exception catch in discord_bot. [132nd-etcher]
- Wip. [132nd-etcher]
- This is getting solid. [132nd-etcher]
- Working on it. [132nd-etcher]
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
- Update changelog. [132nd-etcher]
- Noqa. [132nd-etcher]
- Remove trailing white space. [132nd-etcher]
- Remove unused imports. [132nd-etcher]
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
- Fix server not restarting when not responding. [132nd-etcher]
- Add requirements. [132nd-etcher]
- Add wheel tag. [132nd-etcher]
- Remove print statement. [132nd-etcher]
- Add epab config. [132nd-etcher]
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
- Reduced the amount of spam. [132nd-etcher]
- Added version in default MOTD. [132nd-etcher]
- Fixed DCS resetting the metar upon restart. [132nd-etcher]
- I'm tired. [132nd-etcher]
- Added dependency to EMFT. [132nd-etcher]
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
- Fix player name for the server. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]
- Cleaned up Discord help text. [132nd-etcher]
- Added a delay during execution of commands in dcs module. [132nd-
  etcher]
- Moved GameGUI hook installation do DCS. [132nd-etcher]
- Added a title to the console. [132nd-etcher]
- Set "not running" as the default starting status for DCS app. [132nd-
  etcher]
- Fix player name for the server. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]
- Switched to a way more sensible way to start the dedi remotely.
  [132nd-etcher]
- Fixed call to main classes (minor) [132nd-etcher]
- Added delay in "while True" loops to allow for GIL yield. [132nd-
  etcher]
- Fixed socket thread starting up bonkers. [132nd-etcher]
- Auto_mission is now optional. [132nd-etcher]
- Made MOTD for Discord a config value. [132nd-etcher]
- Fix wrong variable name in server status. [132nd-etcher]
- Fix time display in status command. [132nd-etcher]
  fixes #1
- Fixed __main__ not catching KeyboardInterrupt. [132nd-etcher]
- Published with https://stackedit.io/ [132nd-etcher]
- Removed not so useful call to an error prone function. [132nd-etcher]
  This would crash ESST if the server is killed during startup
- Fixed mouse offset for multiplayer button again, this one should be
  safe enough. [132nd-etcher]
- Fixed height of "Multi player" button being a tight off. [132nd-
  etcher]
- Fixed yet another dependency. [132nd-etcher]
- Fixed packaging (dummy me) [132nd-etcher]
- Fixed missing dependency to click. [132nd-etcher]
- Fixed Discord gateway error while sending message. [132nd-etcher]
- Initial commit. [132nd-etcher]
- Initial commit. [132nd-etcher]