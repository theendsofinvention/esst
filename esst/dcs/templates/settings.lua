cfg =
{
    ["isPublic"] = {{ is_public }},
    ["missionList"] =
    {
        [1] = "{{ mission_file_path }}",
    }, -- end of ["missionList"]
    ["bind_address"] = "",
    ["port"] = "10308",
    ["advanced"] =
    {
        ["event_Role"] = {{ event_role }},
        ["allow_ownship_export"] = {{ allow_ownship_export }},
        ["allow_object_export"] = {{ allow_object_export }},
        ["pause_on_load"] = {{ pause_on_load }},
        ["event_Connect"] = {{ event_connect }},
        ["event_Ejecting"] = {{ event_ejecting }},
        ["event_Kill"] = {{ event_kill }},
        ["event_Takeoff"] = {{ event_takeoff }},
        ["pause_without_clients"] = {{ pause_without_clients }},
        ["client_outbound_limit"] = {{ client_outbound_limit }},
        ["event_Crash"] = {{ event_crash }},
        ["client_inbound_limit"] = {{ client_inbound_limit }},
        ["resume_mode"] = {{ resume_mode }},
        ["allow_sensor_export"] = {{ allow_sensor_export }},
    }, -- end of ["advanced"]
    ["password"] = "{{ passwd }}",
    ["require_pure_clients"] = false,
    ["version"] = 1,
    ["description"] = "",
    ["name"] = "{{ name }}",
    ["listLoop"] = false,
    ["listShuffle"] = false,
    ["maxPlayers"] = {{ max_players }},
} -- end of cfg
