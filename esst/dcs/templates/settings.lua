cfg =
{
    ["listShuffle"] = false,
    ["isPublic"] = {{ is_public }},
    ["description"] = "{{ description }}",
    ["require_pure_textures"] = {{ require_pure_textures }},
    ["version"] = 1,
    ["missionList"] =
    {
        [1] = "{{ mission_file_path }}",
    }, -- end of ["missionList"]
    ["advanced"] =
    {
        ["allow_change_tailno"] = {{ allow_change_tailno }},
        ["allow_ownship_export"] = {{ allow_ownship_export }},
        ["allow_object_export"] = {{ allow_object_export }},
        ["pause_on_load"] = {{ pause_on_load }},
        ["allow_sensor_export"] = {{ allow_sensor_export }},
        ["event_Takeoff"] = {{ event_Takeoff }},
        ["pause_without_clients"] = {{ pause_without_clients }},
        ["client_outbound_limit"] = {{ client_outbound_limit }},
        ["client_inbound_limit"] = {{ client_inbound_limit }},
        ["event_Role"] = {{ event_Role }},
        ["allow_change_skin"] = {{ allow_change_skin }},
        ["event_Connect"] = {{ event_Connect }},
        ["event_Ejecting"] = {{ event_Ejecting }},
        ["event_Kill"] = {{ event_Kill }},
        ["event_Crash"] = {{ event_Crash }},
        ["resume_mode"] = {{ resume_mode }},
        ["maxPing"] = {{ maxPing }},
    }, -- end of ["advanced"]
    ["require_pure_models"] = {{ require_pure_models }},
    ["require_pure_clients"] = {{ require_pure_clients }},
    ["name"] = "{{ name }}",
    ["port"] = "{{ port }}",
    ["password"] = "{{ password }}",
    ["listLoop"] = false,
    ["bind_address"] = "{{ bind_address }}",
    ["maxPlayers"] = {{ maxPlayers }},
} -- end of cfg

