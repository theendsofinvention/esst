# coding=utf-8
"""
Manages config params for dcs server
"""
from elib.config import ConfigProp

NAMESPACE = 'DCS_SERVER'


class DCSServerConfig:
    """
    Manages config params for dcs server
    """
    dcs_server_name = ConfigProp(str, default='', namespace=NAMESPACE)
    dcs_server_max_players = ConfigProp(int, default='30', namespace=NAMESPACE)
    dcs_server_startup_time = ConfigProp(int, default='120', namespace=NAMESPACE)
    dcs_server_event_role = ConfigProp(str, default='true', namespace=NAMESPACE)
    dcs_server_require_pure_clients = ConfigProp(str, default='false', namespace=NAMESPACE)
    dcs_server_allow_ownship_export = ConfigProp(str, default='true', namespace=NAMESPACE)
    dcs_server_allow_object_export = ConfigProp(str, default='true', namespace=NAMESPACE)
    dcs_server_password = ConfigProp(str, default='', namespace=NAMESPACE)
