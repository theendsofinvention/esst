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
    @ConfigProp(str, '', namespace=NAMESPACE)
    def dcs_server_name(self) -> int:
        """
        Public name of the DCS server
        """
        pass

    @ConfigProp(int, 30, namespace=NAMESPACE)
    def dcs_server_max_players(self) -> int:
        """
        Maximum number of players allowed on the server
        """
        pass

    @ConfigProp(int, 120, namespace=NAMESPACE)
    def dcs_server_startup_time(self):
        """
        Period of grace allowed between the moment the DCS application is started and the moment the server
        is ready to accept players
        """
        pass

    @ConfigProp(str, 'true', namespace=NAMESPACE)
    def dcs_server_event_role(self):
        """
        Allow export of EVENT_ROLE
        """
        pass

    @ConfigProp(str, 'false', namespace=NAMESPACE)
    def dcs_server_require_pure_clients(self):
        """
        Enforce data integrity on the server
        """
        pass

    @ConfigProp(str, 'true', namespace=NAMESPACE)
    def dcs_server_allow_ownship_export(self):
        """
        Allow export of own ship data
        """
        pass

    @ConfigProp(str, 'true', namespace=NAMESPACE)
    def dcs_server_allow_object_export(self):
        """
        Allow export of other objects data
        """
        pass

    @ConfigProp(str, '', namespace=NAMESPACE)
    def dcs_server_password(self):
        """
        Password of the server
        """
        pass
