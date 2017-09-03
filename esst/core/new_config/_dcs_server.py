# coding=utf-8

from elib.config import ConfigProp

NAMESPACE = 'DCS_SERVER'

class DCSServerConfig:
    @ConfigProp(str, namespace=NAMESPACE)
    def dcs_server_name(self):
        pass

    @ConfigProp(int, namespace=NAMESPACE)
    def dcs_server_max_players(self):
        pass

    @ConfigProp(int, 120, namespace=NAMESPACE)
    def dcs_server_startup_time(self):
        pass

    @ConfigProp(str, 'true', namespace=NAMESPACE)
    def dcs_server_event_role(self):
        pass

    @ConfigProp(str, 'false', namespace=NAMESPACE)
    def dcs_server_require_pure_clients(self):
        pass

    @ConfigProp(str, 'true', namespace=NAMESPACE)
    def dcs_server_allow_ownship_export(self):
        pass

    @ConfigProp(str, 'true', namespace=NAMESPACE)
    def dcs_server_allow_object_export(self):
        pass
