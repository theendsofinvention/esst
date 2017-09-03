# coding=utf-8

from elib.config import ConfigProp

NAMESPACE = 'DCS'


class DCSConfig:
    @ConfigProp(str, namespace=NAMESPACE)
    def dcs_path(self):
        pass

    @ConfigProp(int, 5, namespace=NAMESPACE)
    def dcs_idle_cpu_usage(self):
        pass

    @ConfigProp(int, 80, namespace=NAMESPACE)
    def dcs_high_cpu_usage(self):
        pass

    @ConfigProp(int, 5, namespace=NAMESPACE)
    def dcs_high_cpu_usage_interval(self):
        pass

    @ConfigProp(int, 30, namespace=NAMESPACE)
    def dcs_ping_interval(self):
        pass

    @ConfigProp(int, 30, namespace=NAMESPACE)
    def dcs_grace_period(self):
        pass

    @ConfigProp(str, namespace=NAMESPACE)
    def dcs_server_password(self):
        pass
