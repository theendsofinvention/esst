# coding=utf-8
"""
Manages config params for dcs application
"""

from elib.config import ConfigProp

NAMESPACE = 'DCS'


class DCSConfig:
    """
    Manages config params for dcs application
    """

    dcs_path = ConfigProp(str, default='', namespace=NAMESPACE)
    dcs_idle_cpu_usage = ConfigProp(int, default='5', namespace=NAMESPACE)
    dcs_high_cpu_usage = ConfigProp(int, default='0', namespace=NAMESPACE)
    dcs_high_cpu_usage_interval = ConfigProp(int, default='5', namespace=NAMESPACE)
    dcs_ping_interval = ConfigProp(int, default='30', namespace=NAMESPACE)
    dcs_grace_period = ConfigProp(int, default='30', namespace=NAMESPACE)
    dcs_cpu_affinity = ConfigProp(list, default='', namespace=NAMESPACE)
    dcs_cpu_priority = ConfigProp(str, default='', namespace=NAMESPACE)
    dcs_delete_logs_older_than = ConfigProp(str, default='', namespace=NAMESPACE)
    dcs_can_start = ConfigProp(bool, default='true')
