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

    @ConfigProp(str, '', namespace=NAMESPACE)
    def dcs_path(self):
        """
        Path of the DCS installation to manage
        """
        pass

    @ConfigProp(int, 5, namespace=NAMESPACE)
    def dcs_idle_cpu_usage(self):
        """
        Maximum percentage of CPU allowed to be considered "idle"
        """
        pass

    @ConfigProp(int, 0, namespace=NAMESPACE)
    def dcs_high_cpu_usage(self):
        """
        Maximum amount of CPU usage allowed before sending an alert
        """
        pass

    @ConfigProp(int, 5, namespace=NAMESPACE)
    def dcs_high_cpu_usage_interval(self):
        """
        Interval of time between each CPU probe while the DCS application is running
        """
        pass

    @ConfigProp(int, 30, namespace=NAMESPACE)
    def dcs_ping_interval(self):
        """
        Maximum amount of seconds allowed between pings before sending an alert

        The server normally sends ping every 5 seconds
        """
        pass

    @ConfigProp(int, 30, namespace=NAMESPACE)
    def dcs_grace_period(self):
        """
        Amount of seconds given to DCS to close itself after issuing the "exit" command via socket; if that
        period is exceeded, DCS application will be forcibly killed
        """
        pass

    @ConfigProp(list, default='', namespace=NAMESPACE)
    def dcs_cpu_affinity(self):
        """
        CPU affinity for the DCS process.
        """
        pass

    @ConfigProp(str, default='', namespace=NAMESPACE)
    def dcs_cpu_priority(self):
        """
        CPU priority for the DCS process.
        """
        pass

    @ConfigProp(str, default='', namespace=NAMESPACE)
    def dcs_delete_logs_older_than(self):
        """
        CPU priority for the DCS process.
        """
        pass
