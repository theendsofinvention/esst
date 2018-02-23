# coding=utf-8
"""
Manages config params for auto mission
"""

from elib.config import ConfigProp

NAMESPACE = 'AUTO_MISSION'


class AutoMissionConfig:
    """
    Manages config params for auto mission
    """
    auto_mission_github_token = ConfigProp(str, namespace=NAMESPACE, default='')
    auto_mission_github_owner = ConfigProp(str, namespace=NAMESPACE, default='')
    auto_mission_github_repo = ConfigProp(str, namespace=NAMESPACE, default='')
