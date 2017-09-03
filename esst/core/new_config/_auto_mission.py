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
    @ConfigProp(str, namespace=NAMESPACE, default='')
    def auto_mission_github_token(self):
        """
        Optional Github token to perform the requests (allow to bypass the API rate limitation)
        """
        pass

    @ConfigProp(str, namespace=NAMESPACE, default='')
    def auto_mission_github_owner(self):
        """
        Name of the user/organization that owns the repo
        """
        pass

    @ConfigProp(str, namespace=NAMESPACE, default='')
    def auto_mission_github_repo(self):
        """
        Name of the repo
        """
        pass
