# coding=utf-8

from elib.config import ConfigProp

NAMESPACE = 'AUTO_MISSION'


class AutoMissionConfig:
    @ConfigProp(str, namespace=NAMESPACE, default='')
    def auto_mission_github_token(self):
        pass

    @ConfigProp(str, namespace=NAMESPACE, default='')
    def auto_mission_github_owner(self):
        pass

    @ConfigProp(str, namespace=NAMESPACE, default='')
    def auto_mission_github_repo(self):
        pass
