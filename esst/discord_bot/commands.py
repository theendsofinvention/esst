# coding=utf-8

from esst.core import CTX


class DISCORD:
    @staticmethod
    def say(message):
        CTX.discord_msg_queue.put(message)
