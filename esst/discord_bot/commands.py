# coding=utf-8

from esst.core import CTX


class DISCORD:
    @staticmethod
    def say(message):
        CTX.discord_msg_queue.put(message)

    @staticmethod
    def send(file_path):
        CTX.discord_file_queue.put(file_path)
