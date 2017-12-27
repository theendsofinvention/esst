# coding=utf-8
"""
UniversRadio status
"""
import esst.utils.sentry_context


class Status(esst.utils.sentry_context.SentryClassContext):
    """
    UniversRadio status
    """

    def __init__(self):
        pass

    install_path = 'unknown'
    settings_folder = 'unknown'
    voice_settings_file = 'unknown'
