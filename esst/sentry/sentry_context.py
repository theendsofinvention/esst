# coding=utf-8
"""
Manages base classes for Sentry contexts
"""
import inspect


class SentryClassContext:
    """
    Base class for data class (class methods only)
    """

    @classmethod
    def get_context(cls) -> dict:
        """

        Returns: dict context for Sentry

        """
        return {
            member: value
            for member, value in inspect.getmembers(cls, lambda a: not inspect.ismethod(a))
            if not member.startswith('_')
        }


class SentryConfigContext:
    """
    Base class for data class (class methods only)
    """

    @classmethod
    def get_context(cls) -> dict:
        """

        Returns: dict context for Sentry

        """
        return {
            member: value()
            for member, value in inspect.getmembers(cls, lambda a: not inspect.ismethod(a))
            if not member.startswith('_')
        }


class SentryContext:
    """
    Base class for full blown class
    """

    def get_context(self) -> dict:
        """

        Returns: dict context for Sentry

        """
        return {
            member: value
            for member, value in inspect.getmembers(self, lambda a: not inspect.ismethod(a))
            if not member.startswith('_')
        }
