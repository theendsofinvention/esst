# coding=utf-8
"""
Manages a mission change context
"""
from pathlib import Path

from . import store


class MissionManagerContext:
    """
    Manages a mission change context
    """

    def __init__(
            self,
            original_mission_path: Path,
            originator: str,
    ) -> None:
        self._original_path = original_mission_path
        self._originator = originator
        self._tmp_path = store.get_random_auto_mission_name(self._original_path)

    @property
    def original_path(self) -> Path:
        """
        Returns: source mission for this context
        """
        return self.original_path

    @property
    def originator(self) -> str:
        """
        Returns: name of the person who issued the command
        """
        return self._originator

    @property
    def tmp_path(self) -> Path:
        """
        Returns: temporary path for this mission
        """
        return self._tmp_path
