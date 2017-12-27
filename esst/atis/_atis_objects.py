# coding=utf-8
"""
Manages ATIS objects
"""


class ATISForAirfield:
    """Simple data class for airfield ATIS information"""

    def __init__(
            self,
            icao,
            active_runway,
            info_identifier,
    ):
        self.icao = icao
        self.active_runway = active_runway
        self.info_id = info_identifier
