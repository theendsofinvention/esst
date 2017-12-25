# coding=utf-8
"""
Provides random phonetic letter for ATIS identifier
"""

import string

from elib.custom_random import random_string

# noinspection SpellCheckingInspection
PHONETIC = {'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo', 'F': 'Foxtrot', 'G': 'Golf',
            "H": "Hotel", 'I': 'India', 'J': 'Juliet', 'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November',
            'O': 'Oscar', 'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango', 'U': 'Uniform',
            'V': 'Victor', 'W': 'Whiskey', 'X': 'Xray', 'Y': 'Yankee', 'Z': 'Zulu'}


def get_random_identifier():
    """

    Returns: random identifier for ATIS

    """
    return PHONETIC[random_string(1, string.ascii_uppercase)]
