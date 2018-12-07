# coding=utf-8
"""
Provides random phonetic letter for ATIS identifier
"""

import random
import string

# noinspection SpellCheckingInspection
PHONETIC = {
    'A': 'Alfa', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Del-tah', 'E': 'Echo', 'F': 'Foxtrot', 'G': 'Golf',
    "H": "Hotel", 'I': 'India', 'J': 'Juliet', 'K': 'Keelo', 'L': 'Leema', 'M': 'Mike', 'N': 'November',
    'O': 'Oscar', 'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango', 'U': 'Uniform',
    'V': 'Victor', 'W': 'Whiskey', 'X': 'ex-ray', 'Y': 'Yankee', 'Z': 'Zulu'
}


def get_random_identifier():
    """

    Returns: random identifier for ATIS

    """
    letter = random.choice(string.ascii_uppercase)  # nosec
    return PHONETIC[letter], letter
