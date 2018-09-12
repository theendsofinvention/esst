# coding=utf-8
"""
Set up Config object
"""
import sys

import everett

from ._new_config import ESSTConfig
from ._validate_config import validate_config


def setup_config():
    """
    Set up the config object

    Returns: instance of ESSTConfig

    """
    try:
        config = ESSTConfig()
        validate_config(config)
    except everett.InvalidValueError as exception:
        key = exception.key
        if exception.namespace:
            key = f'{exception.namespace}_{key}'
        print(f'Invalid config value: {key}')
        sys.exit(1)
    except everett.ConfigurationMissingError as exception:
        key = exception.key
        if exception.namespace:
            key = f'{exception.namespace}_{key}'
        print(f'Missing configuration value: {key}')
        sys.exit(1)
    else:
        return config
