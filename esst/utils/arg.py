# coding=utf-8
"""
Decorator for Discord commands arguments
"""

from argh.constants import ATTR_ARGS


def arg(*args, **kwargs):
    """
    Decorator for Discord commands arguments
    """

    def _wrapper(func):
        if 'protected' in kwargs:
            setattr(func, 'protected_', True)
            return func
        declared_args = getattr(func, ATTR_ARGS, [])
        # The innermost decorator is called first but appears last in the code.
        # We need to preserve the expected order of positional arguments, so
        # the outermost decorator inserts its value before the innermost's:
        declared_args.insert(0, dict(option_strings=args, **kwargs))
        setattr(func, ATTR_ARGS, declared_args)
        return func

    return _wrapper
