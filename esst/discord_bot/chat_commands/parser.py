# coding=utf-8
"""
Discord chat commands parser
"""

import argparse
import inspect
import sys
from types import GeneratorType

import argh
from argh import compat
from argh.constants import (
    ATTR_EXPECTS_NAMESPACE_OBJECT, ATTR_WRAPPED_EXCEPTIONS, ATTR_WRAPPED_EXCEPTIONS_PROCESSOR,
    DEST_FUNCTION,
)
# noinspection PyProtectedMember
from argh.dispatching import ArghNamespace
from argh.exceptions import CommandError
from argh.utils import get_arg_spec

import esst.atis.chat_commands.atis_discord_commands
from esst import LOGGER, commands
from esst.discord_bot import abstract
from esst.discord_bot.chat_commands import dcs, esst_, mission, report, server, weather


def _cancel_execution(*_):
    raise SystemExit(0)


def _get_function_from_namespace_obj(namespace_obj):
    if isinstance(namespace_obj, ArghNamespace):
        # our special namespace object keeps the stack of assigned functions
        try:
            func = namespace_obj.get_function()
        except (AttributeError, IndexError):
            return None
    else:
        # a custom (probably vanilla) namespace object keeps the last assigned
        # function; this may be wrong but at least something may work
        if not hasattr(namespace_obj, DEST_FUNCTION):
            return None
        func = getattr(namespace_obj, DEST_FUNCTION)

    if not func or not hasattr(func, '__call__'):
        return None

    return func


def _execute_command(func, namespace_obj, pre_call=None):  # noqa: C901
    # noinspection SpellCheckingInspection
    """
    Assumes that `function` is a callable.  Tries different approaches
    to call it (with `namespace_obj` or with ordinary signature).
    Yields the results line by line.

    If :class:`~argh.exceptions.CommandError` is raised, its message is
    appended to the results (i.e. yielded by the generator as a string).
    All other exceptions propagate unless marked as wrappable
    by :func:`wrap_errors`.
    """
    if pre_call:
        LOGGER.debug('running pre_call: %s', pre_call)
        pre_call(namespace_obj)

    # namespace -> dictionary
    def _flat_key(key):
        return key.replace('-', '_')

    # noinspection SpellCheckingInspection
    def _call():
        # Actually call the function
        if getattr(func, ATTR_EXPECTS_NAMESPACE_OBJECT, False):
            result_ = func(namespace_obj)
        else:

            all_input = dict((_flat_key(k), v)
                             for k, v in vars(namespace_obj).items())

            # filter the namespace variables so that only those expected
            # by the actual function will pass

            spec = get_arg_spec(func)

            positional = [all_input[k] for k in spec.args]
            # noinspection SpellCheckingInspection
            kw_only = getattr(spec, 'kwonlyargs', [])
            keywords = dict((k, all_input[k]) for k in kw_only)

            # *args
            if spec.varargs:
                positional += getattr(namespace_obj, spec.varargs)

            # **kwargs
            varkw = getattr(spec, 'varkw', getattr(spec, 'keywords', []))
            if varkw:
                not_kwargs = [DEST_FUNCTION] + spec.args + [spec.varargs] + kw_only
                for k in vars(namespace_obj):
                    if k.startswith('_') or k in not_kwargs:
                        continue
                    keywords[k] = getattr(namespace_obj, k)

            result_ = func(*positional, **keywords)

        # Yield the results
        if isinstance(result_, (GeneratorType, list, tuple)):
            # yield each line ASAP, convert CommandError message to a line
            for line_ in result_:
                yield line_
        else:
            # yield non-empty non-iterable result as a single line
            if result_ is not None:
                yield result_

    # noinspection SpellCheckingInspection
    wrappable_exceptions = [CommandError, Exception]
    wrappable_exceptions += getattr(func, ATTR_WRAPPED_EXCEPTIONS, [])

    try:
        LOGGER.debug('running func: %s', func)
        result = _call()
        return '\n'.join(result)
    # pylint: disable=catching-non-exception
    except tuple(wrappable_exceptions) as exc:
        # pylint: disable=unnecessary-lambda
        processor = getattr(
            func, ATTR_WRAPPED_EXCEPTIONS_PROCESSOR,
            lambda exc_: '{0.__class__.__name__}: {0}'.format(exc_)
        )

        LOGGER.error(compat.text_type(processor(exc)))
        LOGGER.exception(exc)


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """
    Dummy
    """

    def add_usage(self, usage, actions, groups, prefix=None):
        """
        Dummy

        Args:
            usage:
            actions:
            groups:
            prefix:

        Returns:

        """
        if usage and '!help' in usage:
            usage = ''
        return super(HelpFormatter, self).add_usage(usage, actions, groups, prefix)


# noinspection SpellCheckingInspection
class DiscordCommandParser(argh.ArghParser, abstract.AbstractDiscordCommandParser):
    """
    Creates chat commands out of regular functions with argh
    """

    def __init__(self,  # pylint: disable=too-many-arguments
                 prog=None,
                 usage=None,
                 description=None,
                 epilog=None,
                 parents=None,
                 formatter_class=HelpFormatter,
                 prefix_chars='-',
                 fromfile_prefix_chars=None,
                 argument_default=None,
                 conflict_handler='error',
                 add_help=True,
                 allow_abbrev=True):
        if parents is None:
            parents = []
        argh.ArghParser.__init__(
            self,
            prog=prog,
            usage=usage,
            description=description,
            epilog=epilog,
            parents=parents,
            formatter_class=formatter_class,
            prefix_chars=prefix_chars,
            fromfile_prefix_chars=fromfile_prefix_chars,
            argument_default=argument_default,
            conflict_handler=conflict_handler,
            add_help=add_help,
            allow_abbrev=allow_abbrev,
        )
        self.formatter_class = HelpFormatter

    def _print_message(self, message, _=None):
        if message:
            commands.DISCORD.say(message)

    # pylint: disable=arguments-differ,too-many-branches,too-many-arguments,too-many-locals
    def dispatch(self,  # noqa: C901
                 argv=None,
                 add_help_command=True,
                 completion=True,  # pylint: disable=unused-argument
                 pre_call=None,
                 output_file=sys.stdout,  # pylint: disable=unused-argument
                 errors_file=sys.stderr,  # pylint: disable=unused-argument
                 raw_output=False,  # pylint: disable=unused-argument
                 namespace=None,
                 skip_unknown_args=False,
                 is_admin: bool = False, ):
        """
        Passes arguments to linked function

        Args:
            is_admin: is the user that issued the command an admin ?
            argv:
            add_help_command:
            completion:
            pre_call:
            output_file:
            errors_file:
            raw_output:
            namespace:
            skip_unknown_args:

        """
        try:
            for arg in argv:
                if arg == 'help':
                    argv.remove('help')
                    argv.append('--help')
            for arg in argv:
                if arg in ['-h', '--help']:
                    pre_call = _cancel_execution

            if argv is None:
                argv = sys.argv[1:]

            if add_help_command:
                if argv:
                    if argv[0] in ['help', '-h']:
                        argv.pop(0)
                        argv.append('--help')

            if skip_unknown_args:
                parse_args = self.parse_known_args
            else:
                parse_args = self.parse_args

            if not namespace:
                namespace = ArghNamespace()

            # this will raise SystemExit if parsing fails
            namespace_obj = parse_args(argv, namespace=namespace)

            func = _get_function_from_namespace_obj(namespace_obj)

            if func:
                if hasattr(func, 'protected_') and not is_admin:
                    LOGGER.error(f'only users with privileges have access to this command')
                    return None
                LOGGER.debug('running func: %s', func)
                return _execute_command(func, namespace_obj, pre_call=pre_call)

            # no commands declared, can't dispatch; display help message
            return [self.format_usage()]

        except SystemExit:
            pass

    def exit(self, _=0, message=None):
        """
        This was supposed to exit the program in case of error; in this case, we simply print the message

        Args:
            _: exit code (useless)
            message: exit message

        """
        if message:
            self._print_message(message)

    def error(self, message):
        """error(message: string)

        Prints a usage message incorporating the message to stderr and
        exits.

        If you override this in a subclass, it should not return -- it
        should either exit or raise an exception.
        """
        self._print_message(message)
        raise SystemExit(-1)

    def parse_args(self, args=None, namespace=None):
        """
        Wrapper for :meth:`argparse.ArgumentParser.parse_args`.  If `namespace`
        is not defined, :class:`argh.dispatching.ArghNamespace` is used.
        This is required for functions to be properly used as commands.
        """
        if len(args) == 1:
            args.append('--help')
        try:
            return super(DiscordCommandParser, self).parse_args(args, namespace)
        except TypeError:
            pass

    def format_help(self):  # pylint: disable=useless-super-delegation
        """
        I'm not sure about this one, this is an experiment

        """
        return super(DiscordCommandParser, self).format_help()

    def parse_discord_message(self, message: str, is_admin: bool):
        """
        PArses message from Discord

        Args:
            message: message content
            is_admin: is sender an admin?

        """
        if message.startswith('!'):

            if message == '!help':
                self._print_message(self.format_help())
            else:
                formatted_args = message.split(' ')
                self.dispatch(formatted_args, is_admin=is_admin)


DESCRIPTION = """
To get help on a specific command, use the "--help" option.

Ex:
    !dcs --help
    !dcs status --help
"""
EPILOG = """
In addition to the commands listed above, you can also upload a mission to the server via Discord:
1. Drag and drop the mission file to this channel
2. In the "Add a comment" field, you can specify one of:
    a. "load": the mission will be loaded immediately (the server will restart)
    b. "overwrite": replace an existing mission file with the same name
    c. "force": force server restart even if there are connected players
    (note: those options can be combined: "load overwrite" is valid)
"""


def make_root_parser():
    """
    Creates the chat commands parser for the Discord bot

    Returns: parser object

    """
    parser = DiscordCommandParser(
        description=DESCRIPTION, prog='', add_help=False, usage='', epilog=EPILOG)
    for module_ in [esst_, mission, server, dcs, report, esst.atis.chat_commands.atis_discord_commands, weather]:
        funcs = [o[1] for o in inspect.getmembers(module_, inspect.isfunction)
                 if o[1].__module__ == module_.__name__ and not o[1].__name__.startswith('_')]
        parser.add_commands(
            functions=funcs,
            namespace=module_.NAMESPACE,
            namespace_kwargs={
                'title': module_.TITLE,
            },
            func_kwargs={
                # 'parents': [parser],
            },
        )

    return parser
