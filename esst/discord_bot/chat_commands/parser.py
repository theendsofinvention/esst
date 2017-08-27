# coding=utf-8
"""
Discord chat commands parser
"""


import argparse
import inspect
import sys

import argh

from esst.core import CTX
from esst.discord_bot import abstract
from esst.discord_bot.chat_commands import dcs, esst_, mission, server


def _cancel_execution(*_):
    raise SystemExit(0)


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


class DiscordCommandParser(argh.ArghParser, abstract.AbstractDiscordCommandParser):
    """
    Creates chat commands out of regular functions with argh
    """
    def __init__(self,
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
            CTX.discord_msg_queue.put(message)

    def dispatch(self,  # pylint: disable=arguments-differ
                 argv=None,
                 add_help_command=True,
                 completion=True,  # pylint: disable=unused-argument
                 pre_call=None,
                 output_file=sys.stdout,  # pylint: disable=unused-argument
                 errors_file=sys.stderr,  # pylint: disable=unused-argument
                 raw_output=False,
                 namespace=None,
                 skip_unknown_args=False):
        """
        Passes arguments to linked function

        Args:
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

            return super(DiscordCommandParser, self).dispatch(
                argv=argv,
                add_help_command=add_help_command,
                completion=False,
                pre_call=pre_call,
                output_file=None, errors_file=None,
                raw_output=raw_output,
                namespace=namespace,
                skip_unknown_args=skip_unknown_args,
            )
        except SystemExit:
            pass

    def exit(self, _=0, message=None):
        if message:
            self._print_message(message)

    def error(self, message):
        self._print_message('Invalid command: ' + message)

    def parse_args(self, args=None, namespace=None):
        if len(args) == 1:
            args.append('--help')
        try:
            return super(DiscordCommandParser, self).parse_args(args, namespace)
        except TypeError:
            pass

    def format_help(self):  # pylint: disable=useless-super-delegation
        return super(DiscordCommandParser, self).format_help()

    def parse_discord_message(self, message: str):
        if message.startswith('!'):

            if message == '!help':
                self._print_message(self.format_help())
            else:
                formatted_args = message.split(' ')
                self.dispatch(formatted_args)


DECRIPTION = """
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
    (note: those options can be combined: "load overwrite" is valid)
"""


def make_root_parser():
    """
    Creates the chat commands parser for the Discord bot

    Returns: parser object

    """
    parser = DiscordCommandParser(description=DECRIPTION, prog='', add_help=False, usage='', epilog=EPILOG)
    for module_ in [esst_, mission, server, dcs, ]:
        funcs = [o[1] for o in inspect.getmembers(module_, inspect.isfunction) if o[1].__module__ == module_.__name__]
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
