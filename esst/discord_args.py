# coding=utf-8

import argparse
import argh
import sys

# parser = argparse.ArgumentParser(description='description', prog='!wx')
# parser.add_argument('-f', '-foo', action='store_true')
# parser.add_argument('test', type=int)
# parser.add_argument('-x', choices=[1, 2, 3], type=int, help='choice argument')
# parser.epilog = 'caribou'


class HelpFormatter(argparse.HelpFormatter):
    
    def add_usage(self, usage, actions, groups, prefix=None):
        # print('usage', usage)
        # print('actions', actions)
        # print('groups', groups)
        # print('prefix', prefix)
        
        super(HelpFormatter, self).add_usage(usage, actions, groups, prefix)


class CustomParser(argh.ArghParser):
    
    

    def __init__(self, *args, **kwargs):
                     
        argh.ArghParser.__init__(self, *args, **kwargs)
        self.formatter_class = HelpFormatter

    def _print_message(self, message, file=None) -> str:
        if message:
            send_message_on_discord(message)
        
    def dispatch(self, argv=None, add_help_command=True,
             completion=True, pre_call=None,
             output_file=sys.stdout, errors_file=sys.stderr,
             raw_output=False, namespace=None,
             skip_unknown_args=False):
        try:
            super(CustomParser, self).dispatch(
                argv=argv,
                add_help_command=add_help_command,
                completion=completion,
                pre_call=pre_call,
                output_file=None, errors_file=None,
                # output_file=output_file, errors_file=errors_file,
                raw_output=raw_output,
                namespace=namespace,
                skip_unknown_args=skip_unknown_args,
                )
        except SystemExit:
            pass
            
    def exit(self, status=0, message=None):
        if message:
            self._print_message(message, _sys.stderr)
        raise SystemExit(0)
            
    def error(self, message):
        send_message_on_discord('Invalid command: ' + message)
            
    def parse_args(self, args=None, namespace=None):
        # # print('args:', args, type(args))
        # if args and args.startswith('!'):
        #     args = args.replace('!', '')
        # args = args.split(' ')
        try:
            return super(CustomParser, self).parse_args(args, namespace)
        except TypeError:
            send_message_on_discord('invalid command: ' + ' '.join(args))
        
    def format_help(self):
        # print('moo')
        return super(CustomParser, self).format_help()
    

def test(flag1: 'flag dosctring' = False):
    """
    Function docstring
    Longer Function docstring
    Huge Function docstring
    """
    print('flag1', flag1)
    

def caribou(flag1: 'flag dosctring' = False):
    """
    Function docstring
    Longer Function docstring
    Huge Function docstring
    """
    print('flag1', flag1)
    

def status():
    """
    Show current DCS status
    """
    print('DCS status')

description = """This is a somewhat
longer
description
of everything
"""
parser = CustomParser(description=description, prog='', add_help=False)
parent_parser = argparse.ArgumentParser(add_help=False)
parent_parser.add_argument('--long-b', '-b',
                    action="store",
                    help='Long and short together')
                    
parser.add_commands([test, caribou], namespace='!foo', 
    namespace_kwargs={'title':'Foo !', 'description': 'description', 'help': 'help text'},
    func_kwargs={'parents': [parent_parser]},
)
parser.add_commands([status], namespace='!dcs')


def send_message_on_discord(message: str):
    if message:
        print('Discord message:\n'
            '===============================================\n'
            '{message}\n'
            '==============================================='.format(
                message=message)
            )


def parse_discord_message(message: str):
    if message.startswith('!'):
        
        if message == '!help':
            send_message_on_discord(parser.print_help())
        else:
            formatted_args = message.split(' ')
            # parser.parse_args(message[1:])
            parser.dispatch(formatted_args)
    


def main():
    args = ' '.join(sys.argv[1:])
    # print('args', args)
    
    parser = CustomParser(description='description')
    parser.add_commands([test])
    parse_discord_message(args)
    # parser.parse_args(args)
    # result = parser.dispatch()
    # print(type(result))
    # print(result)
    # try:
    #     result = parser.dispatch()
    #     print(type(result))
    # except SystemExit:
    #     # We do not want to exit here ...
    #     raise
    #     print('PARSING ERROR')
    
    
if __name__ == '__main__':
    main()