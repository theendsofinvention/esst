# coding=utf-8

import argparse
import argh

# parser = argparse.ArgumentParser(description='description', prog='!wx')
# parser.add_argument('-f', '-foo', action='store_true')
# parser.add_argument('test', type=int)
# parser.add_argument('-x', choices=[1, 2, 3], type=int, help='choice argument')
# parser.epilog = 'caribou'


class CustomParser(argh.ArghParser):

    def _print_message(self, message, file=None):
        print('moo')
        print(message)

@argh.arg('arg1', default='hello world', nargs='+', help='The message')
def test(arg1):
    print(arg1)

parser = CustomParser(description='description', prog='!wx')
parser.add_commands([test])

def main():
    # print(parser.format_help())
    # parser.print_usage()
    # parser.print_help()
    # print(dir(test.argh_args
    #           ))
    parser.parse_args(['test', '--help'])
    # test.format_help()