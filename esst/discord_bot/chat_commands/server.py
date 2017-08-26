# coding=utf-8

import argh


def status():
    """
    Show current server status
    """
    print('Server status')


@argh.arg('--start', help='Show CPU usage in real time')
@argh.arg('--stop', help='Stop showing CPU usage in real time')
def cpu(
        start=False,
        stop=False
):
    """
    Show server CPU usage
    """
    print('Server cpu usage', start, stop)


def restart():
    """
    Restart the server computer
    """
    print('Server restart')


namespace = '!server'
title = 'Manage server computer'
