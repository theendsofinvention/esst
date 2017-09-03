# coding=utf-8
"""
Creates graphic of perfs
"""

from tempfile import mktemp

import numpy as np
from matplotlib import pyplot as plt
from matplotlib import ticker

from esst.core import CTX


def make_history_graph(show: bool = False, save_path=None):
    """
    Creates a graph of perfs

    Args:
        show: show and exit
        save_path: specify path to save to (default to temp path)

    """
    # noinspection PyTypeChecker
    fig, (ax1, ax2, ax3) = plt.subplots(3, sharex=True, figsize=(18, 12))

    time = range(0, 720)

    players_count = np.array(CTX.players_history)
    server_cpu = np.array(CTX.server_cpu_history)
    server_mem = np.array(CTX.server_mem_history)
    dcs_cpu = np.array(CTX.dcs_cpu_history)
    dcs_mem = np.array(CTX.dcs_mem_history)

    server_cpu, = ax1.plot(time, server_cpu, 'r', )
    server_mem = ax1.plot(time, server_mem, 'yo', )
    plt.setp(server_cpu, label='CPU')
    plt.setp(server_mem, label='Memory', alpha=0.3)

    dcs_cpu, = ax2.plot(time, dcs_cpu, 'b', )
    dcs_mem, = ax2.plot(time, dcs_mem, 'co', )
    plt.setp(dcs_cpu, label='CPU')
    plt.setp(dcs_mem, label='Memory', alpha=0.3)

    players_count, = ax3.plot(time, players_count, 'k')
    plt.setp(players_count, label='Players count')

    def _x_format_func(val, _):
        return str(int(round((val - 720) / 12))) + 'min'

    def _y_format_func(val, _):
        return str(int(val)) + '%'

    for axis in [ax1, ax2]:
        axis.xaxis.set_major_formatter(ticker.FuncFormatter(_x_format_func))
        axis.yaxis.set_major_formatter(ticker.FuncFormatter(_y_format_func))
        axis.set_ylim([0, 100])

    ax1.set_ylabel('Server stats')
    ax2.set_ylabel('DCS stats')
    ax3.set_ylabel('Players connected')
    ax3.set_ylim(bottom=0)

    fig.tight_layout()
    plt.xlabel('Time')
    for axis in [ax1, ax2, ax3]:
        axis.grid(True)
        axis.legend()

    if show:
        plt.show()
        plt.close()
        return
    else:
        if not save_path:
            save_path = mktemp('.png')
        plt.savefig(save_path)
        return save_path


if __name__ == '__main__':
    make_history_graph(show=True)
