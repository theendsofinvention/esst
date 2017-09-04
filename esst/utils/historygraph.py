# coding=utf-8
"""
Creates graphic of perfs
"""

import datetime
import typing
from collections import namedtuple
from tempfile import mktemp

import humanize
from matplotlib import gridspec, pyplot as plt, ticker

from esst.core import CTX

GraphValues = namedtuple('GraphValues',
                         [
                             'server_cpu_history',
                             'server_mem_history',
                             'server_bytes_sent_history',
                             'server_bytes_recv_history',
                             'dcs_cpu_history',
                             'dcs_mem_history',
                             'players_history',
                         ]
                         )

PlotLine = namedtuple('PlotValue',
                      [
                          'values',
                          'label',
                          'style',
                      ])


def process_values(values_to_process, time_delta: float):
    server_cpu_history = [data for data in values_to_process.server_cpu_history if data[0] >= time_delta]
    server_mem_history = [data for data in values_to_process.server_mem_history if data[0] >= time_delta]
    server_bytes_sent_history = [data for data in values_to_process.server_bytes_sent_history if data[0] >= time_delta]
    server_bytes_recv_history = [data for data in values_to_process.server_bytes_recv_history if data[0] >= time_delta]
    dcs_cpu_history = [data for data in values_to_process.dcs_cpu_history if data[0] >= time_delta]
    dcs_mem_history = [data for data in values_to_process.dcs_mem_history if data[0] >= time_delta]
    if not values_to_process.players_history:
        players_history = [(time_delta, 0)]
    else:
        # players_history = []
        # for data in CTX.players_history:
        #     if data[0] < time_delta:
        #         continue
        #     if not players_history:
        #         players_history.append(data)
        #     else:
        #         if data[1] != players_history[-1][1]:
        #             players_history.append(data)
        # if CTX.players_history[-1] not in players_history:
        #     players_history.append(CTX.players_history[-1])
        players_history = [data for data in values_to_process.players_history if data[0] >= time_delta]
    if not server_cpu_history:
        server_cpu_history = [(time_delta, 0)]
    if not server_mem_history:
        server_mem_history = [(time_delta, 0)]
    if not server_bytes_sent_history:
        server_bytes_sent_history = [(time_delta, 0)]
    if not server_bytes_recv_history:
        server_bytes_recv_history = [(time_delta, 0)]
    if not dcs_mem_history:
        dcs_mem_history = [(time_delta, 0)]
    if not dcs_cpu_history:
        dcs_cpu_history = [(time_delta, 0)]
    return GraphValues(
        server_cpu_history=zip(*server_cpu_history),
        server_mem_history=zip(*server_mem_history),
        server_bytes_sent_history=zip(*server_bytes_sent_history),
        server_bytes_recv_history=zip(*server_bytes_recv_history),
        dcs_cpu_history=zip(*dcs_cpu_history),
        dcs_mem_history=zip(*dcs_mem_history),
        players_history=tuple(zip(*players_history)),
    )


def make_delta(now, days, hours, minutes):
    delta = datetime.timedelta(days=days, hours=hours, minutes=minutes).total_seconds()
    if delta == 0:
        delta = datetime.timedelta(hours=2).total_seconds()
    return now - delta


def _x_format_func(val, _):
    val = datetime.datetime.fromtimestamp(val)
    return str(val).replace(' ', '\n')


def _y_format_func_percent(val, _):
    return str(int(val)) + '%'


def _y_format_func_bytes(val, _):
    return humanize.naturalsize(val)


def _plot_axis(grid_spec, grid_pos,
               values_to_plot: typing.Set[PlotLine],
               title,
               ylabel_text,
               values,
               now,
               y_format_func,
               visible_x_labels=False,
               sharex=None):
    axis = plt.subplot(grid_spec[grid_pos], sharex=sharex)
    axis.set_title(title)
    plt.setp(axis.get_xticklabels(), visible=visible_x_labels)
    axis.set_ylabel(ylabel_text)

    for line in values_to_plot:
        assert isinstance(line, PlotLine)
        line_, = axis.plot(*line.values, line.style)
        plt.setp(line_, label=line.label)
    _add_players_count_to_axis(axis, values.players_history)
    axis.xaxis.set_major_formatter(ticker.FuncFormatter(_x_format_func))
    axis.yaxis.set_major_formatter(ticker.FuncFormatter(y_format_func))
    axis.grid(True)
    axis.set_xlim(right=now)

    return axis


def _plot_server(grid_spec, values, now):
    lines_to_plot = {
        PlotLine(
            values=values.server_cpu_history,
            style='r',
            label='CPU'
        ),
        PlotLine(
            values=values.server_mem_history,
            style='b',
            label='Memory'
        ),
    }
    axis = _plot_axis(grid_spec,
                      now=now,
                      values_to_plot=lines_to_plot,
                      grid_pos=0,
                      title='Server stats',
                      ylabel_text='Percentage used',
                      values=values,
                      visible_x_labels=False,
                      sharex=None,
                      y_format_func=_y_format_func_percent)
    axis.set_ylim([0, 100])
    return axis


def _plot_dcs(grid_spec, values, now, sharex=None):
    lines_to_plot = {
        PlotLine(
            values=values.dcs_cpu_history,
            style='r',
            label='CPU'
        ),
        PlotLine(
            values=values.dcs_mem_history,
            style='b',
            label='Memory'
        ),
    }
    axis = _plot_axis(grid_spec,
                      now=now,
                      values_to_plot=lines_to_plot,
                      grid_pos=1,
                      title='DCS stats',
                      ylabel_text='Percentage used',
                      values=values,
                      visible_x_labels=False,
                      sharex=sharex,
                      y_format_func=_y_format_func_percent)
    axis.set_ylim([0, 100])
    return axis


def _plot_bandwitdh(grid_spec, values, now, sharex=None):
    lines_to_plot = {
        PlotLine(
            values=values.server_bytes_sent_history,
            style='r',
            label='Bytes sent'
        ),
        PlotLine(
            values=values.server_bytes_recv_history,
            style='b',
            label='Bytes received'
        ),
    }
    axis = _plot_axis(grid_spec,
                      now=now,
                      values_to_plot=lines_to_plot,
                      grid_pos=2,
                      title='Network stats',
                      ylabel_text='Bytes sent/received',
                      values=values,
                      visible_x_labels=True,
                      sharex=sharex,
                      y_format_func=_y_format_func_bytes, )
    return axis


def _add_players_count_to_axis(axis, players_history):
    ax_players = axis.twinx()
    max_player_count = max(max((players_count for players_count in players_history[1])), 10)
    ax_players.set_ylim([0, max_player_count + (max_player_count / 4)])
    ax_players.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax_players.set_ylabel('Connected players')
    players_history, = ax_players.plot(*players_history, 'k.', )
    plt.setp(players_history, label='Players count')

    lines, labels = axis.get_legend_handles_labels()
    lines2, labels2 = ax_players.get_legend_handles_labels()
    axis.legend(lines + lines2, labels + labels2)


def _make_history_graph(values_to_process, days=0, hours=0, minutes=0, show: bool = False, save_path=None):
    """
    Creates a graph of perfs

    Args:
        show: show and exit
        save_path: specify path to save to (default to temp path)

    """
    # noinspection PyTypeChecker
    now = datetime.datetime.now().timestamp()
    time_delta = make_delta(now, days, hours, minutes)

    values = process_values(values_to_process, time_delta)

    # fig, (ax1, ax2, ax3) = plt.subplots(3, sharex=True, figsize=(18, 12))

    figure = plt.figure(figsize=(18, 12))
    grid_spec = gridspec.GridSpec(3, 1, height_ratios=[1, 1, 1])

    ax_server = _plot_server(grid_spec, values, now)
    _plot_dcs(grid_spec, values, now, sharex=ax_server)
    _plot_bandwitdh(grid_spec, values, now, sharex=ax_server)

    plt.tight_layout()
    figure.tight_layout()

    if show:
        plt.show()
        plt.close()
        return
    else:
        if not save_path:
            save_path = mktemp('.png')
        plt.savefig(save_path)
        return save_path


def make_history_graph(callback=None, days=0, hours=0, minutes=0, show: bool = False, save_path=None):
    """
    Creates a graph of perfs

    Args:
        show: show and exit
        save_path: specify path to save to (default to temp path)

    """

    values_to_process = GraphValues(
        dcs_cpu_history=CTX.dcs_cpu_history,
        dcs_mem_history=CTX.dcs_mem_history,
        server_cpu_history=CTX.server_cpu_history,
        server_mem_history=CTX.server_mem_history,
        server_bytes_recv_history=CTX.server_bytes_recv_history,
        server_bytes_sent_history=CTX.server_bytes_sent_history,
        players_history=CTX.players_history,
    )
    future = CTX.process_pool.submit(_make_history_graph, values_to_process, days, hours, minutes, show, save_path)
    if callback:
        future.add_done_callback(callback)


if __name__ == '__main__':
    import random

    time_delta = datetime.timedelta(hours=5)
    total_seconds = int(time_delta.total_seconds())

    now_ = datetime.datetime.now().timestamp()

    player_count = 0
    CTX.players_history.append((now_ - total_seconds, 0))
    for time_stamp in range(total_seconds, 0, -5):
        CTX.server_mem_history.append((now_ - time_stamp, random.randint(60, 70)))
        CTX.dcs_cpu_history.append((now_ - time_stamp, random.randint(20, 30)))
        CTX.dcs_mem_history.append((now_ - time_stamp, random.randint(60, 70)))
        CTX.server_bytes_recv_history.append((now_ - time_stamp, random.randint(0, 50000000)))
        CTX.server_bytes_sent_history.append((now_ - time_stamp, random.randint(0, 50000000)))
        if time_stamp <= int(total_seconds / 2):
            CTX.server_cpu_history.append((now_ - time_stamp, random.randint(20, 30)))
        if random.randint(0, 100) > 99:
            player_count += random.choice([-1, 1])
            if player_count < 0:
                player_count = 0
                continue
        CTX.players_history.append((now_ - time_stamp, player_count))

    time_delta = datetime.datetime.now() - time_delta
    time_delta = time_delta.timestamp()

    make_history_graph(minutes=5, show=True)
