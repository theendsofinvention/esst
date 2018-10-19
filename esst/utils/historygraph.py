# coding=utf-8
"""
Creates graphic of perfs
"""

import datetime
import typing
from collections import namedtuple
from tempfile import mktemp

import humanize

from esst.core import CTX

PLT = GRID_SPEC = TICKER = None


# https://stackoverflow.com/questions/4931376/generating-matplotlib-graphs-without-a-running-x-server/4935945#4935945
# noinspection SpellCheckingInspection
def _init_mpl():
    """
    This is a very stupid hack to go around Matplotlib being stupid about Tkinter.
    My linters don't like import statements mixed within the code, so this will do.
    """
    global PLT, GRID_SPEC, TICKER  # pylint: disable=global-statement
    import matplotlib as mpl
    mpl.use('Agg')
    from matplotlib import pyplot as plt_
    from matplotlib import gridspec as grd_, ticker as tick_
    PLT = plt_
    GRID_SPEC = grd_
    TICKER = tick_


_init_mpl()

GraphValues = namedtuple('GraphValues', ['server_cpu_history',
                                         'server_mem_history',
                                         'server_bytes_sent_history',
                                         'server_bytes_recv_history',
                                         'dcs_cpu_history',
                                         'dcs_mem_history',
                                         'players_history', ])

PlotLine = namedtuple('PlotValue',
                      [
                          'values',
                          'label',
                          'style',
                      ])


def process_values(values_to_process: GraphValues, time_delta: float) -> GraphValues:
    """
    Converts raw values for plotting

    Args:
        values_to_process: values in set from CTX
        time_delta: how far behind?

    Returns: processed values

    """

    def _process(values):
        return [data for data in values if data[0] >= time_delta] or [(time_delta, 0)]

    server_cpu_history = _process(values_to_process.server_cpu_history)
    server_mem_history = _process(values_to_process.server_mem_history)
    server_bytes_sent_history = _process(values_to_process.server_bytes_sent_history)
    server_bytes_recv_history = _process(values_to_process.server_bytes_recv_history)
    dcs_cpu_history = _process(values_to_process.dcs_cpu_history)
    dcs_mem_history = _process(values_to_process.dcs_mem_history)
    players_history = _process(values_to_process.players_history)

    return GraphValues(
        server_cpu_history=zip(*server_cpu_history),
        server_mem_history=zip(*server_mem_history),
        server_bytes_sent_history=zip(*server_bytes_sent_history),
        server_bytes_recv_history=zip(*server_bytes_recv_history),
        dcs_cpu_history=zip(*dcs_cpu_history),
        dcs_mem_history=zip(*dcs_mem_history),
        players_history=tuple(zip(*players_history)),
    )


def _make_delta(now, days, hours, minutes):
    delta = datetime.timedelta(
        days=days, hours=hours, minutes=minutes).total_seconds()
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


def _plot_axis(grid_spec, grid_pos,  # pylint: disable=too-many-arguments
               values_to_plot: typing.Set[PlotLine],
               title,
               y_label_text,
               values,
               now,
               y_format_func,
               visible_x_labels=False,
               share_x=None):
    axis = PLT.subplot(grid_spec[grid_pos], sharex=share_x)  # type: ignore
    axis.set_title(title)
    PLT.setp(axis.get_xticklabels(), visible=visible_x_labels)  # type: ignore
    axis.set_ylabel(y_label_text)

    for line in values_to_plot:
        line_, = axis.plot(*line.values, line.style)
        PLT.setp(line_, label=line.label)  # type: ignore
    _add_players_count_to_axis(axis, values.players_history)
    axis.xaxis.set_major_formatter(TICKER.FuncFormatter(_x_format_func))  # type: ignore
    axis.yaxis.set_major_formatter(TICKER.FuncFormatter(y_format_func))  # type: ignore
    axis.grid(True)
    axis.set_xlim(right=now)

    return axis


# pylint: disable=too-many-arguments,too-many-locals
def _get_axis(
        grid_spec,
        now,
        values,
        grid_pos,
        values_list: typing.List[typing.Any],
        labels_list: typing.List[str],
        title: str,
        y_label: str,
        visible_x: bool,
        y_format_func: typing.Callable,
        share_x=None,
):
    lines_to_plot = set()
    styles = ['r', 'b']
    for _values, _label in zip(values_list, labels_list):
        lines_to_plot.add(
            PlotLine(
                values=_values,
                style=styles.pop(),
                label=_label
            )
        )
    axis = _plot_axis(grid_spec,
                      now=now,
                      values_to_plot=lines_to_plot,
                      grid_pos=grid_pos,
                      title=title,
                      y_label_text=y_label,
                      values=values,
                      visible_x_labels=visible_x,
                      share_x=share_x,
                      y_format_func=y_format_func)
    return axis


def _plot_server(grid_spec, values, now):
    axis = _get_axis(
        grid_spec=grid_spec,
        now=now,
        values=values,
        grid_pos=0,
        values_list=[values.server_cpu_history, values.server_mem_history],
        labels_list=['CPU', 'Memory'],
        title='Server stats',
        y_label='Percentage used',
        visible_x=False,
        y_format_func=_y_format_func_percent,
    )
    axis.set_ylim([0, 100])
    return axis


def _plot_dcs(grid_spec, values, now, share_x=None):
    axis = _get_axis(
        grid_spec=grid_spec,
        now=now,
        values=values,
        grid_pos=1,
        values_list=[values.dcs_cpu_history, values.dcs_mem_history],
        labels_list=['CPU', 'Memory'],
        title='DCS stats',
        y_label='Percentage used',
        visible_x=False,
        y_format_func=_y_format_func_percent,
        share_x=share_x
    )
    axis.set_ylim([0, 100])
    return axis


def _plot_bandwidth(grid_spec, values, now, share_x=None):
    axis = _get_axis(
        grid_spec=grid_spec,
        now=now,
        values=values,
        grid_pos=2,
        values_list=[values.server_bytes_sent_history, values.server_bytes_recv_history],
        labels_list=['Bytes sent', 'Bytes received'],
        title='Bytes sent',
        y_label='Bytes received',
        visible_x=True,
        y_format_func=_y_format_func_bytes,
        share_x=share_x
    )
    return axis


def _add_players_count_to_axis(axis, players_history):
    ax_players = axis.twinx()
    max_player_count = max(
        max((players_count for players_count in players_history[1])), 10)
    ax_players.set_ylim([0, max_player_count + (max_player_count / 4)])
    ax_players.yaxis.set_major_locator(TICKER.MaxNLocator(integer=True))
    ax_players.set_ylabel('Connected players')
    players_history, = ax_players.plot(*players_history, 'k.', )
    PLT.setp(players_history, label='Players count')

    lines, labels = axis.get_legend_handles_labels()
    lines2, labels2 = ax_players.get_legend_handles_labels()
    axis.legend(lines + lines2, labels + labels2)


def _make_history_graph(  # pylint: disable=too-many-arguments
        values_to_process,
        days=0,
        hours=0,
        minutes=0,
        show: bool = False,
        save_path=None):
    """
    Creates a graph of perfs

    Args:
        show: show and exit
        save_path: specify path to save to (default to temp path)

    """
    # noinspection PyTypeChecker
    now = datetime.datetime.now().timestamp()
    time_delta = _make_delta(now, days, hours, minutes)

    values = process_values(values_to_process, time_delta)

    figure = PLT.figure(figsize=(18, 12))  # type: ignore
    grid_spec = GRID_SPEC.GridSpec(3, 1, height_ratios=[1, 1, 1])  # type: ignore

    ax_server = _plot_server(grid_spec, values, now)
    _plot_dcs(grid_spec, values, now, share_x=ax_server)
    _plot_bandwidth(grid_spec, values, now, share_x=ax_server)

    PLT.tight_layout()  # type: ignore
    figure.tight_layout()

    if show:
        PLT.show()  # type: ignore
        PLT.close()  # type: ignore
        return None

    if not save_path:
        save_path = mktemp('.png')  # nosec
    PLT.savefig(save_path)  # type: ignore
    PLT.close()  # type: ignore
    return save_path


# pylint: disable=too-many-arguments
def make_history_graph(callback=None, days=0, hours=0, minutes=0, show: bool = False, save_path=None):
    """
    Creates a graph of perfs

    Args:
        minutes: number of minutes to go back
        hours: number of hours to go back
        days: number of days to go back
        callback: optional call back to the future
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
    graph = _make_history_graph(values_to_process, days, hours, minutes, show, save_path)
    if callback:
        callback(graph)
    # process_pool = futures.ProcessPoolExecutor(max_workers=1)
    # values_to_process = GraphValues(
    #     dcs_cpu_history=CTX.dcs_cpu_history,
    #     dcs_mem_history=CTX.dcs_mem_history,
    #     server_cpu_history=CTX.server_cpu_history,
    #     server_mem_history=CTX.server_mem_history,
    #     server_bytes_recv_history=CTX.server_bytes_recv_history,
    #     server_bytes_sent_history=CTX.server_bytes_sent_history,
    #     players_history=CTX.players_history,
    # )
    # future = process_pool.submit(
    #     _make_history_graph, values_to_process, days, hours, minutes, show, save_path
    # )
    # if callback:
    #     future.add_done_callback(callback)


if __name__ == '__main__':
    # Debug code
    import random

    TIME_DELTA = datetime.timedelta(hours=5)
    TOTAL_SECONDS = int(TIME_DELTA.total_seconds())

    NOW = datetime.datetime.now().timestamp()

    PLAYER_COUNT = 0
    CTX.players_history.append((NOW - TOTAL_SECONDS, 0))
    SKIP = 0
    for time_stamp in range(TOTAL_SECONDS, 0, -10):
        CTX.server_mem_history.append(
            (NOW - time_stamp, random.randint(60, 70)))  # nosec
        CTX.dcs_cpu_history.append((NOW - time_stamp, random.randint(20, 30)))  # nosec
        CTX.dcs_mem_history.append((NOW - time_stamp, random.randint(60, 70)))  # nosec

        SKIP += 1
        if SKIP > 20:
            SKIP = 0
            CTX.server_bytes_recv_history.append(
                (NOW - time_stamp, random.randint(0, 50000000)))  # nosec
            CTX.server_bytes_sent_history.append(
                (NOW - time_stamp, random.randint(0, 50000000)))  # nosec

        if time_stamp <= int(TOTAL_SECONDS / 2):
            CTX.server_cpu_history.append(
                (NOW - time_stamp, random.randint(20, 30)))  # nosec
        if random.randint(0, 100) > 99:  # nosec
            PLAYER_COUNT += random.choice([-1, 1])  # nosec
            if PLAYER_COUNT < 0:
                PLAYER_COUNT = 0
                continue
        CTX.players_history.append((NOW - time_stamp, PLAYER_COUNT))

    TIME_DELTA = datetime.datetime.now() - TIME_DELTA  # type: ignore
    TIME_DELTA = TIME_DELTA.timestamp()  # type: ignore

    make_history_graph(hours=5, save_path='./test.png')
