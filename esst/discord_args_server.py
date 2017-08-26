

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

                    
# parser.add_commands([test, caribou], namespace='!foo', 
#     namespace_kwargs={'title':'Foo !', 'description': 'description', 'help': 'help text'},
#     func_kwargs={'parents': [parent_parser]},
# )

def add_commands(parser, parent_parsers: list = None):
    if parent_parsers is None:
        parent_parsers = []
    parser.add_commands(
        functions=[
            status,
            cpu,
            restart,
        ],
        namespace='!server',
        namespace_kwargs={
            'title':'Manage server computer',
            # 'description': 'DCS description',
            # 'help': 'Availa',
        },
        func_kwargs={
            'parents': parent_parsers,
        },
    )