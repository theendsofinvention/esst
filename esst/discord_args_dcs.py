

import argh    

def status():
    """
    Show current DCS status
    """
    print('DCS status')
    
@argh.arg('--start', help='Show CPU usage in real time')
@argh.arg('--stop', help='Stop showing CPU usage in real time')
def cpu(
        start=False,
        stop=False
    ):
    """
    Show DCS.exe CPU usage
    """
    print('DCS cpu usage', start, stop)
    
def restart():
    """
    Closes and restart DCS.exe
    """
    print('DCS restart')
    
def version():
    """
    Show DCS.exe version
    """
    print('DCS version')

                    
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
        namespace='!dcs',
        namespace_kwargs={
            'title':'Manage DCS application',
            # 'description': 'DCS description',
            # 'help': 'Availa',
        },
        func_kwargs={
            'parents': parent_parsers,
        },
    )