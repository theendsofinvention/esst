

import argh    

def log():
    """
    Show ESST log file
    """
    print('ESST log file')
    
def version():
    """
    Show ESST version
    """
    print('ESST version')
    
def restart():
    """
    Restart ESST
    
    (you must provide a start script in the config)
    """
    print('ESST restart')

                    

def add_commands(parser, parent_parsers: list = None):
    if parent_parsers is None:
        parent_parsers = []
    parser.add_commands(
        functions=[
            log,
            version,
            restart,
        ],
        namespace='!esst',
        namespace_kwargs={
            'title':'Manage ESST application',
            # 'description': 'DCS description',
            # 'help': 'Availa',
        },
        func_kwargs={
            'parents': parent_parsers,
        },
    )