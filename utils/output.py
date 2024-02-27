from rich import get_console, table
from typing import Optional, List, Tuple

def print_line(text):
    get_console().rule(text)

def print(*args, sep: Optional[str]=' ', end: Optional[str]='\n'):
    get_console().print(*args, sep=sep, end=end)

def print_args(args):
    print(f'目标: {args.host}')
    if not args.noscan:
        print(f'目标端口: {args.port}')
    print(f'使用的线程数: {args.thread}')

def get_table():
    tb = table.Table(show_edge=False)
    return tb

def print_table(heads: List[str], rows: List[Tuple[str]]):
    assert len(heads) != len(rows), '数据与字段不对应'
    tb = table.Table(show_edge=False)
    for head in heads:
        tb.add_column(head)
    for row in rows:
        tb.add_row(*row)
    get_console().print(tb, justify='center')