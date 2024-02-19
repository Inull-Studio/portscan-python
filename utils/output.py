from rich import get_console, table
from typing import Optional

def print_line(text):
    get_console().rule(text)

def print(*args, sep: Optional[str]=' ', end: Optional[str]='\n'):
    get_console().print(*args, sep=sep, end=end)

def print_args(args):
    print(f'目标: {args.host}')
    if not args.noscan:
        print(f'目标端口: {args.port}')
    print(f'使用的线程数: {args.thread}')