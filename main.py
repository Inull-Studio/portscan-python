import os
import sys, argparse, time, signal
import threading
from utils.icmp import ICMP
from utils.portscan import PortScan
from utils.service import default_port
from utils.output import *
from utils.thread import ThreadPoolExecutor

def parse():
    parser = argparse.ArgumentParser()
    general_args = parser.add_argument_group('通用选项')
    type_args = parser.add_argument_group('类型选项')
    discover_args = parser.add_argument_group('发现方式')
    portscan_args = parser.add_argument_group('端口扫描')

    general_args.add_argument('-t', '--thread', action='store', type=int, default='500', help='使用的线程数')
    general_args.add_argument('-v', '-vv', action='count', help='详细信息', dest='verbose')
    general_args.add_argument('-w', type=int, help='超时时间，默认3s', dest='timeout', default=3)
    type_args.add_argument('-U', action='store_true', help='UDP扫描')
    discover_args.add_argument('-nP', '--noping', action='store_true', help='禁用ICMP主机发现')
    discover_args.add_argument('-n', action='store_true', help='禁用DNS解析', dest='nodns')
    parser.add_argument('host', help='要扫描的HOST/IP 例: domain.com,192.168.1.123,169.254.0.1/24')
    portscan_args.add_argument('-p', '--port', action='store', default=','.join(map(lambda x:str(x), default_port)), help='要扫描的端口 例: 22,23,80-8080')
    portscan_args.add_argument('-nS', '--noscan', action='store_true', help='禁用端口扫描，只做主机发现')
    return parser

def signal_handler(signal, frame):
    print('正在等待扫描结束..')
    os._exit(-1)


if __name__=='__main__':
    start = time.time()
    main_lock = threading.Lock()
    signal.signal(signal.SIGINT, signal_handler)
    try:
        parser = parse()
        args = parser.parse_args()
        print_args(args)
        ps = PortScan(args.host, args.port, int(args.thread))
        n_ips = []
        tlist = {}
        if not args.noping:
            print_line('主机发现 (ICMP)')
            discover_start = time.time()
            with ThreadPoolExecutor(args.thread) as exec:
                for dst in ps.ips.copy():
                    icmp = ICMP(dst, args.timeout)
                    tlist[dst] = exec.submit(icmp.alive)
                for t in tlist:
                    with main_lock:
                        if tlist[t].result():
                            n_ips.append(t)
            ps.ips = n_ips
            print('执行用时{:.2f}秒, 存活主机数量: {}'.format((time.time() - discover_start), len(ps.ips)))
        if not ps.ips:
            print('主机不存在，若确定存在使用 -nP 参数')
            sys.exit()
        if not args.noscan:
            ps.portscan()
        if args.verbose:
            print_line('服务详情')
            for ip, datas in ps.opens.items():
                for port, data in datas.items():
                    if data:
                        print(ip, port, data)
        print_line('结束')
        end = time.time()
        print('共用时:{:.2f}秒'.format(end - start))
    except Exception as e:
        print(e, e.__traceback__.tb_lineno)
