import socket, threading, ipaddress, time, os
from typing import List, Set, Dict
from .thread import ThreadPoolExecutor
from .output import *


class PortScan:
    def __init__(self, raw_ip: str, raw_port: str, thread: int, timeout: int) -> None:
        self.timeout = timeout
        self.lock = threading.Lock()
        self.thread = thread
        self.ports: List[int] = []
        self.ips: List[str] = []
        self.alive_ips: Set[str] = set()
        self.nets: List[ipaddress.IPv4Network] = []
        self.raw_ip = raw_ip
        self.raw_port = raw_port
        self.opens: Dict[str, Dict[int, bytes]] = {}
        self.format()

    def isNetwork(self, net: str):
        try:
            self.nets.append(ipaddress.ip_network(net, strict=False))
            return True
        except Exception as e:
            print(e)
            return False

    def __formatPort(self):
        ports = []
        if ',' in self.raw_port and '-' in self.raw_port:
            for sport in self.raw_port.strip().split(','):
                tp = sport.split('-')
                if len(tp) < 2:
                    ports.append(int(tp[0]))
                else:
                    start, end = int(tp[0]), int(tp[1])
                    rpors = list(range(start, end+1))
                    ports.extend(rpors)
        elif '-' in self.raw_port:
            tp = self.raw_port.strip().split('-')
            start, end = int(tp[0]), int(tp[1])
            rpors = list(range(start, end+1))
            ports.extend(rpors)
        elif ',' in self.raw_port:
            ports.extend([int(p) for p in self.raw_port.strip().split(',')])
        else:
            ports.append(int(self.raw_port))
        ports = list(set(ports))
        self.ports.extend(ports)

    def __formatNet(self):
        nets = []
        if self.raw_ip.count('.') < 3:
            self.ips.append(self.raw_ip)
            return
        if ',' in self.raw_ip:
            nets = [i for i in self.raw_ip.strip().split(',')]
        else:
            nets.append(self.raw_ip)
        ok = [self.isNetwork(x) for x in nets]
        if False in ok:
            os._exit(1)
        self.__formatIP()

    def __formatIP(self):
        for x in self.nets:
            self.ips.extend(list(x))
        self.ips = list(map(lambda x:x.compressed, self.ips))

    def portscan(self):
        print_line('端口扫描')
        with ThreadPoolExecutor(self.thread) as exec:
            for ip in self.ips:
                self.opens[ip] = {}
                start = time.time()
                tasks = []
                self.ports.sort()
                for port in self.ports:
                    tasks.append(exec.submit(self.check_port, ip, port))
                for t in tasks:
                    t.result()
                if len(self.opens[ip].keys()) == 0:
                    print(ip, '未开启端口')
                    continue
                print('执行用时{:.2f}秒, {} 开放端口数量: {}'.format((time.time() - start), ip, len(self.opens[ip])))

    def check_port(self, ip: str, port: int):
        s = socket.socket()
        s.settimeout(self.timeout)
        try:
            s.connect((ip, port))
            s.send(b'CP')
            with self.lock:
                print('open\t{}:{}'.format(ip, port))
                self.opens[ip][port] = None
                data = s.recv(2048)
                if data:
                    self.opens[ip][port] = data.strip()
        except Exception:
            pass
        finally:
            s.close()

    def format(self):
        self.__formatPort()
        self.__formatNet()