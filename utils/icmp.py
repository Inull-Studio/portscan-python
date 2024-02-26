from ping3 import ping


def alive(dst: str, timeout: int, interface: str=None):
    OKs = []
    for _ in range(3):
        OKs.append(ping(dst, timeout, interface=interface))
    if type(OKs[0]) == bool:
        return False
    else:
        return True