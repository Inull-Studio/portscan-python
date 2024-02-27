import re, struct

default_port = [21, 22, 23, 25, 53, 80, 111, 135, 443, 445, 514, 1433, 2121, 3306, 3389, 5432, 5900, 8080, 8088, 8888]

def bytes_format(data: bytes):
    if data == b'\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27':
        return 'telnet'
    else:
        return 'Unknow'

def data_format(data: bytes):
    try:
        string = data.decode('utf8')
        if 'vsftp' in string.lower():
            return re.search('\((.*)\)', string).group(1)
        elif 'openssh' in string.lower():
            return string.split()[0]
        elif 'pure-ftp' in string.lower():
            return [x for x in string.split() if 'pure-ftp' in x.lower()][0]
        elif 'proftp' in string.lower():
            return ' '.join(string.split()[1:5])
        else:
            return string
    except:
        return bytes_format(data)