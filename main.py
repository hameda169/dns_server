from threading import Thread
import socket
import optparse
from dnslib import DNSRecord, QTYPE, RR, RDMAP
from socket import AF_INET, SOCK_DGRAM
import base64
from urllib.request import urlopen
import json


def is_in_local(request, local_dns):
    question = request.questions[0]
    if question.qtype in [QTYPE.A, QTYPE.AAAA]:
        if (str(question.qname), question.qtype) in local_dns.keys():
            reply = request
            dt = RDMAP[QTYPE[question.qtype]]
            qname = (str(question.qname), question.qtype)
            ans = local_dns[qname]
            [reply.add_answer(RR(question.qname, question.qtype, 1, ans[0], dt(x))) for x in ans[1]]
            return reply, 'LOCAL'
    return None, ''


def is_in_blacklist(request, l):
    question = request.questions[0]
    if any(map(lambda x: x in str(question.qname), l)):
        return request, 'BLACKLIST'
    return None, ''


def is_in_sanction(request, l):
    # change dns server to shecan if it was blocked
    question = request.questions[0]
    if any(map(lambda x: question.qtype in [QTYPE.A, QTYPE.AAAA] and x in str(question.qname), l)):
        dns_proxy = [('178.22.122.100', 53), ('185.51.200.2', 53)]
        s = socket.socket(AF_INET, SOCK_DGRAM)
        try:
            s.sendto(request.pack(), dns_proxy[0])
            s.settimeout(0.2)
            data, _ = s.recvfrom(8192)
        except socket.timeout:
            s.sendto(request.pack(), dns_proxy[1])
            s.settimeout(1)
            data, _ = s.recvfrom(8192)
        return DNSRecord.parse(data), 'SANCTION'
    return None, ''


def is_in_default(request):
    dns_proxy = [('8.8.8.8', 53), ('8.8.4.4', 53)]  # default dns server

    s = socket.socket(AF_INET, SOCK_DGRAM)
    try:
        s.sendto(request.pack(), dns_proxy[0])
        s.settimeout(0.2)
        data, server = s.recvfrom(8192)
    except socket.timeout:
        s.sendto(request.pack(), dns_proxy[1])
        s.settimeout(1)
        data, server = s.recvfrom(8192)
    return DNSRecord.parse(data), 'DEFAULT'


def is_in_doh(request, current_reply, current_where):
    rr = current_reply.rr[0] if current_reply and current_reply.rr else None  # rr stands for resource records
    if rr and rr.rtype in [QTYPE.A, QTYPE.AAAA] and '.'.join(map(str, rr.rdata.data)).startswith('10.10.34'):
        data1 = base64.urlsafe_b64encode(request.pack()).decode().replace("\n", "").replace("\r", "").replace("=", "")
        data = urlopen(f'https://dns.google/dns-query?dns={data1}').read()
        return DNSRecord.parse(data), 'DOH'
    return current_reply, current_where


def logging(request, reply, where):
    rr = reply.rr[0] if reply and reply.rr else None
    if where == 'SANCTION' and rr and (rr.rtype not in [QTYPE.CNAME] or str(rr.rdata).find('shecan.ir') == -1):
        with open('warning.log', 'a') as file:
            print(request.questions, file=file)
            print(reply.rr, file=file)
            print(file=file)

    with open('all.log', 'a') as file:
        print(request.questions, file=file)
        print(reply.rr if reply and reply.rr else '<EMPTY RR>', file=file)
        print(f'<{where}>', file=file)
        print(file=file)


def handle_dns(proxy, data1, client, sanctions, local_dns, blacklist):
    request = None
    reply, where = None, ''
    try:
        request = DNSRecord.parse(data1)

        reply, where = is_in_blacklist(request, blacklist)
        reply, where = is_in_local(request, local_dns) if not where else (reply, where)
        reply, where = is_in_sanction(request, sanctions) if not where else (reply, where)
        reply, where = is_in_default(request) if not where else (reply, where)
        reply, where = is_in_doh(request, reply, where)

        logging(request, reply, where)

        proxy.sendto(reply.pack(), client)
    except Exception as exc:
        with open('error.log', 'a') as file:
            print(type(exc), exc, file=file)
            print(request.questions, file=file)
            print(where, reply.rr if reply and reply.rr else '<EMPTY_RR>', file=file)


def main(opts, handler, sanctions, local, blacklist):
    bind = (opts.bind, opts.port)
    proxy = socket.socket(AF_INET, SOCK_DGRAM)
    proxy.bind(bind)
    print(f'Start dns server on {bind[0]}:{bind[1]}:')
    while True:
        data, client = proxy.recvfrom(8192)
        Thread(target=handler, args=(proxy, data, client, sanctions, local, blacklist)).start()


def load_sanction():
    s = []
    try:
        with open('sanction.list', 'r') as file:
            for i in file.readlines():
                s.append(i[:-1]) if not i.startswith('#') else None
    except FileNotFoundError:
        pass
    return s


def load_local():
    qtypes = {'A': QTYPE.A, 'AAAA': QTYPE.AAAA}
    s = []
    try:
        with open('local.list', 'r') as file:
            s = json.loads(file.read())
    except FileNotFoundError:
        pass
    s = dict(((x['name'], qtypes.get(x['type'])), (x['ttl'], x['answers'])) for x in s)
    return s


def load_blacklist():
    s = []
    try:
        with open('blacklist.list', 'r') as file:
            for i in file.readlines():
                s.append(i[:-1]) if not i.startswith('#') else None
    except FileNotFoundError:
        pass
    return s


def reset():
    file = open('error.log', 'w')
    file.close()
    print('error.log reset')
    file = open('all.log', 'w')
    file.close()
    print('all.log reset')
    file = open('warning.log', 'w')
    file.close()
    print('warning.log reset')


if __name__ == '__main__':
    """
    This application can be used with options
    example: 
        * python3 main.py --help
        * python3 main.py --bind 0.0.0.0 --port 5353
    """
    parser = optparse.OptionParser(usage="Usage: %prog [options]")
    parser.add_option("--port", type=int, default=53, help="Proxy port (default: 53)")
    parser.add_option("--bind", default="127.0.0.153", help="Proxy bind address (default: 127.0.0.153)")
    options, _ = parser.parse_args()
    reset()
    main(options, handle_dns, load_sanction(), load_local(), load_blacklist())
