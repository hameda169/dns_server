from threading import Thread
import socket
import optparse
from dnslib import DNSRecord, QTYPE, RR, A, AAAA
from socket import AF_INET, SOCK_DGRAM
import base64
from urllib.request import urlopen


def handle_dns(proxy, data1, client, sanctions, local_dns):
    request = None
    reply = None
    sanc = False
    try:
        request = DNSRecord.parse(data1)
        question = request.questions[0]

        # check for local dns
        if question.qtype in [QTYPE.A, QTYPE.AAAA]:
            if (str(question.qname), question.qtype) in local_dns.keys():
                reply = request
                dt = A if question.qtype == QTYPE.A else AAAA
                qname = (str(question.qname), question.qtype)
                if type(local_dns[qname]) == str:
                    reply.add_answer(RR(question.qname, question.qtype, 1, 200, dt(local_dns[qname])))
                elif type(local_dns[qname]) == list:
                    [reply.add_answer(RR(question.qname, question.qtype, 1, 200, dt(x))) for x in local_dns[qname]]
                proxy.sendto(reply.pack(), client)
                return

        dns_proxy = [('8.8.8.8', 53), ('8.8.4.4', 53)]  # default dns server

        # change dns server to shecan if it was blocked
        if any(map(lambda x: question.qtype in [QTYPE.A, QTYPE.AAAA] and x in str(question.qname), sanctions)):
            sanc = True
            dns_proxy = [('178.22.122.100', 53), ('185.51.200.2', 53)]

        s = socket.socket(AF_INET, SOCK_DGRAM)
        try:
            s.sendto(data1, dns_proxy[0])
            s.settimeout(0.2)
            data, server = s.recvfrom(8192)
        except socket.timeout:
            s.sendto(data1, dns_proxy[1])
            s.settimeout(1)
            data, server = s.recvfrom(8192)
        reply = DNSRecord.parse(data)
        rr = reply.rr[0] if reply.rr else None  # rr stands for resource records

        if sanc and rr and (rr.rtype not in [QTYPE.CNAME] or str(rr.rdata).find('shecan.ir') == -1):
            with open('warning.log', 'a') as file:
                print(request.questions, file=file)
                print(reply.rr, file=file)
                print(file=file)

        # check if there is any record and try DoH if it was censored
        if rr and rr.rtype in [QTYPE.A, QTYPE.AAAA] and '.'.join(map(str, rr.rdata.data)).startswith('10.10.34'):
            data1 = base64.urlsafe_b64encode(data1).decode().replace("\n", "").replace("\r", "").replace("=", "")
            data = urlopen(f'https://dns.google/dns-query?dns={data1}').read()
            reply = DNSRecord.parse(data)

        with open('all.log', 'a') as file:
            print(request.questions, file=file)
            print(reply.rr, file=file)
            print(file=file)

        proxy.sendto(reply.pack(), client)
    except Exception as exc:
        with open('error.log', 'a') as file:
            print(type(exc), exc, file=file)
            print(request.questions, file=file)
            print(reply.rr if reply else '', file=file)


def main(opts, handler, sanctions):
    bind = (opts.bind, opts.port)
    proxy = socket.socket(AF_INET, SOCK_DGRAM)
    proxy.bind(bind)
    local = {
        ('dns.google.', QTYPE.A): ['8.8.8.8', '8.8.4.4'],
        ('dns.google.', QTYPE.AAAA): '2001:4860:4860::8888',
    }
    print(f'Start dns server on {bind[0]}:{bind[1]}:')
    while True:
        data, client = proxy.recvfrom(8192)
        Thread(target=handler, args=(proxy, data, client, sanctions, local)).start()


def load_sanction():
    s = []
    with open('sanction.list', 'r') as file:
        for i in file.readlines():
            s.append(i[:-1]) if not i.startswith('#') else None
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
    main(options, handle_dns, load_sanction())
