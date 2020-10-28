from dnslib.server import DNSServer, BaseResolver
from dnslib import RR
import copy

class FixedResolver(BaseResolver):
    def __init__(self,zone,keyAuth):
        self.rrs = RR.fromZone(zone)
        self._keyAuth = keyAuth

    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname

        if not self._keyAuth == '':
            qname = self._keyAuth
            print(qname)
        for rr in self.rrs:
            a = copy.copy(rr)
            a.rname = qname
            reply.add_answer(a)
        return reply

class DnsServer:
    def __init__(self, host: str, record: str, url: str):
        resolver = FixedResolver(record, url)
        self._server = DNSServer(resolver, port=10053, address=host)

    def start(self):
        self._server.start_thread()

    def shutDown(self):
        self._server.stop()




