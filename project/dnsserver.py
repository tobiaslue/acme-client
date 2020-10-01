from dnslib.server import DNSServer, DNSLogger
from dnslib.dns import RR

class TestResolver:
    def resolve(self, request, handler):
        reply = request.reply()
        reply.add_answer(*RR.fromZone(". 60 IN A 1.2.3.4"))
        return reply
        

resolver = TestResolver()
logger = DNSLogger(prefix=False)
server = DNSServer(resolver, port=10053, address='1.2.3.4', logger=logger)
server.start()
