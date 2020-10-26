from dnslib.server import DNSServer, DNSRecord
from dnslib import RR

class TestResolver:
    def resolve(self,request,handler):
        reply = request.reply()
        reply.add_answer(*RR.fromZone(". 60 IN A 127.0.0.1"))
        print("dns ", reply)
        return reply

resolver = TestResolver()
server = DNSServer(resolver, port=10053, address="127.0.0.1")
server.start()


