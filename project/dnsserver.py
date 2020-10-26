from dnslib.server import DNSServer, DNSRecord
from dnslib import RR
import sys

record = ''

for i, arg in enumerate(sys.argv):
    if i == 0:
        continue
    if i == 1:
        record = arg

class TestResolver:
    def resolve(self,request,handler):
        reply = request.reply()
        reply.add_answer(*RR.fromZone(f". 60 IN A {record}"))
        print("dns ", reply)
        return reply

resolver = TestResolver()
server = DNSServer(resolver, port=10053, address=record)
server.start()


