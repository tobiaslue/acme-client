from client import Client
import sys
from flask import Flask, request
from flask.helpers import make_response
from multiprocessing import Process

challenge_type = ''
directory = ''
record = ''
revoked = False
domains = []

for i, arg in enumerate(sys.argv):
    if i == 0:
        continue
    if i == 1:
        challenge_type = arg
    elif i == 2:
        directory = arg
    elif i == 3:
        record = arg
    elif arg == 'revoke':
        revoked = True
    else:
        domains.append(arg)

print(revoked)

client = Client(
    challengeType=challenge_type, 
    directory=directory,
    record=record,
    domains=domains,
    isRevoked=revoked)
client.createAccount()
client.writePrivateKey()
certificate = client.getCertificate()
if revoked:
    client.revokeCertificate(certificate.text)
f = open('certificate.pem', 'w')
f.write(certificate.text)
f.close()
print('Certificate ready')
app = Flask(__name__)
@app.route('/')
def getCertificate():
    response = make_response(certificate.text)
    return response
p = Process(target=app.run, kwargs={
    'host': record,
    'port': 5001,
    'ssl_context': ('certificate.pem', 'privateKey.pem')
})   
p.start()  

def shutdown_server():
    print('Shut down shutdown server')
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

shutDownServer = Flask(__name__)

@shutDownServer.route('/')
def shutDown():
    shutdown_server()
    return 'shutdown'

shutDownServer.run(port=5003)

p.terminate()
p.join()
print('Shut down certificate server')