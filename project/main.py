from client import Client
import sys
from flask import Flask
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

client = Client(
    challengeType=challenge_type, 
    directory=directory,
    record=record,
    domains=domains,
    isRevoked=revoked)
client.createAccount()
certificate = client.getCertificate().text
print('Certificate ready')
app = Flask(__name__)
@app.route('/')
def getCertificate():
    response = make_response(certificate)
    return response
p = Process(target=app.run, kwargs={
    'host': record,
    'port': 5001
})   
p.start()  
