from cryptography.hazmat.primitives import serialization
from typing import Any, Dict, List, Tuple
from flask import Flask
from flask.helpers import make_response
import requests
import json
from multiprocessing import Process
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import time
import base64
from dnsserver import DnsServer

Response = requests.models.Response

class Client:
    def __init__(
        self, 
        challengeType: str, 
        directory: str, 
        record: str, 
        domains: List[str],
        isRevoked: bool
        ) -> None:
        self._challengeType: str = challengeType
        self._directory: str = directory
        self._record: str = record
        self._domains: List[str] = domains
        self._isRevoked: bool = isRevoked
        self._privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._privateCertKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._publicKey = self._privateKey.public_key()
        self._setEndpoints()

    def writePrivateKey(self):
        f = open('privateKey.pem', 'wb')
        f.write(self._privateCertKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        f.close()

    def _getKeyAuth(self, token: str) -> str:
        jwk: bytes = json.dumps(self._getJwk(), sort_keys=True, separators=(',', ':')).encode('utf8')
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(jwk)
        digest = getBase64(digest.finalize())
        keyAuth: str = f'{token}.{digest}'
        print('Create keyAuth')
        return keyAuth

    def _setEndpoints(self) -> None:
        r = requests.get(f'{self._directory}', verify='pebble.minica.pem')
        self._newAccount: str = r.json()['newAccount']
        self._newNonce: str = r.json()['newNonce']
        self._newOrder: str = r.json()['newOrder']
        self._revokeCert: str = r.json()['revokeCert']
    
    def createAccount(self) -> None:
        payload: str = getBase64(json.dumps({
            'termsOfServiceAgreed': True
        }).encode('utf-8'))
        response: Response = self._signedPost(self._newAccount, payload)
        self._orders: str = response.json()['orders']
        self._kid: str = response.headers['location']
        print('Create Account')

    def _createOrder(self) -> Tuple[str, str, str]:
        identifiers: List[dict] = []
        for domain in self._domains:
            identifiers.append({
                'type': 'dns', 
                'value': domain
            })
        payload: str = getBase64(json.dumps({
            'identifiers': identifiers
        }).encode('utf8'))
        response: Response = self._signedPost(self._newOrder, payload)
        finalizeUrl: str = response.json()['finalize']
        authUrls: str = response.json()['authorizations']
        orderUrl: str = response.headers['Location']
        print(f'Create order for {self._domains}')
        return authUrls, finalizeUrl, orderUrl

    def _getChallenge(self, authUrl: str) -> Tuple[str, str, str]:
        emptyPayload: str = getBase64(''.encode('utf8'))
        response: Response = self._signedPost(authUrl, emptyPayload)
        challengeType: str = 'http-01' if self._challengeType == 'http01' else 'dns-01'
        token: str = ''
        url: str = ''
        for c in response.json()['challenges']:
            if c['type'] == challengeType:
                token = c['token']
                url = c['url']
        domain: str = response.json()['identifier']['value']
        print(f'Get {challengeType} Challenge')
        return token, url, domain

    def _solveHttpChallenge(self, keyAuth: str, challengeUrl: str, authUrl: str) -> None:
        dnsServer = DnsServer(self._record, f". 60 IN A {self._record}", '')
        dnsServer.start()
        app = Flask(__name__)
        @app.route('/.well-known/acme-challenge/<token>')
        def challenge(token):
            response = make_response(keyAuth)
            response.headers['Content-Type'] = 'application/octet-stream'
            return response
        p = Process(target=app.run, kwargs={
            'host': self._record,
            'port': 5002
        })   
        p.start()  

        emptyDict: str = getBase64(json.dumps({}).encode('utf8'))
        emptyPayload: str = getBase64(''.encode('utf8'))
        responseChallenge: Response = self._signedPost(challengeUrl, emptyDict) 

        status = 'pending'
        while status == 'pending':
            responseAuth: Response = self._signedPost(authUrl, emptyPayload)
            status = responseAuth.json()['status']
            time.sleep(0.5)

        p.terminate()
        p.join()
        dnsServer.shutDown()
        print(f'Http Challenge {status}')
        
    def _solveDnsChallenge(self, keyAuth: str, domain: str, challengeUrl: str, authUrl: str) -> None:
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(keyAuth.encode('utf8'))
        digest = getBase64(digest.finalize())
        dnsUrl: str = f"_acme-challenge.{domain}."
        dnsRecord: str = f" 300 IN TXT {digest}"
        dnsServer = DnsServer(self._record, dnsRecord, dnsUrl)
        dnsServer.start()
        emptyDict: str = getBase64(json.dumps({}).encode('utf8'))
        emptyPayload: str = getBase64(''.encode('utf8'))
        responseChallenge: Response = self._signedPost(challengeUrl, emptyDict) 
        
        status = 'pending'
        while status == 'pending':
            responseAuth: Response = self._signedPost(authUrl, emptyPayload)
            status = responseAuth.json()['status']
            time.sleep(0.5)

        dnsServer.shutDown()
        print(f'Dns Challenge {status}')


    def getCertificate(self) -> Response:
        authUrls, finalizeUrl, orderUrl  = self._createOrder()
        
        for authUrl in authUrls:
            token, challengeUrl, domain = self._getChallenge(authUrl)
            keyAuth: str = self._getKeyAuth(token)

            if self._challengeType == 'http01':
                self._solveHttpChallenge(keyAuth, challengeUrl, authUrl)
            else:
                self._solveDnsChallenge(keyAuth, domain, challengeUrl, authUrl)
        
        emptyPayload: str = getBase64(''.encode('utf8'))        
        csr: dict = {'csr': self._getCsr()}
        print('Send Csr')
       
        responseCsr: Response = self._signedPost(finalizeUrl, getBase64(json.dumps(csr).encode('utf8')))
        orderR: Response = self._signedPost(orderUrl, emptyPayload)
        certificateUrl = orderR.json()['certificate']
        certificate: Response = self._signedPost(certificateUrl, emptyPayload)
        return certificate

      

    def _getCsr(self) -> str:
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self._domains[0]),
        ]))
        dnsNames = []
        for domain in self._domains:
            dnsNames.append(x509.DNSName(domain))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dnsNames),
            critical=False,
        )
        csr = builder.sign(
            self._privateCertKey, hashes.SHA256()
        )
        return getBase64(csr.public_bytes(serialization.Encoding.DER))



    def _getJwk(self) -> dict:
        n: str = getBase64(intToBytes(self._publicKey.public_numbers().n))
        e: str = getBase64(intToBytes(self._publicKey.public_numbers().e))
        return {
            'e': e,
            'kty': 'RSA',
            'n': n,
        }

    def _getProtectedHeader(self, target:str) -> str:
        nonce: str = self._getNonce()
        header: dict = {
            'alg': 'RS256',
            'nonce': nonce,
            'url': target
        }
        if target == self._newAccount:
            header['jwk'] = self._getJwk()
        else:
            header['kid'] = self._kid
        return getBase64(json.dumps(header).encode('utf-8'))

    def _getHeader(self) -> dict:
        return  {
            'User-Agent': 'My User Agent 1.0',
            'Content-Type': 'application/jose+json'
        }

    def _signedPost(self, target: str, payload: str) -> Response:
        headers: dict = self._getHeader()
        status = 400
        while status == 400:
            protectedHeader: str = self._getProtectedHeader(target)
            signatureSource: bytes =  f'{protectedHeader}.{payload}'.encode('utf8')
            signature: str = getBase64(self._privateKey.sign(
                signatureSource,
                padding.PKCS1v15(),
                hashes.SHA256()
            ))
            data: bytes = json.dumps({
                'protected': protectedHeader,
                'payload': payload,
                'signature': signature
            }).encode('utf8')
            r: Response = requests.post(target, verify='pebble.minica.pem', headers=headers, data=data)
            status = r.status_code
        return r

    def _getNonce(self) -> str:
        r = requests.get(self._newNonce, verify='pebble.minica.pem')
        return r.headers['Replay-Nonce']

    def revokeCertificate(self, certificate: str):
        cert = x509.load_pem_x509_certificate(certificate.encode('utf8')).public_bytes(serialization.Encoding.DER)
        payload: str = getBase64(json.dumps({
            'certificate': getBase64(cert)
        }).encode('utf8'))
        response: Response = self._signedPost(self._revokeCert, payload)
        print('Revoke certificate')

def getBase64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode('utf-8').replace('=', '')
    
def intToBytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')