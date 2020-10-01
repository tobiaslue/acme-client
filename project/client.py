from typing import Any, List
from flask import Flask
from flask.helpers import make_response
import requests
import json
from multiprocessing import Process
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from utils import *
import time

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
        self._publicKey = self._privateKey.public_key()
        self._setEndpoints()

    def _getKeyAuth(self, token: str) -> str:
        jwk: bytes = json.dumps(self._getJwk()).encode('utf8')
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(jwk)
        digest = getBase64(digest.finalize())
        print("digest: " + digest)
        keyAuth: str = f'{token}.{digest}'
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
        self._kid: str = response.headers['location']

    def getCertificate(self) -> None:
        payload: str = getBase64(json.dumps({
            "identifiers": [
                { "type": "http1", "value": "www.example.org" },
            ]}).encode('utf8'))
        responseOrder: Response = self._signedPost(self._newOrder, payload)
        print(responseOrder.json())
        authTarget: str = responseOrder.json()['authorizations'][0]
        emptyPayload: str = getBase64(''.encode('utf8'))
        responseAuth: Response = self._signedPost(authTarget, emptyPayload)
        token: str = responseAuth.json()['challenges'][1]['token']
        print(token)
        url:str = responseAuth.json()['challenges'][1]['url']
        keyAuth: str = self._getKeyAuth(token)
        print(keyAuth)
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

        r: Response = self._signedPost(url, emptyPayload)  
        print(r.text)
        time.sleep(3)
        r: Response = self._signedPost(url, emptyPayload)  
        print(r.text)
        time.sleep(3)
        r: Response = self._signedPost(url, emptyPayload)  
        print(r.text)
        time.sleep(3)
        r: Response = self._signedPost(url, emptyPayload)  
        print(r.text)
        time.sleep(3)
        r: Response = self._signedPost(url, emptyPayload)  
        print(r.text)
        time.sleep(3)
        r: Response = self._signedPost(url, emptyPayload)  
        print(r.text)
        time.sleep(3)
        r: Response = self._signedPost(url, emptyPayload)  
        print(r.text)

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
        print(header)
        return getBase64(json.dumps(header).encode('utf-8'))

    def _getHeader(self) -> dict:
        return  {
            'User-Agent': 'My User Agent 1.0',
            'Content-Type': 'application/jose+json'
        }

    def _signedPost(self, target: str, payload: str) -> Response:
        headers: dict = self._getHeader()
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
        return r

    def _getNonce(self) -> str:
        r = requests.get(self._newNonce, verify='pebble.minica.pem')
        return r.headers['Replay-Nonce']
