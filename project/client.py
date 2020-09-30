from typing import Any, List
import requests
import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from utils import *

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
                { "type": "dns", "value": "www.example.org" },
            ]}).encode('utf8'))
        responseOrder: Response = self._signedPost(self._newOrder, payload)
        authTarget: str = responseOrder.json()['authorizations'][0]
        emptyPayload: str = getBase64(''.encode('utf8'))
        responseAuth: Response = self._signedPost(authTarget, emptyPayload)
        print(responseAuth.text)

    def _getProtectedHeader(self, target:str, publicKey: Any) -> str:
        nonce: str = self._getNonce()
        header: dict = {
            'alg': 'RS256',
            'nonce': nonce,
            'url': target
        }
        if target == self._newAccount:
            n: str = getBase64(intToBytes(publicKey.public_numbers().n))
            e: str = getBase64(intToBytes(publicKey.public_numbers().e))
            header['jwk'] = {
                'kty': 'RSA',
                'n': n,
                'e': e
            }
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
        protectedHeader: str = self._getProtectedHeader(target, self._publicKey)
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
        print(target)
        r: Response = requests.post(target, verify='pebble.minica.pem', headers=headers, data=data)
        return r

    def _getNonce(self) -> str:
        r = requests.get(self._newNonce, verify='pebble.minica.pem')
        return r.headers['Replay-Nonce']
