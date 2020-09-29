import requests
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

headers = {
    'User-Agent': 'My User Agent 1.0',
    'Content-Type': 'application/jose+json'
}

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

public_key_serialized = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

protected_header = base64.urlsafe_b64encode(json.dumps({
    "alg": "RS256",
    "jwk": public_key_serialized.decode("utf-8"),
    "nonce": "6S8IqOGY7eL2lsGoTZYifg",
    "url": "https://localhost:14000/sign-me-up"
}).encode('utf-8'))


inner_payload = base64.urlsafe_b64encode("".encode('utf-8'))

signature = private_key.sign(
    (protected_header + '.'.encode('utf-8') + inner_payload),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

signature_base64 = base64.urlsafe_b64encode(signature)

paylaod = {
    'protected': protected_header,
    'payload': inner_payload,
    'signature': signature_base64
}

r = requests.post('https://localhost:14000/sign-me-up', verify='project/pebble.minica.pem', headers=headers, data=paylaod)

print(r.text)