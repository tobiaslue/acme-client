import base64

def getBase64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode('utf-8').replace('=', '')
    
def intToBytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')