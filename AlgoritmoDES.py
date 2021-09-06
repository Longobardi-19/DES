from Crypto.Cipher import DES
from secrets import token_bytes

key = token_bytes(8)


def encrypt(msg):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    textocifrado, tag = cipher.encrypt_and_digest(msg.encode())
    return nonce, textocifrado, tag


def decrypt(nonce, textocifrado, tag):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    textodescifrado = cipher.decrypt(textocifrado)

    try:
        cipher.verify(tag)
        return textodescifrado.decode('utf-8')
    except:
        return False


nonce, textocifrado, tag = encrypt(input('Ingresa un mensaje: '))
textodescifrado = decrypt(nonce, textocifrado, tag)
print(f'Texto cifrado:{textocifrado}')

if not textodescifrado:
    print('Mensaje corrupto')
else:
    print(f'Texto ingresado: {textodescifrado}')
