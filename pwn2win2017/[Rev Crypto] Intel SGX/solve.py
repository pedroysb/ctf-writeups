import base64

from pwn import *

from Crypto.Util.number import *

from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

p = None
private_key = None
public_key = None
symmetric_key = None

def generate_keys():
    global private_key, public_key, symmetric_key
    private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
    public_key = private_key.public_key()
    symmetric_key = None

def derive_key(shared_key, label):
    shared_key_le = shared_key[::-1]
    key_0_str = "00000000000000000000000000000000".decode("hex")

    c1 = cmac.CMAC(algorithms.AES(key_0_str), backend=default_backend())
    c1.update(shared_key_le)
    cmac_key0 = str(c1.finalize())

    derive_key_str = ("01" + label.encode("hex") + "008000").decode("hex")

    c2 = cmac.CMAC(algorithms.AES(cmac_key0), backend=default_backend())
    c2.update(derive_key_str)
    derived_key = c2.finalize()

    return derived_key

def decrypt(key, ciphertext):
    iv = ciphertext[:12]
    tag = ciphertext[12:28]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext[28:]) + decryptor.finalize()

def send_msg0():
    public_numbers = public_key.public_numbers()
    key_base64_le = base64.b64encode(long_to_bytes(public_numbers.x)[::-1] +
        long_to_bytes(public_numbers.y)[::-1])

    p.sendline(key_base64_le)
    res = p.recv()
    print res
    return base64.b64decode(res.split("\n")[1].strip())

def process_msg1(msg1):
    try:
        global symmetric_key

        x = bytes_to_long(msg1[:32][::-1])
        y = bytes_to_long(msg1[32:64][::-1])
        gid = msg1[64:68][::-1]
        context = msg1[-4:]

        sp_public_key_le = msg1[:64]

        sp_public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())
        shared_key = private_key.exchange(ec.ECDH(), sp_public_key)

        derived_key_smk = derive_key(shared_key, "SMK")
        symmetric_key = derive_key(shared_key, "SK")

        public_numbers = public_key.public_numbers()
        public_key_le = long_to_bytes(public_numbers.x)[::-1] + long_to_bytes(public_numbers.y)[::-1]

        spid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".decode("hex")
        quote_type = "0000".decode("hex")[::-1]
        kdf_id = "0001".decode("hex")[::-1]

        public_keys_concat = public_key_le + sp_public_key_le
        sign_pk_concat_encoded = private_key.sign(public_keys_concat, ec.ECDSA(hashes.SHA256()))
        sign_pk_concat_decoded = utils.decode_dss_signature(sign_pk_concat_encoded)
        sign_pk_concat = long_to_bytes(sign_pk_concat_decoded[0])[::-1] + long_to_bytes(sign_pk_concat_decoded[1])[::-1]

        c = cmac.CMAC(algorithms.AES(derived_key_smk), backend=default_backend())
        c.update(public_key_le + spid + quote_type + kdf_id + sign_pk_concat)
        mac = c.finalize()

        sig_rl_size = format(0, "08x").decode("hex")

        msg2 = public_key_le + spid + quote_type + kdf_id + sign_pk_concat + mac + sig_rl_size

        return msg2
    except Exception as e:
        print e
        return process_msg1(msg1)

def send_msg2(msg2):
    p.sendline(base64.b64encode(msg2))
    res = p.recvline()
    print res
    res = p.recvline()
    print res
    res = p.recvline()
    print res
    return base64.b64decode(res.strip())

def main():
    global p, symmetric_key
    p = remote("enclave.butcher.team", 8088)
    res = p.recv()
    print res
    p.sendline("2")
    res = p.recv()
    print res
    generate_keys()
    msg1 = send_msg0()
    msg2 = process_msg1(msg1)
    flag = send_msg2(msg2)
    print decrypt(symmetric_key, flag)
    p.close()

if __name__ == "__main__":
    main()
