from M2Crypto import RSA, BIO, EVP
import base64
    
def sign(private_key, string_to_sign):
    signing_key = EVP.load_key_string(private_key)

    signing_key.sign_init()
    signing_key.sign_update(string_to_sign)
    return signing_key.sign_final()


def verify_signature(public_key, data_signed, signature):
    
    public_key.reset_context(md='sha1')
    public_key.verify_init()
    public_key.verify_update(data_signed)

    # Signature length is length of modulus in bytes rest is padding
    # get_modulus returns string so /2 for bytes
    return public_key.verify_final(signature)

def load_public_key(public_key_string):
    key = RSA.load_pub_key_bio(BIO.MemoryBuffer(public_key_string))

    pub_key = EVP.PKey()
    pub_key.assign_rsa(key)
    return pub_key

def convert_der_encoded_to_pem(der_encoded):
    TEMPLATE = """
-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----
"""
    return TEMPLATE % base64.encodestring(der_encoded).rstrip()