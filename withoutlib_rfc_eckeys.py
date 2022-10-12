import json
import base64
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

f = open('SCV_PowerEdgeCSeries_Profile_v1.5.json')
payload = json.load(f)

header = {'alg': 'ES384',
         'typ': 'JWT',
         'x5c':["MIIC7TCCAnOgAwIBAgIUdx2dJj72Tr2ZiDmOfThZ5jRJpC8wCgYIKoZIzj0EAwMwgZgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczETMBEGA1UEBwwKUm91bmQgUm9jazEfMB0GA1UECgwWRGVsbCBUZWNobm9sb2dpZXMgSW5jLjEqMCgGA1UECwwhU2VydmVyIGFuZCBJbmZyYXN0cnVjdHVyZSBTeXN0ZW1zMRcwFQYDVQQDDA5pRFJBQyBTQ1YgUm9vdDAeFw0yMDA4MjUxODM5NDBaFw0zODA4MjQxODM5NDBaMIGuMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEzARBgNVBAcMClJvdW5kIFJvY2sxHzAdBgNVBAoMFkRlbGwgVGVjaG5vbG9naWVzIEluYy4xKjAoBgNVBAsMIVNlcnZlciBhbmQgSW5mcmFzdHJ1Y3R1cmUgU3lzdGVtczEtMCsGA1UEAwwkaURSQUMgU2VjdXJlZCBDb21wb25lbnQgVmVyaWZpY2F0aW9uMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDoOY22XWcSrg0TzkTLY+jDAMX4W2bhcnl9xFmUn9i5vbR+a5PIKSg/nu+yMfHPSPxGCymEBVAXxtOzCc/9nsM8mgVKwZTGum2biL+zypZnJ930JBdOgCvSWjL+RV8Vx0o2YwZDAdBgNVHQ4EFgQUB5WZa2AHKfb/0zwF1NpGx9LQ4ikwHwYDVR0jBBgwFoAURUPdegU34dWDj6E6PES8bXUt/64wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwMDaAAwZQIwfOooIe6P8/SF6+rScnOQZwVphaXn8tby+UDAqh0qZ7o5k65YW/57/jBgCbY2kN9pAjEAj6ejcrCqm8Uhon59LYZ99omBhzv/CJ+Om2ojNweAsTZKnWrHlP2OO5UfyEVRfWo/"]
         }
key_file = open("es384priv.pem", "r")
key = key_file.read()
key_file.close()
priv_key = serialization.load_pem_private_key(key.encode(), password=None)

if key.startswith('-----BEGIN '):
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
else:
    pkey = crypto.load_pkcs12(key).get_privatekey()

header_str = json.dumps(header,separators=(',', ':'))
header_enc = header_str.encode("utf-8")
header_encoded = base64.urlsafe_b64encode(header_enc).rstrip(b'=')
base64_header = header_encoded.decode("utf-8")
print(base64_header)

payload_str = json.dumps(payload,separators=(',', ':'))
payload_enc = payload_str.encode("utf-8")
payload_encoded = base64.urlsafe_b64encode(payload_enc).rstrip(b'=')
base64_payload = payload_encoded.decode("utf-8")
print(base64_payload)

str = base64_header + "." + base64_payload

res = bytes(str, 'utf-8')
signature = priv_key.sign(res,ec.ECDSA(hashes.SHA384()))

sign_base64 = base64.urlsafe_b64encode(signature).rstrip(b'=')
sign_final= sign_base64.decode("utf-8")
print(sign_final)

jwt_str = base64_header +"." + base64_payload + "." + sign_final
#MEUCIQCavwdEM4qYEdpxO8T5Rrl6Q0cfMMd91urFINdGy2h6jwIgSleFZx0I8dy8gCL0hgtbuwTRtKzIbWhISfTgBz1knIw
#############################################################################################

public_key = open('es384pub.pem', 'r').read()
pubkey = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)


# the verify() function expects that the public key is wrapped in an X.509 certificate
x509 = crypto.X509()
x509.set_pubkey(pubkey)

#print( jwt.decode(jwt=jwt_str, key=public_key, algorithms=["ES256"]))

header_payload_from_jwt = jwt_str.split('.')[0] + "." + jwt_str.split('.')[1]
sign_from_jwt = jwt_str.split('.')[2]
decoded_sign = base64.urlsafe_b64decode(sign_from_jwt + '=' * (4 - len(sign_from_jwt) % 4))
#print(decoded_sign)

try:
    if crypto.verify(x509, decoded_sign,header_payload_from_jwt , 'sha384') is None:
        print("Success!")
except Exception as ex:
        raise ValueError(f"Error occurred during signature validation: {ex}", {"error": 400})
        print(False)
