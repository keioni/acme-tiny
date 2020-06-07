import sys
import json
import base64

with open(sys.argv[1]) as fp:
    pkey = json.load(fp)

print('asn1=SEQUENCE:private_key\n[private_key]')
print('version=INTEGER:0')
for k,v in pkey.items():
    if k == 'kty':
        continue
    missing_padding = 4 - len(v) % 4
    if missing_padding > 0:
      v = v + ('='*missing_padding)
    v_hex = base64.urlsafe_b64decode(v).hex().upper()
    print('{}=INTEGER:0x{}'.format(k, v_hex))

# python THIS_SCRIPT private_key.json > private_key.asn1
# openssl asn1parse -genconf private_key.asn1 -noout -out private_key.der
# openssl rsa -inform der -in private_key.der -outform pem -out private_key.pem
