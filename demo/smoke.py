#!/usr/bin/env python3
"""Check the disposable host over HTTPS with its explicitly trusted local certificate."""
import http.client, json, os, socket, ssl, sys
from pathlib import Path
from urllib.parse import urlsplit
product = sys.argv[1]
secrets = Path(os.environ['SOCA_DEMO_SECRETS'])
config = json.loads((secrets / 'config.json').read_text())
origin = config['origin']; parts = urlsplit(origin)
context = ssl.create_default_context(cafile=str(secrets / 'server.crt'))
paths = {
 'nextcloud': ['/index.php/apps/soca/metadata','/index.php/apps/soca/jwks','/index.php/apps/soca/login','/index.php/login'],
 'typo3': ['/soca/metadata','/soca/jwks','/soca/login','/typo3/'],
 'matomo': ['/index.php?module=Soca&action=metadata','/index.php?module=Soca&action=jwks','/index.php?module=Soca&action=start','/index.php?module=Login&action=login'],
}[product]
def get(path):
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=20)
    connection._create_connection = lambda address, *args, **kwargs: socket.create_connection(('127.0.0.1', parts.port or 443), 20)
    connection.request('GET',path,headers={'Host':parts.netloc})
    response=connection.getresponse(); body=response.read(524288); code=response.status; headers=dict(response.getheaders());connection.close()
    return code,headers,body
code,headers,body=get(paths[0]);assert code==200,(product,'metadata',code)
metadata=json.loads(body);assert metadata['client_id']==origin+paths[0];assert metadata['token_endpoint_auth_method']=='private_key_jwt';assert metadata['token_endpoint_auth_signing_alg']=='ES256';assert metadata['id_token_signed_response_alg']=='ES256'
code,headers,body=get(paths[1]);assert code==200,(product,'jwks',code)
keys=json.loads(body)['keys'];assert keys and keys[0]['crv']=='P-256' and 'd' not in keys[0]
code,headers,body=get(paths[2]);assert code==403,(product,'disabled login',code)
path=paths[3]
for attempt in range(4):
    code,headers,body=get(path)
    if code not in (301,302,303,307,308):break
    target=urlsplit(headers.get('Location',headers.get('location','')))
    assert not target.netloc or target.netloc==parts.netloc,'recovery redirect leaves local host'
    path=target.path+('?' + target.query if target.query else '')
assert code==200,(product,'local recovery form',code)
assert b'password' in body.lower(),(product,'local password recovery missing')
print(product+': HTTPS metadata, public ES256 JWKS, disabled-login denial and native password recovery form passed.')
