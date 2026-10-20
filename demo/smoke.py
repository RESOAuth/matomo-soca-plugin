#!/usr/bin/env python3
"""Check the disposable host over HTTPS with its explicitly trusted local certificate."""
import base64, http.client, json, os, socket, ssl, sys
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import urlencode
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
cookies={}
def get(path,fields=None):
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=20)
    connection._create_connection = lambda address, *args, **kwargs: socket.create_connection(('127.0.0.1', parts.port or 443), 20)
    headers={'Host':parts.netloc,'Cookie':'; '.join(key+'='+value for key,value in cookies.items())}
    if fields is not None: headers['Content-Type']='application/x-www-form-urlencoded'
    connection.request('POST' if fields is not None else 'GET',path,body=urlencode(fields) if fields is not None else None,headers=headers)
    response=connection.getresponse(); body=response.read(524288); code=response.status; raw_headers=response.getheaders(); headers=dict(raw_headers)
    for name,value in raw_headers:
        if name.lower()=='set-cookie':
            parsed=SimpleCookie(value)
            for key,item in parsed.items(): cookies[key]=item.value
    connection.close()
    return code,headers,body
code,headers,body=get(paths[0]);assert code==200,(product,'metadata',code)
metadata=json.loads(body)
if config.get('metadata_mode','hosted')=='proxy':
    public={key:value for key,value in metadata.items() if key!='client_id'}
    payload=json.dumps(public,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8')
    encoded=base64.urlsafe_b64encode(payload).decode('ascii').rstrip('=')
    expected=config.get('proxy_template','https://dynamic-cimd.resoauth.cloud/cimd/%s').replace('%s',encoded)
else:
    expected=origin+paths[0]
assert metadata['client_id']==expected
assert metadata['token_endpoint_auth_method']=='private_key_jwt';assert metadata['token_endpoint_auth_signing_alg']=='ES256';assert metadata['id_token_signed_response_alg']=='ES256'
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
class FormInputs(HTMLParser):
    def __init__(self): super().__init__(); self.values={}
    def handle_starttag(self,tag,attributes):
        attrs=dict(attributes)
        if tag=='input' and 'name' in attrs: self.values[attrs['name']]=attrs.get('value','')
if product=='matomo':
    form=FormInputs();form.feed(body.decode('utf-8'))
    code,headers,body=get(paths[3],{'module':'Login','action':'login','form_login':'localadmin','form_password':(secrets/'admin-password').read_text().strip(),'form_nonce':form.values['form_nonce'],'form_redirect':''})
    assert code in (302,303),('local administrator authentication',code)
    code,headers,body=get('/index.php?module=Soca&action=index')
    assert code==200 and b'SOCA sign-in' in body and b'SOCA_CONFIG_FILE' in body,('native administrator settings',code)
    assert b'BEGIN EC PRIVATE KEY' not in body and b'BEGIN PRIVATE KEY' not in body
    print('matomo: authenticated native administrator settings render with redacted deployment status.')
print(product+': HTTPS metadata, public ES256 JWKS, disabled-login denial and native password recovery form passed.')
