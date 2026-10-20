#!/usr/bin/env python3
"""Create local demonstration secrets outside the source/public tree."""
import json, os, secrets, stat, subprocess, sys
from pathlib import Path
product, folder, origin = sys.argv[1:]
d = Path(folder)
if d.is_symlink():
    raise SystemExit('Refusing a symlink as the demo secrets directory.')
if d.exists():
    info = d.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise SystemExit('Existing demo secrets directory must be a private directory owned by the current user, mode 0700.')
    if any(d.iterdir()):
        raise SystemExit('Existing demo secrets preserved. Choose an empty private SOCA_DEMO_SECRETS directory.')
else:
    d.mkdir(mode=0o700, parents=True)

subprocess.run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',str(d/'client.pem')],check=True)
(d/'state.key').write_bytes(secrets.token_bytes(32))
for name in ['admin-password','db-password','db-root']:
    (d/name).write_text(secrets.token_urlsafe(32)+'!Aa7')
host=origin.split('://',1)[1].split(':',1)[0]
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','7','-keyout',str(d/'server.key'),'-out',str(d/'server.crt'),'-subj','/CN='+host,'-addext','subjectAltName=DNS:'+host],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
root=Path(__file__).resolve().parents[1]
c=json.loads((root/'config.example.json').read_text())
c.update({'origin':origin,'metadata_mode':'proxy','private_key_file':'/run/soca/client.pem','state_key_file':'/run/soca/state.key','client_name':'SOCA '+product+' local demo'})
(d/'config.json').write_text(json.dumps(c,indent=2)+'\n')
# The directory remains 0700 on the host. Individual read-only mounts are readable by web workers.
for p in d.iterdir(): p.chmod(0o644)
print('Demo configuration and generated secrets: '+str(d))
