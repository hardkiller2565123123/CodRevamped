"""Exercise the running local server with synthetic credentials only."""
import base64
import http.client
import json
import urllib.parse
import ssl
import time
from pathlib import Path

local_ca = Path(r'D:\SteamLibrary\steamapps\common\Call of Duty Modern Warfare\revamped-bgs-root-ca.cer')
context = ssl.create_default_context(cadata=local_ca.read_bytes())
# The existing local CA lacks AKI; retain chain verification with pre-3.13 rules.
context.verify_flags &= ~ssl.VERIFY_X509_STRICT
# Synthetic loopback-only test; the local service certificate names DW hosts.
context.check_hostname = False
connection = http.client.HTTPSConnection('127.0.0.1', 443, timeout=20, context=context)
body = urllib.parse.urlencode(dict(titleID=6000, platform='steam', serviceLevel='paid',
    ivSeed=1, machineID='codrevamped-title-contract-test', token='local-test'))
connection.request('POST', '/v1/login/', body, {
    'Host': 'wz-steam-loginservice.prod.demonware.net',
    'Content-Type': 'application/x-www-form-urlencoded',
})
response = connection.getresponse()
assert response.status == 200, response.status
data = json.loads(response.read())
connection.close()
title = data['title']
for key in ('userID', 'sessionID', 'titleID'):
    assert type(title[key]) is int and title[key] > 0, key
for key, bound in [('accountType', 11), ('username', 65), ('clientID', 64),
                   ('sessionKey', 33), ('loginTicket', 512), ('lsgEndpoint', 1024)]:
    assert isinstance(title[key], str) and 0 < len(title[key].encode()) < bound, key
assert type(title['crossplayEnabled']) is bool
key = base64.b64decode(title['sessionKey'], validate=True)
ticket = base64.b64decode(title['loginTicket'], validate=True)
assert len(key) == 24
assert len(ticket) == 128
assert ticket[:24] == key
assert title['userID'] == data['userID']
assert type(title['loginTicketIssueTime']) is int
assert abs(time.time() - title['loginTicketIssueTime']) < 60
umbrella = data['umbrella']
for field in ('unoID', 'umbrellaID', 'accessExpiresIn', 'refreshExpiresIn'):
    assert type(umbrella[field]) is int and umbrella[field] > 0, field
for field, bound in [('unoUsername', 65), ('accessToken', 4096), ('refreshToken', 4096)]:
    assert isinstance(umbrella[field], str) and 0 < len(umbrella[field]) < bound, field
assert isinstance(umbrella['accounts'], list)
assert data['uno']['unoID'] == umbrella['unoID'] == title['userID']
assert isinstance(data['uno']['userName'], str) and 0 < len(data['uno']['userName']) < 65
print('PASS: native title/Umbrella/UNO types, bounds, identity and local session-key binding')
