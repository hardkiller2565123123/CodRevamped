"""Loopback-only regression for the Raven store metadata/content contract."""
import http.client
import json
import ssl
from pathlib import Path

root = Path(r'D:\SteamLibrary\steamapps\common\Call of Duty Modern Warfare')
context = ssl.create_default_context(cadata=(root / 'revamped-bgs-root-ca.cer').read_bytes())
context.verify_flags &= ~ssl.VERIFY_X509_STRICT
context.check_hostname = False  # Loopback transport; local CA verification remains on.
expected = b'{"categories":[]}'
for name in ('store_v2.json', 'store_v2_warzone.json'):
    connection = http.client.HTTPSConnection('127.0.0.1', 443, context=context, timeout=15)
    connection.request('GET', '/__revamped/objectstore/publisher/raven/' + name,
                       headers={'Host': 'objectstore.prod.demonware.net'})
    response = connection.getresponse()
    body = response.read()
    assert response.status == 200, (name, response.status)
    assert int(response.getheader('Content-Length')) == len(expected), name
    assert body == expected, (name, len(body))
    assert json.loads(body) == {'categories': []}
    connection.close()
print('PASS: both Raven store HTTP bodies match the shared 17-byte metadata content')
