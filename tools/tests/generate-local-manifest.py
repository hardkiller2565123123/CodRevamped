"""Generate a local empty 1.20 manifest; private key stays in ignored artifacts."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import pefile

root = Path(__file__).resolve().parents[2]
openssl = r"C:\Program Files\Git\usr\bin\openssl.exe"
key = root / "artifacts/build/local-manifest-private.pem"
key.parent.mkdir(parents=True, exist_ok=True)
def run(*args, data=None):
    return subprocess.run([openssl, *map(str, args)], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True).stdout
if not key.exists():
    run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key)
public = run("rsa", "-in", key, "-RSAPublicKey_out", "-outform", "DER")
assert len(public) == 270
parsed = bytearray(0xDC00C)
struct.pack_into("<IHHH", parsed, 0xDC000, 0, 1, 4111, 0)
signature = run("dgst", "-sha256", "-sign", key, "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:8", data=parsed)
assert len(signature) == 256
with tempfile.TemporaryDirectory() as temp:
    # Cryptographic output, not source files.
    sig = Path(temp) / "signature.bin"
    sig.write_bytes(signature)
    pub = Path(temp) / "public.pem"
    pub.write_bytes(run("rsa", "-in", key, "-pubout"))
    run("dgst", "-sha256", "-verify", pub, "-signature", sig,
        "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:8", data=parsed)
    modified = parsed.copy()
    modified[0] ^= 1
    try:
        run("dgst", "-sha256", "-verify", pub, "-signature", sig,
            "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:8", data=modified)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("Modified manifest unexpectedly verified")
body = json.dumps(dict(count=0, manifestver=1, dataverff=4111, purgeCache=0,
                       signature=signature.hex()), separators=(",", ":"))
pe = pefile.PE(r"D:\unlock\Modern Warfare\Call of Duty Modern Warfare (1.20)\game_dx12_ship_replay.exe", fast_load=True)
assert pe.FILE_HEADER.TimeDateStamp == 0x5E9BAF80
stock = pe.get_data(0x2416200, 270)
print(json.dumps(dict(public=list(public), stock=list(stock), body=body,
                     checksum=base64.b64encode(hashlib.sha1(body.encode()).digest()).decode())))
