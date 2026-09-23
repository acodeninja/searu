import argparse
import json
import os
import sys
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--url", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--name", default=None)
parser.add_argument("--header", action="append", default=[])
# A general HTTP request: default GET downloads a file; --method POST/PUT with --data drives an API
# (e.g. POST /rest/user/login to mint a session token).
parser.add_argument("--method", default="GET")
parser.add_argument("--data", default=None)
args = parser.parse_args()

name = args.name or (args.url.rstrip("/").split("/")[-1].split("?")[0] or "download.bin")
body = args.data.encode() if args.data is not None else None
request = urllib.request.Request(args.url, method=args.method.upper(), data=body)
for header in args.header:
    if ":" in header:
        key, value = header.split(":", 1)
        request.add_header(key.strip(), value.strip())

try:
    response = urllib.request.urlopen(request, timeout=20)
    data = response.read()
    status = response.getcode()
except urllib.error.HTTPError as error:
    status = error.code
    data = error.read() or b""
except Exception as error:  # noqa: BLE001 - report any transport failure and stop
    print(f"error: {error}", file=sys.stderr)
    sys.exit(1)

path = os.path.join(args.out, name)
with open(path, "wb") as handle:
    handle.write(data)

print(json.dumps({"kind": "download", "url": args.url, "name": name, "bytes": len(data), "status": status}))

# If the response is JSON carrying a session token (login/refresh), surface it as loot so authz/jwt can
# carry it. Juice Shop nests it under authentication.token; other apps use a top-level token/access_token.
try:
    doc = json.loads(data.decode("utf-8", "replace"))
    token = None
    if isinstance(doc, dict):
        auth = doc.get("authentication")
        if isinstance(auth, dict) and isinstance(auth.get("token"), str):
            token = auth["token"]
        for key in ("token", "access_token", "accessToken", "jwt"):
            if token is None and isinstance(doc.get(key), str):
                token = doc[key]
    if token:
        print(json.dumps({"kind": "token", "value": token}))
except Exception:  # noqa: BLE001 - a non-JSON body simply has no token to extract
    pass
