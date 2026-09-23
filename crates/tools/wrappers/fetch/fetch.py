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
args = parser.parse_args()

name = args.name or (args.url.rstrip("/").split("/")[-1].split("?")[0] or "download.bin")
request = urllib.request.Request(args.url)
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
