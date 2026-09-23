import argparse
import json
import sys
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--url", required=True)
parser.add_argument("--method", default="GET")
parser.add_argument("--header", action="append", default=[])
parser.add_argument("--data", default=None)
parser.add_argument("--should-deny", action="store_true")
parser.add_argument("--label", default="")
args = parser.parse_args()

body = args.data.encode() if args.data is not None else None
request = urllib.request.Request(args.url, method=args.method.upper(), data=body)
for header in args.header:
    if ":" in header:
        name, value = header.split(":", 1)
        request.add_header(name.strip(), value.strip())

try:
    response = urllib.request.urlopen(request, timeout=15)
    status = response.getcode()
    length = len(response.read())
except urllib.error.HTTPError as error:
    status = error.code
    length = len(error.read() or b"")
except Exception as error:  # noqa: BLE001 - report any transport failure and stop
    print(f"error: {error}", file=sys.stderr)
    sys.exit(1)

print(json.dumps({"kind": "replay", "status": status, "length": length, "url": args.url}))

allowed = 200 <= status < 400
if args.should_deny and allowed:
    print(f"VIOLATION status={status} length={length} label={args.label} url={args.url}")
