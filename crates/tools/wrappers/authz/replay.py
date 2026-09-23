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
# Sweep an object-id range: put `{id}` in --url and pass --range a-b to test each id in one run
# (authenticated IDOR — carry a victim/attacker JWT in --header and walk the neighbouring ids).
parser.add_argument("--range", default=None)
args = parser.parse_args()

body = args.data.encode() if args.data is not None else None


def expand(url, spec):
    if spec and "{id}" in url:
        try:
            lo_s, hi_s = spec.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
        except ValueError:
            return [(None, url)]
        if hi < lo:
            lo, hi = hi, lo
        if hi - lo > 500:
            hi = lo + 500
        return [(str(i), url.replace("{id}", str(i))) for i in range(lo, hi + 1)]
    return [(None, url)]


def do_request(url):
    request = urllib.request.Request(url, method=args.method.upper(), data=body)
    for header in args.header:
        if ":" in header:
            name, value = header.split(":", 1)
            request.add_header(name.strip(), value.strip())
    try:
        response = urllib.request.urlopen(request, timeout=15)
        return response.getcode(), len(response.read())
    except urllib.error.HTTPError as error:
        return error.code, len(error.read() or b"")


served = False
for ident, url in expand(args.url, args.range):
    try:
        status, length = do_request(url)
    except Exception as error:  # noqa: BLE001 - a single transport failure should not abort the sweep
        print(f"error: {error}", file=sys.stderr)
        continue
    served = True
    print(json.dumps({"kind": "replay", "status": status, "length": length, "url": url}))
    if args.should_deny and 200 <= status < 400:
        label = args.label + (f"#{ident}" if ident is not None else "")
        print(f"VIOLATION status={status} length={length} label={label} url={url}")

if not served:
    sys.exit(1)
