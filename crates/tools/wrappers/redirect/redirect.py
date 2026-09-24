import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse

parser = argparse.ArgumentParser()
parser.add_argument("--url", required=True)  # the redirect endpoint, e.g. http://host/redirect
parser.add_argument("--param", default="to")  # the redirect-target parameter
parser.add_argument("--attacker", default="https://searu-redirect.example/pwned")
# Known allow-listed strings to embed for a bypass (an allowlist that only substring-matches is defeated
# by appending an allow-listed URL to an attacker URL); supplied by the operator per target.
parser.add_argument("--allowlisted", action="append", default=[])
args = parser.parse_args()

target_host = urlparse(args.url).netloc
attacker_host = urlparse(args.attacker).netloc or args.attacker

candidates = [args.attacker]
for allowed in args.allowlisted:
    candidates += [
        f"{args.attacker}?x={allowed}",
        f"{args.attacker}#{allowed}",
        f"{args.attacker}/{allowed}",
        f"{allowed}.{attacker_host}",
        allowed,  # for a deprecated-but-still-allow-listed destination
    ]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


opener = urllib.request.build_opener(NoRedirect)


def probe(destination):
    sep = "&" if "?" in args.url else "?"
    url = args.url + sep + args.param + "=" + quote(destination, safe="")
    try:
        response = opener.open(url, timeout=15)
        return response.getcode(), response.headers.get("Location"), url
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Location"), url
    except Exception as error:  # noqa: BLE001 - a single transport failure should not abort the sweep
        print(f"error: {error}", file=sys.stderr)
        return None, None, url


for destination in candidates:
    status, location, url = probe(destination)
    if status is None:
        continue
    print(json.dumps({"kind": "redirect", "status": status, "location": location, "url": url}))
    if location and 300 <= status < 400:
        loc_host = urlparse(location).netloc
        controlled = location == destination or attacker_host in location or loc_host == urlparse(destination).netloc
        if loc_host and loc_host != target_host and controlled:
            print(f"REDIRECT-VIOLATION status={status} location={location} payload={destination} url={url}")
