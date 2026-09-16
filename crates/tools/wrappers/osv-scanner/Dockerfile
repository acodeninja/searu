FROM ghcr.io/google/osv-scanner:v2.6.0

# osv-scanner exits non-zero whenever it reports a vulnerability, with no flag to suppress it; searu
# signals a clean run through exit 0 and reports findings separately, so normalise the exit code here.
ENTRYPOINT ["/bin/sh", "-c", "/osv-scanner \"$@\"; exit 0", "--"]
