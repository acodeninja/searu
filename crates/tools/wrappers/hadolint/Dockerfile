FROM hadolint/hadolint:v2.15.1-alpine

# hadolint exits non-zero whenever it reports a lint issue, with no flag to suppress it; searu signals a
# clean run through exit 0 and reports findings separately, so normalise the exit code here.
ENTRYPOINT ["/bin/sh", "-c", "hadolint \"$@\"; exit 0", "--"]
