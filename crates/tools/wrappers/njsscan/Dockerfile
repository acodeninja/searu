FROM python:3.13-slim

RUN pip install --no-cache-dir njsscan==1.0.0

# njsscan exits non-zero whenever it reports a finding, with no flag to suppress it; searu signals a
# clean run through exit 0 and reports findings separately, so normalise the exit code here.
ENTRYPOINT ["/bin/sh", "-c", "njsscan \"$@\"; exit 0", "--"]
