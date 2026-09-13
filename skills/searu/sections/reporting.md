# Reporting

Review and summarise what the engagement recorded. Everything `searu` captured lives in three
append-only stores under `./pentest/`, queryable at any time.

## Review the stores

```
searu findings                      # all findings; filter with --technique/--severity/--tool
searu loot                          # captured secrets by fingerprint; --reveal to see values
searu observations                  # recon: endpoints, servers, tech, params
```

Group findings into issues (one defect can affect many endpoints), lead with the highest severity,
and tie each to its ATT&CK technique and evidence. Loot values are sensitive — reveal them only when
the report needs them, and remember findings themselves store only a fingerprint.

## Formal report & export (planned, M4)

A `searu report` deliverable (PDF, with a rules-of-engagement appendix and an ATT&CK coverage
heat-map) and a Dradis CSV export are planned for a later milestone. Until then the deliverable is
the queried findings/loot/observations above, summarised by you.
