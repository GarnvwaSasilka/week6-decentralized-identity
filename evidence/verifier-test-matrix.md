| Test | Fixture / Request | Expected | Observed | Reason Code | Explanation |
|---|---|---|---|---|---|
| Valid credential | valid.json + correct holder + read-training-lab | ALLOW | ALLOW | ALL_REQUIRED_CHECKS_PASSED | All checks passed. |
| Untrusted issuer | untrusted-issuer.json | DENY | DENY | ISSUER_NOT_TRUSTED | Issuer not in trust list. |
| Expired credential | expired.json | DENY | DENY | CREDENTIAL_EXPIRED | validUntil is in the past. |
| Missing claim | missing-claim.json | DENY | DENY | REQUIRED_CLAIM_MISSING | Required status field missing. |
| Unauthorised action | valid.json + delete-root-database | DENY | DENY | ACTION_NOT_ALLOWED | Action not allowed by policy. |
| Subject mismatch | valid.json + wrong holder DID | DENY | DENY | SUBJECT_MISMATCH | Holder DID doesn't match credential subject. |
| Subject mismatch | valid.json + wrong holder DID | DENY | DENY | SUBJECT_MISMATCH | Holder DID doesn't match credential subject. |
