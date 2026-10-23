# Public-source privacy review

The initial secret scan did not catch all personal information. The sanitized
source replaces captured temporary test paths and deployment-derived graph/network
identifiers with explicit synthetic values, uses the organization dependency URL,
and strips ancillary image metadata without changing compressed image pixels.
The synthetic owner proof and review digests were regenerated to remain valid.

Public release commits use neutral project attribution. Real Wallets, passwords,
private keys, API tokens, recovery files, machine configuration, native signing
profiles and compiled artifacts are not included. Test credentials and keys are
explicitly synthetic; public certificate fixtures name example hosts.

Generic product paths and protocol names remain in source because they implement
discovery and storage. Loopback API defaults, supported OS paths and example
network addresses are product behavior/test data, not evidence that a user's
machine is publicly reachable.

Verification: 177 native tests, six opt-in checks skipped, zero failures after
fixture sanitization. Gitleaks and the committed-tree privacy guard are separate
checks. A private deny-list may add known identifiers without publishing them:

```sh
python3 scripts/check-public-privacy.py --ref main --deny-list /private/path/markers.json
gitleaks git . --config .gitleaks.toml --redact
```

History replacement removes the old commit from the branch; it cannot erase
copies already fetched or guarantee immediate removal of provider caches. GitHub
cached/dangling commit removal may require a separate repository-owner request.
