# Developer validation

The repository has separate Java, Go and Python validation layers. CI runs all of them in
`.github/workflows/ci.yml`; a successful Gradle build alone does not run the Go sidecar tests or
the Python tool suites.

## Prerequisites

- JDK 21 or newer for the Gradle build and Java tests.
- Go 1.27.0, as declared in `recon/go.mod`.
- Python 3 and GNU grep with PCRE (`grep -P`) for the curated GF checks.
- OpenSSL for the runtime-verification tests, which generate a temporary TLS certificate.

The commands below use a POSIX shell and follow the CI workflow. Build the sidecar first so the
Java integration tests that consume it are enabled:

```bash
set -euo pipefail

(
  cd recon
  go test ./...
  go vet ./...
  go build -trimpath -o /tmp/reconctl ./cmd/reconctl
)

RECONCTL_TEST_BINARY=/tmp/reconctl ./gradlew clean build --no-daemon

python3 tools/gf/manage.py check
python3 tools/gf/manage.py test-grep
python3 -m unittest discover -s tools/gf/tests -v
python3 -m unittest discover -s tools/runtime-verification/tests -v
```

The Gradle build creates both the normal extension JAR and the isolated
`build/runtime-verification/recon-hound-runtime-verification.jar`. CI also smoke-checks the
packaged JARs and passive recon CLI artifact. These tests do not launch Burp or verify Burp's
physical network peer; use the [runtime verification kit](BURP_RUNTIME_KIT.md) for the operator-run
experiment and its limitations.
