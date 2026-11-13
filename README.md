# ZKPassport Proof Verifier

API service that verifies ZKPassport proofs server-side, so that services which cannot run
`@zkpassport/sdk` themselves can verify a proof bundle with a single POST request.

## Endpoints

- `POST /verify` — verifies any ZKPassport proof bundle. This is what the SDK calls in
  `verifierMode: "api"` and, as a fallback, in `"auto"`.
  Body: `{ proofs, originalQuery, queryResult, serviceConfig?, options?, oprfKeyId? }`, where
  `serviceConfig` is `{ domain?, scope?, validityPeriodInSeconds?, devMode? }` and `options` is
  `{ ignoreValidity? }`. Proofs are checked against `domain` and `scope`, so pass the values the
  request was created with.
  Returns `{ verified, uniqueIdentifier?, uniqueIdentifierType?, ignoredValidity? }`, or 400
  with `{ verified: false, error, queryResultErrors? }` when the proof fails. A 503 with
  `{ verified: false, error }` means the check could not run (for example the registry or an
  RPC was unreachable) and is not a verdict on the proof.
- `POST /verify-oprf-auth` (alias `POST /oprf/verify`) — verifies the 5-proof OPRF v1 auth
  bundle for the OPRF nodes. Body: `{ blinded_unique_identifier, proofs }`.
- `POST /oprf/v2/{identify,register,query,rotate}` - verifies the proof bundle of one OPRF v2
  step for the OPRF nodes. Add `?devmode=true` for dev mode. Body:
  `{ proofs, blinded_query?, I?, commitment? }`, where `blinded_query` is `"0x<x><y>"` (32 bytes
  each, as in v1), `I` is `["<x>", "<y>"]` and `commitment` is a field element (decimal or
  0x-prefixed hex). Each step takes the 3 base proofs plus:

  | route      | step               | node oracle call          | extra proofs                     | also needs                          |
  | ---------- | ------------------ | ------------------------- | -------------------------------- | ----------------------------------- |
  | `identify` | 1, `register` OPRF | `salted_identifier`       | `oprf_auth`                      | `blinded_query`                     |
  | `register` | 2, registration    | `registration_commitment` | `oprf_registration`              | `I`, `commitment` (x' to store)     |
  | `query`    | 3, `nullifier` OPRF | `preimage_proof`         | `oprf_auth`, `oprf_registration` | `blinded_query`, `I`, `commitment` (x' stored for `I`) |
  | `rotate`   | 4, rotation        | `secret_rotation`         | `facematch`, `oprf_registration` | `I`, `commitment` (y' to store)     |

  Every step checks the base chain from a currently valid certificate root to the passport
  commitment P, that every other proof opens the same P, and every proof against the circuit
  registry (each under its own version). `oprf_auth` must output `blinded_query`;
  `oprf_registration` must match `I` and `commitment` and be evaluated under the pinned
  registration key; `facematch` gets the v1 checks. Returns `{ verified: true }`, 400
  `{ verified: false, error }` when the bundle is rejected, or 503 when the check could not run.
- `GET /health` — liveness.

## Configuration

- `OPRF_REGISTRATION_PUBLIC_KEY` - public key of the OPRF registration key `k_reg`, as
  `<x>,<y>` (decimal or 0x-prefixed hex). Required for the `register`, `query` and `rotate`
  steps, which answer 500 without it. The registration circuit only checks the OPRF proof
  against the key it is given, so this pin is what stops a client from using a key of its own.
- `CIRCUITS_URL` - a base URL with the registry layout (`by-version/<version>/manifest.json`,
  `by-root/<root>/manifest.json`, `by-hash/<hash>.json`). Circuits served there take precedence;
  anything not listed (other circuits, other versions) comes from the public circuit registry. For
  OPRF proofs only: the SDK verifies the face match against the public registry.
- `CIRCUITS_DIR` - a packaged circuits directory (`manifest.json` and `circuits/<name>.json`, as
  `npm run package-circuits` in the circuits repo writes to `target/packaged`) the oracle serves
  itself under `/circuits` and uses as `CIRCUITS_URL` when that is not set. Default `./packaged`,
  which the image bakes in from the repo's `packaged/` directory. Lets the OPRF nodes be tested
  against circuits that are not released yet: package just those, e.g.
  `npx tsx src/ts/scripts/circuit-packager --only oprf_registration`.

## Docker image

The "Publish image" workflow is run by hand (Actions, pick the branch) and publishes
`ghcr.io/zkpassport/zkpassport-proof-verifier:<branch>` (and `:sha-<commit>`). To bake unreleased
circuits into an image, give it the URL of a tarball of the packaged circuits directory, which
tags the image `:<branch>-circuits` as well:

```bash
# in the circuits repo, after npm run package-circuits
tar -czf packaged.tar.gz -C target/packaged .
```

Locally, copy or extract the directory to `packaged/` and `docker build .`.

```bash
docker run -p 8080:8080 -e OPRF_REGISTRATION_PUBLIC_KEY="<x>,<y>" ghcr.io/zkpassport/zkpassport-proof-verifier:<tag>
```

## Usage

```bash
npm run dev        # Start development server with hot reload
npm run build      # Compile TypeScript to JavaScript
npm start          # Run compiled server (production)
npm test           # Run the test suite (needs network access to the circuit registry)
```
