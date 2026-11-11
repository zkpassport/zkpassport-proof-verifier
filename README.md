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
- `POST /verify-oprf-auth` (alias `POST /oprf/verify`) — verifies the 5-proof OPRF auth bundle
  for the OPRF nodes. Body: `{ blinded_unique_identifier, proofs }`.
- `POST /verify-passport-proof` - verifies the proof bundle of one OPRF v2 step for the OPRF
  nodes. Add `?devmode=true` for dev mode. Body:
  `{ mode, proofs, blinded_query?, I?, commitment? }`, where `blinded_query` is
  `"0x<x><y>"` (32 bytes each, as in v1), `I` is `["<x>", "<y>"]` and `commitment` is a field
  element (decimal or 0x-prefixed hex). Each mode takes the 3 base proofs plus:

  | mode       | step               | extra proofs                     | also needs                          |
  | ---------- | ------------------ | -------------------------------- | ----------------------------------- |
  | `identify` | 1, `register` OPRF | `oprf_auth`                      | `blinded_query`                     |
  | `register` | 2, registration    | `oprf_registration`              | `I`, `commitment` (x' to store)     |
  | `query`    | 3, `nullifier` OPRF | `oprf_auth`, `oprf_registration` | `blinded_query`, `I`, `commitment` (x' stored for `I`) |
  | `rotate`   | 4, rotation        | `facematch`, `oprf_registration` | `I`, `commitment` (y' to store)     |

  Every mode checks the base chain from a currently valid certificate root to the passport
  commitment P, that every other proof opens the same P, and every proof against the circuit
  registry (each under its own version). `oprf_auth` must output `blinded_query`;
  `oprf_registration` must match `I` and `commitment` and be evaluated under the pinned
  registration key; `facematch` gets the v1 checks. Returns `{ verified: true }`, 400
  `{ verified: false, error }` when the bundle is rejected, or 503 when the check could not run.
- `GET /health` — liveness.

## Configuration

- `OPRF_REGISTRATION_PUBLIC_KEY` - public key of the OPRF registration key `k_reg`, as
  `<x>,<y>` (decimal or 0x-prefixed hex). Required for the `register`, `query` and `rotate`
  modes, which answer 500 without it. The registration circuit only checks the OPRF proof
  against the key it is given, so this pin is what stops a client from using a key of its own.

## Usage

```bash
npm run dev        # Start development server with hot reload
npm run build      # Compile TypeScript to JavaScript
npm start          # Run compiled server (production)
npm test           # Run the test suite (needs network access to the circuit registry)
```
