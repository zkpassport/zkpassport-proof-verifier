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
  with `{ verified: false, error, queryResultErrors? }`.
- `POST /verify-oprf-auth` (alias `POST /oprf/verify`) — verifies the 5-proof OPRF auth bundle
  for the OPRF nodes. Body: `{ blinded_unique_identifier, proofs }`.
- `GET /health` — liveness.

## Usage

```bash
npm run dev        # Start development server with hot reload
npm run build      # Compile TypeScript to JavaScript
npm start          # Run compiled server (production)
npm test           # Run the test suite (needs network access to the circuit registry)
```
