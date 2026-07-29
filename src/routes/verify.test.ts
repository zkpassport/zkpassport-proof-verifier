import { describe, it, before, after, mock } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { buildApp } from "../app"
import type { FastifyInstance } from "fastify"
import {
  getProofData,
  getNumberOfPublicInputs,
  getCurrentDateFromOuterProof,
  getCurrentDateFromDisclosureProof,
  NullifierType,
} from "@zkpassport/utils"

// Real proof fixture from a mobile app test run (3 base + facematch + oprf_auth)
const fixture = JSON.parse(
  readFileSync(join(__dirname, "../test/fixtures/oprf-verify-request.json"), "utf8"),
)

// Query the fixture proofs were generated for
const facematchQuery = { facematch: { mode: "regular", passed: true } }

// oprf_auth proofs need a blinded identifier too, so those cases are grouped further down
const proofs = fixture.proofs.filter((p: { name?: string }) => !p.name?.startsWith("oprf_auth"))

// The fixture ages past the SDK's default 7-day validity window
const TEN_YEARS_IN_SECONDS = 10 * 365 * 24 * 60 * 60

// Force bb.js's WASM backend: on macOS its native backend leaks an uncaught
// socket-poll rejection after verify(), which node:test fails the file for
Object.defineProperty(process, "arch", { value: "unsupported" })

describe("POST /verify", () => {
  let app: FastifyInstance

  before(async () => {
    app = buildApp()
    await app.ready()
  })

  after(async () => {
    await app.close()
  })

  it("should return 400 when required fields are missing", async () => {
    const payloads = [
      {},
      { proofs: "not-an-array", originalQuery: facematchQuery, queryResult: facematchQuery },
      { proofs, queryResult: facematchQuery },
      { proofs, originalQuery: facematchQuery },
      {
        proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: "not-an-object",
      },
      {
        proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        options: "not-an-object",
      },
    ]
    for (const payload of payloads) {
      const res = await app.inject({ method: "POST", url: "/verify", payload })
      assert.equal(res.statusCode, 400)
      assert.equal(res.json().verified, false)
    }
  })


  it("should return 400 when proof verification throws", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        proofs: [{ proof: "0x" + "aa".repeat(64), name: "bogus", version: "0.19.0" }],
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
      },
    })
    assert.equal(res.statusCode, 400)
    assert.equal(res.json().verified, false)
  })

  it("should return verified: true for valid proofs with a matching query", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: { validityPeriodInSeconds: TEN_YEARS_IN_SECONDS, devMode: true },
      },
    })

    const body = res.json()
    assert.equal(body.verified, true, `Expected verified: true, got error: ${body.error}`)
    assert.equal(res.statusCode, 200)
  })

  it("should return verified: false for an aged proof without ignoreValidity", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: { devMode: true },
      },
    })

    assert.equal(res.statusCode, 400)
    assert.equal(res.json().verified, false)
  })

  it("should return verified: true for the same aged proof with options.ignoreValidity", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: { devMode: true },
        options: { ignoreValidity: true },
      },
    })

    const body = res.json()
    assert.equal(body.verified, true, `Expected verified: true, got error: ${body.error}`)
    assert.equal(res.statusCode, 200)
  })

  it("should return verified: false when the query does not match the proofs", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        proofs,
        originalQuery: { facematch: { mode: "strict", passed: true } },
        queryResult: { facematch: { mode: "strict", passed: true } },
        serviceConfig: { validityPeriodInSeconds: TEN_YEARS_IN_SECONDS, devMode: true },
      },
    })

    assert.equal(res.statusCode, 400)
    assert.equal(res.json().verified, false)
  })

  // --- OPRF auth bundles ---

  it("should return 400 for an oprf_auth bundle without blinded_unique_identifier", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        proofs: fixture.proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: { devMode: true },
        options: { ignoreValidity: true },
      },
    })

    assert.equal(res.statusCode, 400)
    assert.match(res.json().error, /require blinded_unique_identifier/)
  })

  it("should return 400 for an oprf_auth bundle with a mismatched blinded identifier", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        blinded_unique_identifier: "0x" + "00".repeat(64),
        proofs: fixture.proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: { devMode: true },
        options: { ignoreValidity: true },
      },
    })

    assert.equal(res.statusCode, 400)
    assert.match(res.json().error, /blinded_unique_identifier does not match/)
  })

  it("should verify an oprf_auth bundle given the matching blinded identifier", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        blinded_unique_identifier: fixture.blinded_unique_identifier,
        proofs: fixture.proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: { devMode: true },
        options: { ignoreValidity: true },
      },
    })

    const body = res.json()
    assert.equal(body.verified, true, `Expected verified: true, got error: ${body.error}`)
    assert.equal(res.statusCode, 200)
  })


})

// Real mainnet proofs from mobile app runs, one per proof mode, at circuit version 0.20.0.
// originalQuery is reconstructed from the captured result, the app's own query wasn't saved.
const loadModeFixture = (name: string) =>
  JSON.parse(readFileSync(join(__dirname, `../test/fixtures/${name}`), "utf8"))

const EXPECTED_UNIQUE_IDENTIFIER =
  "9993331391667981369032344615261176787245866814375674411672468922215950818795"

// This one asked for a salted identifier, so it is the only fixture that makes the SDK check
// the OPRF key. It also used strict facematch and included a bind proof.
const SALTED_UNIQUE_IDENTIFIER =
  "11967442281966260380238871272653119004869513454295625115950587293921126852242"

// When the proofs were made, so tests can set the clock to that moment
const bundleDate = (proofs: { name: string; proof: string }[]) => {
  const outer = proofs.find((p) => p.name.startsWith("outer"))
  if (outer) {
    return getCurrentDateFromOuterProof(
      getProofData(outer.proof, getNumberOfPublicInputs(outer.name)),
    )
  }
  const disclosure = proofs.find(
    (p) =>
      !p.name.startsWith("sig_check_") &&
      !p.name.startsWith("data_check_") &&
      !p.name.startsWith("oprf_auth"),
  )!
  return getCurrentDateFromDisclosureProof(
    getProofData(disclosure.proof, getNumberOfPublicInputs(disclosure.name)),
  )
}

describe("POST /verify — proof modes", () => {
  let app: FastifyInstance

  before(async () => {
    app = buildApp()
    await app.ready()
  })

  after(async () => {
    await app.close()
  })

  // Setting the clock to when the proofs were made stops these failing as the fixtures age
  for (const [mode, file, expectedId, expectedIdType] of [
    ["fast", "verify-fast-request.json", EXPECTED_UNIQUE_IDENTIFIER, NullifierType.NON_SALTED],
    [
      "compressed",
      "verify-compressed-request.json",
      EXPECTED_UNIQUE_IDENTIFIER,
      NullifierType.NON_SALTED,
    ],
    [
      "fast, salted OPRF nullifier",
      "verify-fast-oprf-request.json",
      SALTED_UNIQUE_IDENTIFIER,
      NullifierType.SALTED,
    ],
  ] as const) {
    it(`should verify a ${mode} bundle`, async () => {
      const body = loadModeFixture(file)
      mock.timers.enable({ apis: ["Date"], now: bundleDate(body.proofs) })
      try {
        const res = await app.inject({ method: "POST", url: "/verify", payload: body })
        const json = res.json()
        assert.equal(json.verified, true, `Expected verified: true, got error: ${json.error}`)
        assert.equal(res.statusCode, 200)
        assert.equal(json.uniqueIdentifier, expectedId)
        assert.equal(json.uniqueIdentifierType, expectedIdType)
      } finally {
        mock.timers.reset()
      }
    })
  }

  // This mode is verified by a call to the verifier contract, which needs network access and
  // the domain and scope from the fixture. It uses the contract's own clock, so it will start
  // failing 7 days after the proofs were made until the SDK passes ignoreValidity through.
  it("should verify a compressed-evm bundle against the on-chain verifier", async () => {
    const body = loadModeFixture("verify-compressed-evm-request.json")
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: { ...body, options: { ignoreValidity: true } },
    })
    const json = res.json()
    assert.equal(json.verified, true, `Expected verified: true, got error: ${json.error}`)
    assert.equal(res.statusCode, 200)
    assert.equal(json.uniqueIdentifier, EXPECTED_UNIQUE_IDENTIFIER)
  })
})
