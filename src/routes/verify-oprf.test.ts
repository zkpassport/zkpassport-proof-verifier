import { describe, it, before, after } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { buildApp } from "../app"
import type { FastifyInstance } from "fastify"
import {
  getProofData,
  getNumberOfPublicInputs,
  getCommitmentInFromDisclosureProof,
} from "@zkpassport/utils"

// Load real proof fixture generated from a zkpassport mobile app test run.
// Contains 5 subproofs (3 base + facematch + oprf_auth) with a matching blinded_unique_identifier.
const fixture = JSON.parse(
  readFileSync(join(__dirname, "../test/fixtures/oprf-verify-request.json"), "utf8"),
)

describe("POST /oprf/verify", () => {
  let app: FastifyInstance

  before(async () => {
    app = buildApp()
    await app.ready()
  })

  after(async () => {
    await app.close()
  })

  // --- Input validation ---

  it("should return 400 when body is missing", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify-oprf-auth",
      payload: {},
    })
    assert.equal(res.statusCode, 400)
    const body = res.json()
    assert.equal(body.verified, false)
    assert.match(body.error, /Missing required fields/)
  })

  it("should return 400 when proofs is not an array", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify-oprf-auth",
      payload: {
        blinded_unique_identifier: "0x1234",
        proofs: "not-an-array",
      },
    })
    assert.equal(res.statusCode, 400)
    const body = res.json()
    assert.equal(body.verified, false)
  })

  it("should return 400 when proof count is wrong", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify-oprf-auth",
      payload: {
        blinded_unique_identifier: "0x1234",
        proofs: [{ proof: "0xaa", name: "test" }],
      },
    })
    assert.equal(res.statusCode, 400)
    const body = res.json()
    assert.equal(body.verified, false)
    assert.match(body.error, /Expected 5 subproofs/)
  })

  it("should return 400 when required proof types are missing", async () => {
    const mockProof = {
      proof: "0x" + "aa".repeat(32),
      vkeyHash: "0x" + "bb".repeat(32),
      version: "0.17.0",
      name: "test_circuit",
    }

    const res = await app.inject({
      method: "POST",
      url: "/verify-oprf-auth",
      payload: {
        blinded_unique_identifier: "0x" + "cc".repeat(32),
        proofs: Array(5).fill(mockProof),
      },
    })

    assert.equal(res.statusCode, 400)
    const body = res.json()
    assert.equal(body.verified, false)
    assert.match(body.error, /Missing required/)
  })

  // --- Blinded identifier validation ---

  it("should return 400 when blinded_unique_identifier does not match proof output", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify-oprf-auth",
      payload: {
        blinded_unique_identifier: "0x" + "00".repeat(64),
        proofs: fixture.proofs,
      },
    })

    assert.equal(res.statusCode, 400)
    const body = res.json()
    assert.equal(body.verified, false)
    assert.match(body.error, /blinded_unique_identifier does not match/)
  })

  const WORD = (hex: string) => hex.padStart(64, "0")
  const COMM_A = "a".repeat(64)
  const COMM_B = "b".repeat(64)
  const BLINDED_X = "1".repeat(64)
  const BLINDED_Y = "2".repeat(64)

  // Raw proof hex (no 0x prefix, matching the request format): public input words then a dummy body.
  const makeProof = (publicInputs: string[], bodyWords = 40) =>
    publicInputs.map(WORD).join("") + "00".repeat(32 * bodyWords)

  // blinded_unique_identifier exactly as the route derives it from oprf_auth public inputs 1 and 2.
  const blindedIdFor = (x: string, y: string) =>
    "0x" +
    BigInt("0x" + x).toString(16).padStart(64, "0") +
    BigInt("0x" + y).toString(16).padStart(64, "0")

  const buildPayload = (oprfAuthCommIn: string) => ({
    blinded_unique_identifier: blindedIdFor(BLINDED_X, BLINDED_Y),
    proofs: [
      { name: "sig_check_dsc", version: "0.17.0", proof: makeProof(Array(30).fill(WORD("c1"))) },
      { name: "sig_check_id_data", version: "0.17.0", proof: makeProof(Array(30).fill(WORD("c2"))) },
      { name: "data_check_integrity", version: "0.17.0", proof: makeProof(Array(30).fill(WORD("c3"))) },
      { name: "facematch_ios", version: "0.17.0", proof: makeProof([COMM_A, ...Array(7).fill(WORD("f0"))]) },
      { name: "oprf_auth", version: "0.17.0", proof: makeProof([oprfAuthCommIn, BLINDED_X, BLINDED_Y]) },
    ],
  })

  it("should return 400 when oprf_auth comm_in does not match facematch comm_in", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify-oprf-auth",
      payload: buildPayload(COMM_B),
    })

    assert.equal(res.statusCode, 400)
    const body = res.json()
    assert.equal(body.verified, false)
    assert.match(body.error, /oprf_auth comm_in does not match facematch comm_in/)
  })

  it("extracts equal comm_in for an honest oprf_auth/facematch pair, unequal for a tampered one", () => {
    const facematchProof = makeProof([COMM_A, ...Array(7).fill(WORD("f0"))])
    const honestOprfAuth = makeProof([COMM_A, BLINDED_X, BLINDED_Y])
    const tamperedOprfAuth = makeProof([COMM_B, BLINDED_X, BLINDED_Y])

    const facematchCommIn = getCommitmentInFromDisclosureProof(
      getProofData(facematchProof, getNumberOfPublicInputs("facematch_ios")),
    )
    const honestCommIn = BigInt(getProofData(honestOprfAuth, 3).publicInputs[0])
    const tamperedCommIn = BigInt(getProofData(tamperedOprfAuth, 3).publicInputs[0])

    // Honest: oprf_auth is bound to the same identity that was face-matched.
    assert.equal(honestCommIn, facematchCommIn)
    // Attack: oprf_auth commits to a different identity than the facematch proof.
    assert.notEqual(tamperedCommIn, facematchCommIn)
  })


  it("should return verified: true with valid proofs and matching blinded identifier", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify-oprf-auth?devmode=true",
      payload: {
        blinded_unique_identifier: fixture.blinded_unique_identifier,
        proofs: fixture.proofs,
      },
    })

    const body = res.json()
    assert.equal(body.verified, true, `Expected verified: true, got error: ${body.error}`)
    assert.equal(res.statusCode, 200)
  })
})

describe("GET /health", () => {
  let app: FastifyInstance

  before(async () => {
    app = buildApp()
    await app.ready()
  })

  after(async () => {
    await app.close()
  })

  it("should return ok", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/health",
    })
    assert.equal(res.statusCode, 200)
    assert.deepEqual(res.json(), { status: "ok" })
  })
})
