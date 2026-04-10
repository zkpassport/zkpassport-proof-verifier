import { describe, it, before, after } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { buildApp } from "../app"
import type { FastifyInstance } from "fastify"

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
      url: "/oprf/verify",
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
      url: "/oprf/verify",
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
      url: "/oprf/verify",
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
      url: "/oprf/verify",
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
      url: "/oprf/verify",
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

  // --- Full verification ---
  // Note: This test requires bb.js version to match the circuit compiler version.
  // Skip with { skip: true } if bb.js is not yet updated.

  it("should return verified: true with valid proofs and matching blinded identifier", { skip: "Requires bb.js v4 to match circuit compiler version" }, async () => {
    const res = await app.inject({
      method: "POST",
      url: "/oprf/verify",
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
