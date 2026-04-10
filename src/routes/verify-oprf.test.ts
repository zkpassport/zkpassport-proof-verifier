import { describe, it, before, after } from "node:test"
import assert from "node:assert/strict"
import { buildApp } from "../app"
import type { FastifyInstance } from "fastify"

describe("POST /oprf/verify", () => {
  let app: FastifyInstance

  before(async () => {
    app = buildApp()
    await app.ready()
  })

  after(async () => {
    await app.close()
  })

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

  it("should return 400 when proof types are missing", async () => {
    const mockProof = {
      proof: "0x" + "aa".repeat(32),
      vkeyHash: "0x" + "bb".repeat(32),
      version: "0.16.0",
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
