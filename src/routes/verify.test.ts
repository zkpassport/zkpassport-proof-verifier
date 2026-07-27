import { describe, it, before, after } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { buildApp } from "../app"
import type { FastifyInstance } from "fastify"

// Real proof fixture from a mobile app test run (3 base + facematch + oprf_auth)
const fixture = JSON.parse(
  readFileSync(join(__dirname, "../test/fixtures/oprf-verify-request.json"), "utf8"),
)

// Query the fixture proofs were generated for
const facematchQuery = { facematch: { mode: "regular", passed: true } }

// oprf_auth proofs are rejected by /verify, so use the fixture without it
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
    ]
    for (const payload of payloads) {
      const res = await app.inject({ method: "POST", url: "/verify", payload })
      assert.equal(res.statusCode, 400)
      assert.equal(res.json().verified, false)
    }
  })

  it("should return 400 for bundles containing an oprf_auth proof", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/verify",
      payload: {
        proofs: fixture.proofs,
        originalQuery: facematchQuery,
        queryResult: facematchQuery,
        serviceConfig: { validityPeriodInSeconds: TEN_YEARS_IN_SECONDS, devMode: true },
      },
    })
    assert.equal(res.statusCode, 400)
    const body = res.json()
    assert.equal(body.verified, false)
    assert.ok(body.error.includes("/verify-oprf-auth"))
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
})
