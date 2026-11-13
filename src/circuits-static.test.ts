import { describe, it, before, after } from "node:test"
import assert from "node:assert"
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import type { FastifyInstance } from "fastify"
import { buildApp } from "./app"
import { hasPackagedCircuits } from "./circuits-static"

describe("GET /circuits (packaged circuits served by the oracle)", () => {
  let dir: string
  let app: FastifyInstance
  const manifest = {
    version: "9.9.9",
    root: "0x00ab",
    circuits: { oprf_registration: { hash: "0x00ff" } },
  }
  const circuit = { name: "oprf_registration", vkey: "AAAA", hash: "0x00ff" }

  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "packaged-"))
    await mkdir(path.join(dir, "circuits"))
    await writeFile(path.join(dir, "manifest.json"), JSON.stringify(manifest))
    await writeFile(path.join(dir, "circuits", "oprf_registration.json"), JSON.stringify(circuit))
    app = buildApp({ circuitsDir: dir })
    await app.ready()
  })

  after(async () => {
    await app.close()
    await rm(dir, { recursive: true, force: true })
  })

  it("detects a packaged circuits directory", async () => {
    assert.equal(await hasPackagedCircuits(dir), true)
    assert.equal(await hasPackagedCircuits(path.join(dir, "circuits")), false)
  })

  it("serves the manifest by its version and root only", async () => {
    const byVersion = await app.inject({ url: "/circuits/by-version/9.9.9/manifest.json" })
    assert.equal(byVersion.statusCode, 200)
    assert.deepEqual(byVersion.json(), manifest)
    assert.equal((await app.inject({ url: "/circuits/by-version/0.1.0/manifest.json" })).statusCode, 404)
    assert.equal((await app.inject({ url: "/circuits/by-root/ab/manifest.json" })).statusCode, 200)
    assert.equal((await app.inject({ url: "/circuits/by-root/0xcd/manifest.json" })).statusCode, 404)
  })

  it("serves a packaged circuit by its vkey hash", async () => {
    const res = await app.inject({ url: "/circuits/by-hash/ff.json" })
    assert.equal(res.statusCode, 200)
    assert.deepEqual(res.json(), circuit)
    assert.equal((await app.inject({ url: "/circuits/by-hash/0x00ff.json" })).statusCode, 200)
    assert.equal((await app.inject({ url: "/circuits/by-hash/ee.json" })).statusCode, 404)
    assert.equal((await app.inject({ url: "/circuits/by-hash/manifest.json" })).statusCode, 404)
  })

  it("serves nothing without a directory", async () => {
    const plain = buildApp()
    await plain.ready()
    assert.equal((await plain.inject({ url: "/circuits/by-version/9.9.9/manifest.json" })).statusCode, 404)
    await plain.close()
  })
})
