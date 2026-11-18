import { describe, it, after } from "node:test"
import assert from "node:assert"
import type { createRegistryClient } from "@zkpassport/registry"
import type { ProofResult } from "@zkpassport/utils"
import { RegistryProofBackend } from "./proof-backend"

// Two circuit sources: the oracle's own (one circuit, one version) and the public registry
const LOCAL = { version: "0.22.0", root: "0x01", circuits: { oprf_registration: { hash: "0x0a" } } }
const PUBLIC = {
  "0.22.0": { version: "0.22.0", root: "0x02", circuits: { sig_check_dsc: { hash: "0x0b" } } },
  "0.19.0": { version: "0.19.0", root: "0x03", circuits: { oprf_auth: { hash: "0x0c" } } },
}

function fakeClients() {
  const fetched: string[] = []
  const createClient = ((_chain: unknown, overrides: Record<string, unknown>) => {
    const isLocal = "circuitManifestUrlGenerator" in overrides
    return {
      async getCircuitManifest(_: unknown, { version }: { version: string }) {
        const manifest = isLocal
          ? LOCAL.version === version && LOCAL
          : PUBLIC[version as keyof typeof PUBLIC]
        if (!manifest) throw new Error(`no manifest ${version}`)
        return manifest
      },
      async getPackagedCircuit(name: string) {
        fetched.push(`${isLocal ? "local" : "registry"}:${name}`)
        return { vkey: Buffer.alloc(8).toString("base64") }
      },
    }
  }) as unknown as typeof createRegistryClient
  return { createClient, fetched }
}

describe("RegistryProofBackend circuit sources", () => {
  const { createClient, fetched } = fakeClients()
  const backend = new RegistryProofBackend({
    devMode: true,
    circuitsUrl: "http://127.0.0.1/circuits",
    createClient,
  })
  // A proof this short never verifies, so the result only says whether a vkey was found
  const proof = (name: string, version: string) =>
    ({ name, version, proof: "00".repeat(32) }) as ProofResult

  after(() => backend.close())

  it("takes a circuit the local source lists from there", async () => {
    assert.equal(await backend.verifyProof(proof("oprf_registration", "0.22.0"), 6), false)
    assert.deepEqual(fetched, ["local:oprf_registration"])
  })

  it("falls back to the registry for a circuit the local source does not list", async () => {
    await backend.verifyProof(proof("sig_check_dsc", "0.22.0"), 3)
    assert.deepEqual(fetched.at(-1), "registry:sig_check_dsc")
  })

  it("falls back to the registry for a version the local source does not have", async () => {
    await backend.verifyProof(proof("oprf_auth", "0.19.0"), 3)
    assert.deepEqual(fetched.at(-1), "registry:oprf_auth")
  })

  it("rejects a circuit neither source lists without fetching anything", async () => {
    const before = fetched.length
    assert.equal(await backend.verifyProof(proof("facematch_ios", "0.22.0"), 3), false)
    assert.equal(fetched.length, before)
  })
})

describe("RegistryProofBackend reused across requests", () => {
  const proof = (name: string, version: string) =>
    ({ name, version, proof: "00".repeat(32 * 4) }) as ProofResult

  function fakeVerifiers(results: Array<boolean | Error>) {
    const state = { loaded: 0, destroyed: 0 }
    const loadVerifier = async () => {
      state.loaded++
      return {
        async verifyProof() {
          const next = results.shift() ?? true
          if (next instanceof Error) throw next
          return next
        },
        async destroy() {
          state.destroyed++
        },
      }
    }
    return { loadVerifier, state }
  }

  it("loads bb once and fetches each circuit once", async () => {
    const { createClient, fetched } = fakeClients()
    const { loadVerifier, state } = fakeVerifiers([])
    const backend = new RegistryProofBackend({ devMode: true, createClient, loadVerifier })
    for (let i = 0; i < 3; i++) {
      assert.equal(await backend.verifyProof(proof("sig_check_dsc", "0.22.0"), 3), true)
    }
    assert.deepEqual(fetched, ["registry:sig_check_dsc"])
    assert.equal(state.loaded, 1)
    await backend.close()
    assert.equal(state.destroyed, 1)
  })

  it("fetches a circuit again after a failed fetch", async () => {
    const { createClient } = fakeClients()
    let down = true
    const flaky = ((chain: any, overrides: any) => {
      const client = (createClient as any)(chain, overrides)
      return {
        ...client,
        async getCircuitManifest(...args: any[]) {
          if (down) throw new Error("registry down")
          return client.getCircuitManifest(...args)
        },
      }
    }) as unknown as typeof createRegistryClient
    const backend = new RegistryProofBackend({
      devMode: true,
      createClient: flaky,
      loadVerifier: fakeVerifiers([]).loadVerifier,
    })
    await assert.rejects(backend.verifyProof(proof("sig_check_dsc", "0.22.0"), 3), {
      name: "ServiceUnavailableError",
    })
    down = false
    assert.equal(await backend.verifyProof(proof("sig_check_dsc", "0.22.0"), 3), true)
    await backend.close()
  })

  it("replaces a bb instance that fails mid-call and retries the proof on the new one", async () => {
    const { createClient } = fakeClients()
    const { loadVerifier, state } = fakeVerifiers([new Error("bb exited"), true])
    const backend = new RegistryProofBackend({ devMode: true, createClient, loadVerifier })
    assert.equal(await backend.verifyProof(proof("sig_check_dsc", "0.22.0"), 3), true)
    assert.equal(state.loaded, 2)
    assert.equal(state.destroyed, 1)
    await backend.close()
  })

  it("rejects a proof bb throws on twice", async () => {
    const { createClient } = fakeClients()
    const { loadVerifier } = fakeVerifiers([new Error("bad proof"), new Error("bad proof")])
    const backend = new RegistryProofBackend({ devMode: true, createClient, loadVerifier })
    assert.equal(await backend.verifyProof(proof("sig_check_dsc", "0.22.0"), 3), false)
    await backend.close()
  })
})
