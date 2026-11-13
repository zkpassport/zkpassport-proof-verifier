import { describe, it, before, after, beforeEach, mock } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import type { FastifyInstance } from "fastify"
import type { ProofResult } from "@zkpassport/utils"
import {
  getCurrentDateFromDisclosureProof,
  getNumberOfPublicInputs,
  getProofData,
} from "@zkpassport/utils"
import { buildApp } from "../app"
import { getRegistrationOprfPublicKey, type Point } from "../oprf-v2/config"
import { ServiceUnavailableError, type ProofBackend } from "../oprf-v2/proof-backend"
import type { FacematchVerifier } from "../oprf-v2/verify-bundle"

// --- Synthetic bundles: real public input layouts, fake cryptography ---

const VERSION = "0.22.0"
const ROOT = 7n
const P = 1000n // passport commitment, comm_out of the integrity proof
const B: Point = { x: 21n, y: 22n } // blinded query
const I: Point = { x: 31n, y: 32n } // registration id
const K_REG: Point = { x: 41n, y: 42n } // pinned registration key
const K_C: Point = { x: 51n, y: 52n } // nullifier key
const X_COMMITMENT = 61n

const NAMES = {
  dsc: "sig_check_dsc_tbs_700_rsa_pkcs_2048_sha256",
  idData: "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256",
  integrity: "data_check_integrity_sa_sha256_dg_sha256",
  facematch: "facematch_ios",
}

function proofHex(publicInputs: bigint[]): string {
  return [...publicInputs, ...new Array(10).fill(0n)]
    .map((v) => v.toString(16).padStart(64, "0"))
    .join("")
}

const proof = (name: string, publicInputs: bigint[], version = VERSION): ProofResult =>
  ({ name, version, proof: proofHex(publicInputs) }) as ProofResult

const base = (p = P) => [
  proof(NAMES.dsc, [ROOT, 11n]),
  proof(NAMES.idData, [11n, 12n]),
  proof(NAMES.integrity, [12n, p]),
]
const oprfAuth = (b = B, p = P) => proof("oprf_auth", [p, b.x, b.y])
const oprfRegistration = ({ i = I, pk = K_REG, c = X_COMMITMENT, p = P } = {}) =>
  proof("oprf_registration", [p, i.x, i.y, pk.x, pk.y, c])
const facematch = (p = P) => proof(NAMES.facematch, [p, 0n, 0n, 0n, 0n, 0n, 0n, 0n])

const hexPoint = (p: Point) =>
  `0x${p.x.toString(16).padStart(64, "0")}${p.y.toString(16).padStart(64, "0")}`
const wireI = (p: Point) => [p.x.toString(), p.y.toString()]

const requests = {
  identify: () => ({ mode: "identify", proofs: [...base(), oprfAuth()], blinded_query: hexPoint(B) }),
  register: () => ({
    mode: "register",
    proofs: [...base(), oprfRegistration()],
    I: wireI(I),
    commitment: X_COMMITMENT.toString(),
  }),
  query: () => ({
    mode: "query",
    proofs: [...base(), oprfAuth(), oprfRegistration()],
    blinded_query: hexPoint(B),
    I: wireI(I),
    commitment: X_COMMITMENT.toString(),
  }),
  rotate: () => ({
    mode: "rotate",
    proofs: [...base(), facematch(), oprfRegistration()],
    I: wireI(I),
    commitment: X_COMMITMENT.toString(),
  }),
}

class FakeBackend implements ProofBackend {
  rootValid = true
  unavailable = false
  rejectProof?: string
  verified: string[] = []
  closed = false

  async isCertificateRootValid(root: bigint) {
    if (this.unavailable) throw new ServiceUnavailableError("registry down")
    return this.rootValid && root === ROOT
  }

  async verifyProof(p: ProofResult, publicInputCount: number) {
    this.verified.push(`${p.name}/${publicInputCount}`)
    return p.name !== this.rejectProof
  }

  async close() {
    this.closed = true
  }
}

describe("POST /oprf/v2/<step>", () => {
  let app: FastifyInstance
  let backend: FakeBackend
  let facematchCalls: ProofResult[][]
  let facematchResult: { verified: boolean; error?: string }
  // Same routes, but the operator did not pin k_reg
  let appWithoutKey: FastifyInstance

  const verifyFacematch: FacematchVerifier = async (proofs) => {
    facematchCalls.push(proofs)
    return facematchResult
  }

  type Payload = Record<string, unknown>

  // The step is the route; the request builders above carry it as `mode`
  const send = async ({ mode, ...payload }: Payload, target = app) => {
    const res = await target.inject({ method: "POST", url: `/oprf/v2/${mode}`, payload })
    return { status: res.statusCode, body: res.json() }
  }

  const expectRejected = async (payload: Payload, error: RegExp, status = 400, target = app) => {
    const res = await send(payload, target)
    assert.equal(res.status, status, JSON.stringify(res.body))
    assert.equal(res.body.verified, false)
    assert.match(res.body.error, error)
  }

  before(async () => {
    const createBackend = () => backend
    app = buildApp({
      oprf: { createBackend, verifyFacematch, registrationPublicKey: K_REG },
    })
    appWithoutKey = buildApp({
      oprf: { createBackend, verifyFacematch, registrationPublicKey: undefined },
    })
    await Promise.all([app.ready(), appWithoutKey.ready()])
  })

  after(async () => {
    await Promise.all([app.close(), appWithoutKey.close()])
  })

  beforeEach(() => {
    backend = new FakeBackend()
    facematchCalls = []
    facematchResult = { verified: true }
  })

  describe("valid bundles", () => {
    it("identify: verifies 3 base + oprf_auth", async () => {
      const res = await send(requests.identify())
      assert.equal(res.status, 200, JSON.stringify(res.body))
      assert.deepEqual(res.body, { verified: true })
      assert.deepEqual(backend.verified, [
        `${NAMES.dsc}/2`,
        `${NAMES.idData}/2`,
        `${NAMES.integrity}/2`,
        "oprf_auth/3",
      ])
      assert.equal(backend.closed, true)
    })

    it("register: verifies 3 base + oprf_registration", async () => {
      const res = await send(requests.register())
      assert.equal(res.status, 200, JSON.stringify(res.body))
      assert.ok(backend.verified.includes("oprf_registration/6"))
      assert.equal(backend.verified.length, 4)
    })

    it("query: verifies 3 base + oprf_auth + oprf_registration", async () => {
      const res = await send(requests.query())
      assert.equal(res.status, 200, JSON.stringify(res.body))
      assert.equal(backend.verified.length, 5)
    })

    it("rotate: the SDK verifies base + facematch, the oracle verifies oprf_registration", async () => {
      const res = await send(requests.rotate())
      assert.equal(res.status, 200, JSON.stringify(res.body))
      assert.equal(facematchCalls.length, 1)
      assert.deepEqual(
        facematchCalls[0].map((p) => p.name),
        [NAMES.dsc, NAMES.idData, NAMES.integrity, NAMES.facematch],
      )
      assert.deepEqual(backend.verified, ["oprf_registration/6"])
    })

    it("accepts proofs in any order and hex-encoded field elements", async () => {
      const req = requests.query()
      req.proofs.reverse()
      const res = await send({ ...req, I: [`0x${I.x.toString(16)}`, `0x${I.y.toString(16)}`] })
      assert.equal(res.status, 200, JSON.stringify(res.body))
    })

    it("identify does not need the registration key", async () => {
      assert.equal((await send(requests.identify(), appWithoutKey)).status, 200)
    })
  })

  describe("request validation", () => {
    it("has no route for an unknown step", async () => {
      assert.equal((await send({ ...requests.identify(), mode: "nullifier" })).status, 404)
    })

    it("rejects a malformed blinded_query", async () => {
      await expectRejected({ ...requests.identify(), blinded_query: "0x1234" }, /blinded_query/)
    })

    it("rejects an I outside the field", async () => {
      const tooBig =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
      await expectRejected({ ...requests.register(), I: [tooBig, "1"] }, /field element/)
    })

    it("rejects a non-numeric commitment", async () => {
      await expectRejected({ ...requests.register(), commitment: "1e5" }, /commitment/)
    })

    it("identify requires blinded_query", async () => {
      const { blinded_query: _, ...req } = requests.identify()
      await expectRejected(req, /requires blinded_query/)
    })

    it("register requires I and commitment", async () => {
      const { commitment: _, ...req } = requests.register()
      await expectRejected(req, /requires I and commitment/)
    })

    it("fails closed with 500 when the registration key is not configured", async () => {
      await expectRejected(requests.register(), /OPRF_REGISTRATION_PUBLIC_KEY/, 500, appWithoutKey)
    })
  })

  describe("bundle composition", () => {
    it("rejects a missing proof", async () => {
      await expectRejected({ ...requests.query(), proofs: [...base(), oprfAuth()] }, /Expected 5 proofs/)
    })

    it("rejects a proof that does not belong to the mode", async () => {
      // identify with a registration proof instead of oprf_auth
      await expectRejected(
        { ...requests.identify(), proofs: [...base(), oprfRegistration()] },
        /Unexpected proof for mode identify: oprf_registration/,
      )
    })

    it("rejects a duplicate proof", async () => {
      const proofs = [...base(), oprfAuth()]
      proofs[1] = base()[0]
      await expectRejected({ ...requests.identify(), proofs }, /Duplicate sig_check_dsc/)
    })

    it("rejects an EVM face match", async () => {
      const proofs = [...base(), { ...facematch(), name: "facematch_ios_evm" }, oprfRegistration()]
      await expectRejected({ ...requests.rotate(), proofs }, /Unexpected proof.*facematch_ios_evm/)
    })

    it("rejects a proof without a version", async () => {
      const proofs = [...base(), { ...oprfAuth(), version: undefined }]
      await expectRejected({ ...requests.identify(), proofs }, /missing its proof or version/)
    })

    it("rejects malformed proof bytes", async () => {
      const proofs = [...base(), { ...oprfAuth(), proof: "zz" }]
      await expectRejected({ ...requests.identify(), proofs }, /Malformed proof/)
    })
  })

  describe("base chain", () => {
    it("rejects a broken DSC -> ID data link", async () => {
      const proofs = [...base(), oprfAuth()]
      proofs[1] = proof(NAMES.idData, [99n, 12n])
      await expectRejected({ ...requests.identify(), proofs }, /certificate signature and ID signature/)
    })

    it("rejects a broken ID data -> integrity link", async () => {
      const proofs = [...base(), oprfAuth()]
      proofs[2] = proof(NAMES.integrity, [99n, P])
      await expectRejected({ ...requests.identify(), proofs }, /ID signature and the data signed/)
    })

    it("rejects an unknown certificate root", async () => {
      backend.rootValid = false
      await expectRejected(requests.identify(), /unrecognized root certificate/)
      assert.deepEqual(backend.verified, [])
    })
  })

  describe("oprf_auth bindings", () => {
    it("rejects a blinded query other than the session's", async () => {
      await expectRejected({ ...requests.identify(), blinded_query: hexPoint({ x: 1n, y: 2n }) }, /blinded_query does not match/)
    })

    it("rejects an oprf_auth proof for another passport", async () => {
      const proofs = [...base(), oprfAuth(B, 2000n)]
      await expectRejected({ ...requests.identify(), proofs }, /oprf_auth comm_in/)
    })

    it("query: rejects an oprf_auth for another passport than the registration proof", async () => {
      const req = requests.query()
      req.proofs[3] = oprfAuth(B, 2000n)
      await expectRejected(req, /oprf_auth comm_in/)
    })
  })

  describe("oprf_registration bindings", () => {
    it("rejects an I other than the proof's", async () => {
      await expectRejected({ ...requests.register(), I: wireI({ x: 1n, y: 2n }) }, /I does not match/)
    })

    it("rejects a proof evaluated under another key than k_reg", async () => {
      const proofs = [...base(), oprfRegistration({ pk: K_C })]
      await expectRejected({ ...requests.register(), proofs }, /not evaluated under the registration key/)
    })

    it("rejects a commitment other than the proof's", async () => {
      await expectRejected({ ...requests.register(), commitment: "62" }, /commitment does not match/)
    })

    it("query: rejects a registration proof for a superseded commitment", async () => {
      // The node passes the commitment it has stored now; the cached proof is for the old one
      await expectRejected({ ...requests.query(), commitment: "999" }, /commitment does not match/)
    })

    it("rejects a registration proof for another passport", async () => {
      const proofs = [...base(), oprfRegistration({ p: 2000n })]
      await expectRejected({ ...requests.register(), proofs }, /oprf_registration comm_in/)
    })
  })

  describe("rotate", () => {
    it("rejects a face match for another passport", async () => {
      const req = requests.rotate()
      req.proofs[3] = facematch(2000n)
      await expectRejected(req, /facematch comm_in/)
      assert.equal(facematchCalls.length, 0)
    })

    it("rejects when the face match checks fail", async () => {
      facematchResult = { verified: false, error: "Invalid facematch mode" }
      await expectRejected(requests.rotate(), /Face match verification failed: Invalid facematch mode/)
      assert.deepEqual(backend.verified, [])
    })
  })

  describe("cryptographic verification", () => {
    it("rejects when a proof does not verify", async () => {
      backend.rejectProof = "oprf_registration"
      await expectRejected(requests.query(), /Proof verification failed: oprf_registration@0.22.0/)
    })

    it("returns 503 when the registry is unreachable, so the node retries", async () => {
      backend.unavailable = true
      await expectRejected(requests.identify(), /registry down/, 503)
      assert.equal(backend.closed, true)
    })
  })
})

describe("OPRF_REGISTRATION_PUBLIC_KEY", () => {
  it("parses decimal and hex coordinates", () => {
    assert.deepEqual(getRegistrationOprfPublicKey({ OPRF_REGISTRATION_PUBLIC_KEY: "41, 0x2a" }), {
      x: 41n,
      y: 42n,
    })
  })

  it("is optional", () => {
    assert.equal(getRegistrationOprfPublicKey({}), undefined)
  })

  it("rejects malformed values", () => {
    assert.throws(() => getRegistrationOprfPublicKey({ OPRF_REGISTRATION_PUBLIC_KEY: "41" }))
    assert.throws(() => getRegistrationOprfPublicKey({ OPRF_REGISTRATION_PUBLIC_KEY: "a,b" }))
  })
})

// --- Real proofs (needs network access to the registry, like the v1 tests) ---

// 3 base + facematch + oprf_auth from a mobile app test run; identify uses all but the face match
const fixture = JSON.parse(
  readFileSync(join(__dirname, "../test/fixtures/oprf-verify-request.json"), "utf8"),
)

describe("POST /oprf/v2/<step> with real proofs", () => {
  let app: FastifyInstance

  before(async () => {
    app = buildApp()
    await app.ready()
  })

  after(async () => {
    await app.close()
  })

  const identifyPayload = (blindedQuery: string) => ({
    proofs: fixture.proofs.filter((p: ProofResult) => !p.name?.startsWith("facematch")),
    blinded_query: blindedQuery,
  })

  it("identify: verifies a real 3 base + oprf_auth bundle", async () => {
    // Check the certificate root as of when the proofs were made, as the v1 test does
    const fm = fixture.proofs.find((p: ProofResult) => p.name?.startsWith("facematch"))
    const fmData = getProofData(fm.proof, getNumberOfPublicInputs(fm.name))
    mock.timers.enable({ apis: ["Date"], now: getCurrentDateFromDisclosureProof(fmData) })
    try {
      const res = await app.inject({
        method: "POST",
        url: "/oprf/v2/identify?devmode=true",
        payload: identifyPayload(fixture.blinded_unique_identifier),
      })
      const body = res.json()
      assert.equal(body.verified, true, `Expected verified: true, got error: ${body.error}`)
      assert.equal(res.statusCode, 200)
    } finally {
      mock.timers.reset()
    }
  })

  it("identify: rejects a real bundle for another session's blinded query", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/oprf/v2/identify?devmode=true",
      payload: identifyPayload(`0x${"01".repeat(64)}`),
    })
    assert.equal(res.statusCode, 400)
    assert.match(res.json().error, /blinded_query does not match/)
  })
})
