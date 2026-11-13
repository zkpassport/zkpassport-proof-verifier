import type { ProofResult } from "@zkpassport/utils"
import {
  getCommitmentFromDSCProof,
  getCommitmentInFromDisclosureProof,
  getCommitmentInFromIDDataProof,
  getCommitmentInFromIntegrityProof,
  getCommitmentOutFromIDDataProof,
  getCommitmentOutFromIntegrityProof,
  getMerkleRootFromDSCProof,
  getNumberOfPublicInputs,
  getProofData,
} from "@zkpassport/utils"
import type { Point } from "./config"
import { ServiceUnavailableError, type ProofBackend } from "./proof-backend"

export type Mode = "identify" | "register" | "query" | "rotate"

export const MODES: readonly Mode[] = ["identify", "register", "query", "rotate"]

type ExtraProofKind = "oprf_auth" | "oprf_registration" | "facematch"
type ProofKind = "sig_check_dsc" | "sig_check_id_data" | "data_check_integrity" | ExtraProofKind

const BASE_KINDS = ["sig_check_dsc", "sig_check_id_data", "data_check_integrity"] as const

const EXTRA_PROOFS: Record<Mode, readonly ExtraProofKind[]> = {
  identify: ["oprf_auth"],
  register: ["oprf_registration"],
  query: ["oprf_auth", "oprf_registration"],
  rotate: ["facematch", "oprf_registration"],
}

// oprf_auth: comm_in, blinded query (x, y)
const OPRF_AUTH_PUBLIC_INPUT_COUNT = 3
// oprf_registration: comm_in, registration id (x, y), OPRF public key (x, y), auth commitment
const OPRF_REGISTRATION_PUBLIC_INPUT_COUNT = 6

export type BundleRequest = {
  mode: Mode
  proofs: ProofResult[]
  blindedQuery?: Point
  registrationId?: Point
  /** query: the commitment the node has stored for I; register, rotate: the one to store */
  commitment?: bigint
}

export type FacematchVerifier = (
  proofs: ProofResult[],
  devMode: boolean,
) => Promise<{ verified: boolean; error?: string }>

export type VerifyContext = {
  backend: ProofBackend
  registrationPublicKey?: Point
  verifyFacematch: FacematchVerifier
  devMode: boolean
}

export type BundleVerdict =
  | { verified: true }
  | { verified: false; status: 400 | 500 | 503; error: string }

const reject = (error: string): BundleVerdict => ({ verified: false, status: 400, error })

function getProofKind(name: string | undefined): ProofKind | undefined {
  if (!name) return undefined
  for (const kind of BASE_KINDS) if (name.startsWith(kind)) return kind
  if (name === "oprf_auth") return "oprf_auth"
  if (name === "oprf_registration") return "oprf_registration"
  // The EVM variant has a different public input layout
  if (name.startsWith("facematch") && !name.endsWith("_evm")) return "facematch"
  return undefined
}

function getPublicInputCount(kind: ProofKind, name: string): number {
  if (kind === "oprf_auth") return OPRF_AUTH_PUBLIC_INPUT_COUNT
  if (kind === "oprf_registration") return OPRF_REGISTRATION_PUBLIC_INPUT_COUNT
  return getNumberOfPublicInputs(name)
}

const samePoint = (a: Point, b: Point) => a.x === b.x && a.y === b.y
const formatPoint = (p: Point) => `(${p.x}, ${p.y})`

function classify(
  mode: Mode,
  proofs: ProofResult[],
): { byKind: Map<ProofKind, ProofResult> } | { error: string } {
  const expected: ProofKind[] = [...BASE_KINDS, ...EXTRA_PROOFS[mode]]
  if (proofs.length !== expected.length) {
    return {
      error: `Expected ${expected.length} proofs for mode ${mode} (${expected.join(", ")}), got ${proofs.length}`,
    }
  }
  const byKind = new Map<ProofKind, ProofResult>()
  for (const proof of proofs) {
    if (typeof proof?.proof !== "string" || !proof.proof || !proof.version) {
      return { error: `Proof ${proof?.name ?? "(unnamed)"} is missing its proof or version` }
    }
    const kind = getProofKind(proof.name)
    if (!kind || !expected.includes(kind)) {
      return { error: `Unexpected proof for mode ${mode}: ${proof.name ?? "(unnamed)"}` }
    }
    if (byKind.has(kind)) return { error: `Duplicate ${kind} proof` }
    byKind.set(kind, proof)
  }
  return { byKind }
}

// Base chain from a valid certificate root to P, every other proof opens the same P, oprf_auth
// matches the blinded query, oprf_registration matches I, the pinned k_reg and the commitment,
// then every proof is verified against the circuit registry
export async function verifyBundle(req: BundleRequest, ctx: VerifyContext): Promise<BundleVerdict> {
  const classified = classify(req.mode, req.proofs)
  if ("error" in classified) return reject(classified.error)
  const { byKind } = classified
  const has = (kind: ProofKind) => byKind.has(kind)

  if (has("oprf_auth") && !req.blindedQuery) {
    return reject(`Mode ${req.mode} requires blinded_query`)
  }
  if (has("oprf_registration")) {
    if (!req.registrationId || req.commitment === undefined) {
      return reject(`Mode ${req.mode} requires I and commitment`)
    }
    if (!ctx.registrationPublicKey) {
      return {
        verified: false,
        status: 500,
        error: "Oracle misconfigured: OPRF_REGISTRATION_PUBLIC_KEY is not set",
      }
    }
  }

  // Buffer.from(hex) silently drops invalid hex, so check the encoding first
  const publicInputs = new Map<ProofKind, bigint[]>()
  const proofData = new Map<ProofKind, ReturnType<typeof getProofData>>()
  try {
    for (const [kind, proof] of byKind) {
      const count = getPublicInputCount(kind, proof.name!)
      const hex = proof.proof as string
      if (!/^([0-9a-fA-F]{64})+$/.test(hex) || hex.length / 64 <= count) {
        return reject(`Malformed proof: ${proof.name}`)
      }
      const data = getProofData(hex, count)
      proofData.set(kind, data)
      publicInputs.set(
        kind,
        data.publicInputs.map((input) => BigInt(input)),
      )
    }
  } catch {
    return reject("Malformed proof")
  }

  const dsc = proofData.get("sig_check_dsc")!
  const idData = proofData.get("sig_check_id_data")!
  const integrity = proofData.get("data_check_integrity")!
  if (getCommitmentFromDSCProof(dsc) !== getCommitmentInFromIDDataProof(idData)) {
    return reject("Failed to check the link between the certificate signature and ID signature")
  }
  if (getCommitmentOutFromIDDataProof(idData) !== getCommitmentInFromIntegrityProof(integrity)) {
    return reject("Failed to check the link between the ID signature and the data signed")
  }
  const passportCommitment = getCommitmentOutFromIntegrityProof(integrity)

  if (has("oprf_auth")) {
    const [commIn, bx, by] = publicInputs.get("oprf_auth")!
    if (commIn !== passportCommitment) {
      return reject("oprf_auth comm_in does not match the base proof commitment")
    }
    if (!samePoint({ x: bx, y: by }, req.blindedQuery!)) {
      return reject("blinded_query does not match the oprf_auth proof output")
    }
  }

  if (has("oprf_registration")) {
    const [commIn, ix, iy, pkx, pky, commitment] = publicInputs.get("oprf_registration")!
    if (commIn !== passportCommitment) {
      return reject("oprf_registration comm_in does not match the base proof commitment")
    }
    if (!samePoint({ x: ix, y: iy }, req.registrationId!)) {
      return reject("I does not match the oprf_registration proof")
    }
    if (!samePoint({ x: pkx, y: pky }, ctx.registrationPublicKey!)) {
      return reject(
        `oprf_registration was not evaluated under the registration key: got ${formatPoint({ x: pkx, y: pky })}`,
      )
    }
    if (commitment !== req.commitment) {
      return reject("commitment does not match the oprf_registration proof")
    }
  }

  if (has("facematch")) {
    if (getCommitmentInFromDisclosureProof(proofData.get("facematch")!) !== passportCommitment) {
      return reject("facematch comm_in does not match the base proof commitment")
    }
  }

  try {
    if (!(await ctx.backend.isCertificateRootValid(getMerkleRootFromDSCProof(dsc)))) {
      return reject("The ID was signed by an unrecognized root certificate")
    }

    let toVerify = [...byKind.entries()]
    if (has("facematch")) {
      // The SDK verifies the base proofs along with the face match
      const base = BASE_KINDS.map((kind) => byKind.get(kind)!)
      const facematch = await ctx.verifyFacematch([...base, byKind.get("facematch")!], ctx.devMode)
      if (!facematch.verified) {
        return reject(`Face match verification failed${facematch.error ? `: ${facematch.error}` : ""}`)
      }
      toVerify = toVerify.filter(([kind]) => kind === "oprf_auth" || kind === "oprf_registration")
    }

    for (const [kind, proof] of toVerify) {
      if (!(await ctx.backend.verifyProof(proof, getPublicInputCount(kind, proof.name!)))) {
        return reject(`Proof verification failed: ${proof.name}@${proof.version}`)
      }
    }
  } catch (error) {
    if (error instanceof ServiceUnavailableError) {
      return { verified: false, status: 503, error: error.message }
    }
    throw error
  }

  return { verified: true }
}
