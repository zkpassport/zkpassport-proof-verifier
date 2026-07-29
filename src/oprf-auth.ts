import type { ProofResult } from "@zkpassport/utils"
import {
  getProofData,
  getNumberOfPublicInputs,
  getCommitmentInFromDisclosureProof,
} from "@zkpassport/utils"

// oprf_auth circuit has 3 public inputs: comm_in (1 input) + (x, y) blinded query point (2 outputs)
const OPRF_AUTH_PUBLIC_INPUT_COUNT = 3

export interface BindingFailure {
  error: string
  logFields: Record<string, string>
}

export function findOprfAuthProof(proofs: ProofResult[]): ProofResult | undefined {
  return proofs.find(
    (proof) => proof?.name?.startsWith("oprf_auth") || proof?.name?.startsWith("oprf-auth"),
  )
}

export function hasOprfAuthProof(proofs: ProofResult[]): boolean {
  return findOprfAuthProof(proofs) !== undefined
}

// Checks the oprf_auth proof was made for this request, and for the same ID as the facematch
// proof. The SDK skips the oprf_auth proof entirely, so these are the only checks on it.
export function checkOprfAuthBinding(
  proofs: ProofResult[],
  blindedUniqueIdentifier: string,
): BindingFailure | null {
  const facematchProof = proofs.find((proof) => proof?.name?.startsWith("facematch"))
  const oprfAuthProof = findOprfAuthProof(proofs)

  if (!facematchProof?.proof) {
    return {
      error: "Missing required facematch proof",
      logFields: { event: "missing_proof", proof: "facematch" },
    }
  }

  if (!oprfAuthProof?.proof) {
    return {
      error: "Missing required oprf_auth proof",
      logFields: { event: "missing_proof", proof: "oprf_auth" },
    }
  }

  // Verify blinded_unique_identifier matches oprf_auth public output
  // oprf_auth outputs (x, y) on BabyJubJub as public outputs (indices 1 and 2)
  const oprfAuthData = getProofData(oprfAuthProof.proof, OPRF_AUTH_PUBLIC_INPUT_COUNT)
  const blindedX = BigInt(oprfAuthData.publicInputs[1]).toString(16).padStart(64, "0")
  const blindedY = BigInt(oprfAuthData.publicInputs[2]).toString(16).padStart(64, "0")
  const expectedBlindedId = `0x${blindedX}${blindedY}`

  if (blindedUniqueIdentifier.toLowerCase() !== expectedBlindedId.toLowerCase()) {
    return {
      error: "blinded_unique_identifier does not match oprf_auth proof output",
      logFields: { event: "mismatch", check: "blinded_unique_identifier" },
    }
  }

  const facematchData = getProofData(
    facematchProof.proof,
    getNumberOfPublicInputs(facematchProof.name!),
  )
  const facematchCommIn = getCommitmentInFromDisclosureProof(facematchData)
  const oprfAuthCommIn = BigInt(oprfAuthData.publicInputs[0])

  if (facematchCommIn !== oprfAuthCommIn) {
    return {
      error: "oprf_auth comm_in does not match facematch comm_in",
      logFields: { event: "mismatch", check: "comm_in" },
    }
  }

  return null
}
