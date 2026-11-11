import type { ProofResult } from "@zkpassport/utils"
import { ZKPassport } from "@zkpassport/sdk"
import { IGNORE_VALIDITY_SECONDS } from "../validity"
import type { FacematchVerifier } from "./verify-bundle"
import { ServiceUnavailableError } from "./proof-backend"

/**
 * Verify 3 base proofs + a face-match proof with the SDK, with the same query as v1
 * /verify-oprf-auth: strict mode (regular in dev mode), production attestation, ZKPassport app id,
 * date within the default validity.
 */
export const verifyFacematchWithSdk: FacematchVerifier = async (
  proofs: ProofResult[],
  devMode: boolean,
) => {
  const facematch = { mode: devMode ? "regular" : "strict", passed: true }
  let result: { verified: boolean; queryResultErrors?: unknown }
  try {
    result = await new ZKPassport("*").verify({
      proofs,
      originalQuery: { facematch },
      queryResult: { facematch },
      devMode,
      validity: devMode ? IGNORE_VALIDITY_SECONDS : undefined,
      verifierMode: "local",
    } as any)
  } catch (cause) {
    // The SDK reports bad proofs as verified: false; a throw means it could not run
    throw new ServiceUnavailableError("Could not run the face match verification", { cause })
  }
  return result.verified
    ? { verified: true }
    : { verified: false, error: JSON.stringify(result.queryResultErrors ?? {}) }
}
