import type { ProofResult } from "@zkpassport/utils"
import { ZKPassport } from "@zkpassport/sdk"
import { IGNORE_VALIDITY_SECONDS } from "../validity"
import type { FacematchVerifier } from "./verify-bundle"
import { ServiceUnavailableError } from "./proof-backend"

// Same SDK query as v1 /verify-oprf-auth
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
    // A throw means the SDK could not run, not that the proofs are bad
    throw new ServiceUnavailableError("Could not run the face match verification", { cause })
  }
  return result.verified
    ? { verified: true }
    : { verified: false, error: JSON.stringify(result.queryResultErrors ?? {}) }
}
