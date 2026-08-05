import type { NullifierType, ProofResult, Query, QueryResult } from "@zkpassport/utils"
import { canVerifyLocally, ZKPassport } from "@zkpassport/sdk"

// Mirrors the ServiceConfig struct of the Solidity verifier
// (registry-contracts Types.sol / the SDK's SolidityServiceConfig)
export interface ServiceConfig {
  validityPeriodInSeconds?: number
  domain?: string
  scope?: string
  devMode?: boolean
}

export interface VerifyOptions {
  ignoreValidity?: boolean
}

export interface VerifyParams {
  proofs: ProofResult[]
  originalQuery: Query
  queryResult: QueryResult
  serviceConfig?: ServiceConfig
  options?: VerifyOptions
  oprfKeyId?: string
}

export interface VerifyResult {
  verified: boolean
  uniqueIdentifier?: string
  uniqueIdentifierType?: NullifierType
  queryResultErrors?: unknown
  // Only set when options.ignoreValidity was used, so callers know the age was not checked
  ignoredValidity?: boolean
}

// Thrown when this service's SDK is too old to verify the proofs
export class UnsupportedProofError extends Error {}

// The SDK requires a non-empty domain in Node; domain-unbound proofs
// (e.g. OPRF auth) verify against this placeholder
const PLACEHOLDER_DOMAIN = " "

// Large number instead of Infinity so it also works with the Solidity verifier
const IGNORE_VALIDITY_SECONDS = 100 * 365 * 24 * 60 * 60

export async function verifyProofs(params: VerifyParams): Promise<VerifyResult> {
  const serviceConfig = params.serviceConfig ?? {}
  const zkpassport = new ZKPassport(serviceConfig.domain || PLACEHOLDER_DOMAIN)
  const ignoredValidity = params.options?.ignoreValidity === true
  const validity = ignoredValidity
    ? IGNORE_VALIDITY_SECONDS
    : serviceConfig.validityPeriodInSeconds
  let result: VerifyResult
  try {
    result = await zkpassport.verify({
      proofs: params.proofs,
      originalQuery: params.originalQuery,
      queryResult: params.queryResult,
      scope: serviceConfig.scope,
      validity,
      devMode: serviceConfig.devMode === true,
      oprfKeyId: params.oprfKeyId,
      // This service is the SDK's verifier API, so it must never defer to it
      mode: "local",
    })
  } catch (err) {
    throwIfUnsupported(params.proofs)
    throw err
  }
  if (!result.verified) {
    throwIfUnsupported(params.proofs)
  }
  return ignoredValidity ? { ...result, ignoredValidity } : result
}

// After a failed attempt, proofs from a bb version this service's SDK doesn't support
// report as "not yet supported" (501) rather than "invalid"
function throwIfUnsupported(proofs: ProofResult[]) {
  const proof = proofs[0]
  if (!canVerifyLocally(proof ?? {})) {
    throw new UnsupportedProofError(
      `Proofs generated with bb ${proof?.bbVersion} are not yet supported by the verifier service`,
    )
  }
}
