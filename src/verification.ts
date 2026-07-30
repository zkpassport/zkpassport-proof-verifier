import type { NullifierType, ProofResult, Query, QueryResult } from "@zkpassport/utils"
import { isCircuitVersionSupported, ZKPassport } from "@zkpassport/sdk"

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
  // Optional: when supplied, the route checks the oprf_auth proof was made for this OPRF query
  blinded_unique_identifier?: string
}

export interface VerifyResult {
  verified: boolean
  uniqueIdentifier?: string
  uniqueIdentifierType?: NullifierType
  queryResultErrors?: unknown
}

// The SDK requires a non-empty domain in Node; domain-unbound proofs
// (e.g. OPRF auth) verify against this placeholder
const PLACEHOLDER_DOMAIN = " "

// Large number instead of Infinity so it also works with the Solidity verifier
const IGNORE_VALIDITY_SECONDS = 100 * 365 * 24 * 60 * 60

export async function verifyProofs(params: VerifyParams): Promise<VerifyResult> {
  const circuitVersion = params.proofs[0]?.version
  if (!isCircuitVersionSupported(circuitVersion)) {
    throw new Error(
      `Circuit version ${circuitVersion ?? "unknown"} is not yet supported by the verifier service`,
    )
  }
  const serviceConfig = params.serviceConfig ?? {}
  const zkpassport = new ZKPassport(serviceConfig.domain || PLACEHOLDER_DOMAIN)
  const validity = params.options?.ignoreValidity
    ? IGNORE_VALIDITY_SECONDS
    : serviceConfig.validityPeriodInSeconds
  return zkpassport.verify({
    proofs: params.proofs,
    originalQuery: params.originalQuery,
    queryResult: params.queryResult,
    scope: serviceConfig.scope,
    validity,
    devMode: serviceConfig.devMode === true,
    oprfKeyId: params.oprfKeyId,
  })
}
