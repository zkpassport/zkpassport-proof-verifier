import type { NullifierType, ProofResult, Query, QueryResult } from "@zkpassport/utils"
import { ZKPassport } from "@zkpassport/sdk"

// Mirrors the ServiceConfig struct of the Solidity verifier
// (registry-contracts Types.sol / the SDK's SolidityServiceConfig)
export interface ServiceConfig {
  validityPeriodInSeconds?: number
  domain?: string
  scope?: string
  devMode?: boolean
}

export interface VerifyParams {
  proofs: ProofResult[]
  originalQuery: Query
  queryResult: QueryResult
  serviceConfig?: ServiceConfig
  oprfKeyId?: string
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

export async function verifyProofs(params: VerifyParams): Promise<VerifyResult> {
  const serviceConfig = params.serviceConfig ?? {}
  const zkpassport = new ZKPassport(serviceConfig.domain || PLACEHOLDER_DOMAIN)
  return zkpassport.verify({
    proofs: params.proofs,
    originalQuery: params.originalQuery,
    queryResult: params.queryResult,
    scope: serviceConfig.scope,
    validity: serviceConfig.validityPeriodInSeconds,
    devMode: serviceConfig.devMode === true,
    oprfKeyId: params.oprfKeyId,
  })
}
