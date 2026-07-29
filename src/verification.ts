import type { NullifierType, ProofResult, Query, QueryResult } from "@zkpassport/utils"
import { ZKPassport } from "@zkpassport/sdk"

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
}

// The SDK requires a non-empty domain in Node; domain-unbound proofs
// (e.g. OPRF auth) verify against this placeholder
const PLACEHOLDER_DOMAIN = " "

// Use large number instead of "Infinity" to make this work with Solidy verifier
const IGNORE_VALIDITY_SECONDS = 100 * 365 * 24 * 60 * 60

export async function verifyProofs(params: VerifyParams): Promise<VerifyResult> {
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
