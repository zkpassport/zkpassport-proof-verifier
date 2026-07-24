import { ZKPassport } from "@zkpassport/sdk"
import type { NullifierType, ProofResult, Query, QueryResult } from "@zkpassport/utils"

export interface VerifyParams {
  proofs: ProofResult[]
  originalQuery: Query
  queryResult: QueryResult
  domain?: string
  scope?: string
  validity?: number
  devMode?: boolean
  oprfKeyId?: string
}

export interface VerifyResult {
  verified: boolean
  uniqueIdentifier?: string
  uniqueIdentifierType?: NullifierType
  queryResultErrors?: unknown
}

// The SDK requires a non-empty domain in Node; proofs not bound to a domain
// (e.g. OPRF auth) are verified against this placeholder.
const PLACEHOLDER_DOMAIN = " "

// When the service becomes version agnostic, pick the SDK matching
// proofs[0].version here.
export async function verifyProofs(params: VerifyParams): Promise<VerifyResult> {
  const zkpassport = new ZKPassport(params.domain || PLACEHOLDER_DOMAIN)
  return zkpassport.verify({
    proofs: params.proofs,
    originalQuery: params.originalQuery,
    queryResult: params.queryResult,
    scope: params.scope,
    validity: params.validity,
    devMode: params.devMode,
    oprfKeyId: params.oprfKeyId,
  })
}
