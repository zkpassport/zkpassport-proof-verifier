import type { FastifyInstance, RouteHandler } from "fastify"
import { z } from "zod"
import type { ProofResult, Query, QueryResult } from "@zkpassport/utils"
import { ZKPassport, type VerificationResult } from "@zkpassport/sdk"

const isObject = (value: unknown) => typeof value === "object" && value !== null

// Checks only the request shape — the SDK does the real proof and query validation
const verifyRequestSchema = z.object({
  proofs: z.array(z.custom<ProofResult>(isObject, "Expected an object")).min(1),
  originalQuery: z.custom<Query>(isObject, "Expected an object"),
  queryResult: z.custom<QueryResult>(isObject, "Expected an object"),
  // Mirrors the ServiceConfig struct of the Solidity verifier
  // (registry-contracts Types.sol / the SDK's SolidityServiceConfig)
  serviceConfig: z
    .object({
      validityPeriodInSeconds: z.number().optional(),
      domain: z.string().optional(),
      scope: z.string().optional(),
      devMode: z.boolean().optional(),
    })
    .optional(),
  options: z
    .object({
      ignoreValidity: z.boolean().optional(),
    })
    .optional(),
  oprfKeyId: z.string().optional(),
})

type VerifyRequest = z.infer<typeof verifyRequestSchema>

type VerifyResponse = Partial<VerificationResult> & {
  verified: boolean
  // Only set when options.ignoreValidity was used, so callers know the age was not checked
  ignoredValidity?: boolean
  error?: string
}

// The SDK requires a non-empty domain in Node; domain-unbound proofs
// (e.g. OPRF auth) verify against this placeholder
const PLACEHOLDER_DOMAIN = " "

// Large number instead of Infinity so it also works with the Solidity verifier
const IGNORE_VALIDITY_SECONDS = 100 * 365 * 24 * 60 * 60

const isOprfAuthProof = (name?: string) =>
  !!name && (name.startsWith("oprf_auth") || name.startsWith("oprf-auth"))

export async function verifyRoute(fastify: FastifyInstance) {
  const handler: RouteHandler<{ Body: unknown; Reply: VerifyResponse }> = async (
    request,
    reply,
  ) => {
    const startedAt = Date.now()
    const log = request.log.child({ route: "verify" })
    const rawBody = (request.body ?? {}) as Partial<VerifyRequest>

    log.info(
      {
        event: "received",
        proofCount: Array.isArray(rawBody.proofs) ? rawBody.proofs.length : null,
        version: Array.isArray(rawBody.proofs) ? rawBody.proofs[0]?.version : undefined,
        devMode: rawBody.serviceConfig?.devMode === true,
      },
      "verify request received",
    )

    const parsed = verifyRequestSchema.safeParse(request.body)
    if (!parsed.success) {
      const error = parsed.error.issues
        .map((issue) => `${issue.path.join(".") || "body"}: ${issue.message}`)
        .join("; ")
      log.warn({ event: "bad_request", error }, "verify request failed validation")
      return reply.status(400).send({ verified: false, error })
    }
    const body = parsed.data

    // Nothing here checks an oprf_auth proof, so accepting one would call it verified
    // when it never was. /verify-oprf-auth is the route that checks them.
    if (body.proofs.some((proof) => isOprfAuthProof(proof?.name))) {
      log.warn({ event: "rejected", reason: "oprf_auth_proof" }, "oprf_auth proof sent to /verify")
      return reply.status(400).send({
        verified: false,
        error: "oprf_auth proofs are not verified here, use POST /verify-oprf-auth instead",
      })
    }

    // Known SDK gap: it uses the committedInputs field from the request to decide what was
    // proven, so a query can pass without a proof behind it. Does not affect the OPRF route.
    try {
      const serviceConfig = body.serviceConfig ?? {}
      const zkpassport = new ZKPassport(serviceConfig.domain || PLACEHOLDER_DOMAIN)
      const ignoredValidity = body.options?.ignoreValidity === true
      const result = await zkpassport.verify({
        proofs: body.proofs,
        originalQuery: body.originalQuery,
        queryResult: body.queryResult,
        scope: serviceConfig.scope,
        validity: ignoredValidity ? IGNORE_VALIDITY_SECONDS : serviceConfig.validityPeriodInSeconds,
        devMode: serviceConfig.devMode === true,
        oprfKeyId: body.oprfKeyId,
        verifierMode: "local",
      })

      if (!result.verified) {
        log.warn(
          {
            event: "verification_failed",
            durationMs: Date.now() - startedAt,
            queryResultErrors: result.queryResultErrors,
          },
          "Proof verification failed",
        )
        return reply.status(400).send({
          ...result,
          error: `Proof verification failed: ${JSON.stringify(result.queryResultErrors ?? {})}`,
        })
      }

      log.info({ event: "verified", durationMs: Date.now() - startedAt }, "verify succeeded")
      return reply.send(ignoredValidity ? { ...result, ignoredValidity } : result)
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown verification error"
      log.error(
        { err, event: "error", durationMs: Date.now() - startedAt },
        "Proof verification threw",
      )
      return reply.status(400).send({ verified: false, error: message })
    }
  }

  fastify.post<{ Body: unknown; Reply: VerifyResponse }>("/verify", handler)
}
