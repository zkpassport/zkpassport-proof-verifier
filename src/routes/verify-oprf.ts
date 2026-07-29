import type { FastifyInstance, RouteHandler } from "fastify"
import type { ProofResult } from "@zkpassport/utils"
import { ZKPassport } from "@zkpassport/sdk"
import { checkOprfAuthBinding } from "../oprf-auth"

interface VerifyOprfRequest {
  blinded_unique_identifier: string
  proofs: ProofResult[]
}

interface VerifyOprfResponse {
  verified: boolean
  error?: string
}

export async function verifyOprfRoute(fastify: FastifyInstance) {
  const handler: RouteHandler<{ Body: VerifyOprfRequest; Reply: VerifyOprfResponse }> = async (
    request,
    reply,
  ) => {
    const startedAt = Date.now()
    const log = request.log.child({ route: "verify-oprf-auth" })

    const { blinded_unique_identifier, proofs } = request.body

    const isDevMode = request.query && (request.query as any).devmode === "true"

    log.info(
      { event: "received", proofCount: Array.isArray(proofs) ? proofs.length : null, devMode: isDevMode },
      "verify-oprf-auth request received",
    )

    if (!blinded_unique_identifier || !proofs || !Array.isArray(proofs)) {
      log.warn({ event: "bad_request", reason: "missing_fields" }, "Missing required fields")
      return reply.status(400).send({
        verified: false,
        error: "Missing required fields: blinded_unique_identifier, proofs",
      })
    }

    if (proofs.length !== 5) {
      log.warn(
        { event: "bad_request", reason: "proof_count", proofCount: proofs.length },
        "Unexpected number of subproofs",
      )
      return reply.status(400).send({
        verified: false,
        error: `Expected 5 subproofs (3 base + facematch + oprf_auth), got ${proofs.length}`,
      })
    }

    try {
      const bindingFailure = checkOprfAuthBinding(proofs, blinded_unique_identifier)
      if (bindingFailure) {
        log.warn(bindingFailure.logFields, bindingFailure.error)
        return reply.status(400).send({ verified: false, error: bindingFailure.error })
      }

      // Use ZKPassport SDK to verify all proofs (commitment chain + cryptographic verification).
      log.info({ event: "sdk_verify_start" }, "Running ZKPassport SDK proof verification")
      const zkpassport = new ZKPassport(" ")
      const { verified, queryResultErrors } = await zkpassport.verify({
        proofs,
        // Ignore facematch validation in dev mode
        originalQuery: { facematch: { mode: isDevMode ? "regular" : "strict", passed: true } },
        queryResult: { facematch: { mode: isDevMode ? "regular" : "strict", passed: true } },
        devMode: isDevMode,
      } as any)

      if (!verified) {
        log.warn(
          { event: "verification_failed", durationMs: Date.now() - startedAt, queryResultErrors },
          "SDK reported proof verification failed",
        )
        return reply.status(400).send({
          verified: false,
          error: `Proof verification failed: ${JSON.stringify(queryResultErrors ?? {})}`,
        })
      }

      log.info(
        { event: "verified", durationMs: Date.now() - startedAt },
        "verify-oprf-auth succeeded",
      )
      return reply.send({ verified: true })
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown verification error"
      log.error({ err, event: "error", durationMs: Date.now() - startedAt }, "Proof verification threw")
      return reply.status(400).send({
        verified: false,
        error: message,
      })
    }
  }

  fastify.post<{ Body: VerifyOprfRequest; Reply: VerifyOprfResponse }>("/verify-oprf-auth", handler)
  fastify.post<{ Body: VerifyOprfRequest; Reply: VerifyOprfResponse }>("/oprf/verify", handler)
}
