import type { FastifyInstance, RouteHandler } from "fastify"
import {
  UnsupportedProofError,
  verifyProofs,
  type VerifyParams,
  type VerifyResult,
} from "../verification"

type VerifyResponse = VerifyResult & { error?: string }

const isOprfAuthProof = (name?: string) =>
  !!name && (name.startsWith("oprf_auth") || name.startsWith("oprf-auth"))

export async function verifyRoute(fastify: FastifyInstance) {
  const handler: RouteHandler<{ Body: VerifyParams; Reply: VerifyResponse }> = async (
    request,
    reply,
  ) => {
    const startedAt = Date.now()
    const log = request.log.child({ route: "verify" })
    const body = request.body ?? ({} as VerifyParams)

    log.info(
      {
        event: "received",
        proofCount: Array.isArray(body.proofs) ? body.proofs.length : null,
        version: Array.isArray(body.proofs) ? body.proofs[0]?.version : undefined,
        devMode: body.serviceConfig?.devMode === true,
      },
      "verify request received",
    )

    if (!Array.isArray(body.proofs) || body.proofs.length === 0) {
      return reply
        .status(400)
        .send({ verified: false, error: "Missing required field: proofs (non-empty array)" })
    }
    if (!body.originalQuery || typeof body.originalQuery !== "object") {
      return reply.status(400).send({ verified: false, error: "Missing required field: originalQuery" })
    }
    if (!body.queryResult || typeof body.queryResult !== "object") {
      return reply.status(400).send({ verified: false, error: "Missing required field: queryResult" })
    }
    // null is rejected, not treated as missing: the defaults skip the domain check
    if (body.serviceConfig !== undefined && (typeof body.serviceConfig !== "object" || body.serviceConfig === null)) {
      return reply.status(400).send({ verified: false, error: "Invalid field: serviceConfig (must be an object)" })
    }
    if (body.options !== undefined && (typeof body.options !== "object" || body.options === null)) {
      return reply.status(400).send({ verified: false, error: "Invalid field: options (must be an object)" })
    }
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
      const result = await verifyProofs(body)

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
      return reply.send(result)
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown verification error"
      // 501, not 400: the request was fine, this service just can't verify these proofs yet
      const status = err instanceof UnsupportedProofError ? 501 : 400
      log.error(
        { err, event: "error", status, durationMs: Date.now() - startedAt },
        "Proof verification threw",
      )
      return reply.status(status).send({ verified: false, error: message })
    }
  }

  fastify.post<{ Body: VerifyParams; Reply: VerifyResponse }>("/verify", handler)
}
