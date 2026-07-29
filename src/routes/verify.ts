import type { FastifyInstance, RouteHandler } from "fastify"
import { verifyProofs, type VerifyParams, type VerifyResult } from "../verification"
import { checkOprfAuthBinding, hasOprfAuthProof } from "../oprf-auth"

type VerifyResponse = VerifyResult & { error?: string }

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
    if (body.serviceConfig !== undefined && (typeof body.serviceConfig !== "object" || body.serviceConfig === null)) {
      return reply.status(400).send({ verified: false, error: "Invalid field: serviceConfig (must be an object)" })
    }
    if (body.options !== undefined && (typeof body.options !== "object" || body.options === null)) {
      return reply.status(400).send({ verified: false, error: "Invalid field: options (must be an object)" })
    }
    // An oprf_auth proof only means something together with the OPRF request it was made for
    if (hasOprfAuthProof(body.proofs)) {
      const blindedUniqueIdentifier = body.blinded_unique_identifier
      if (typeof blindedUniqueIdentifier !== "string" || blindedUniqueIdentifier.length === 0) {
        return reply.status(400).send({
          verified: false,
          error:
            "OPRF auth proof bundles require blinded_unique_identifier, which binds the proof to the OPRF query it authorizes",
        })
      }
      const bindingFailure = checkOprfAuthBinding(body.proofs, blindedUniqueIdentifier)
      if (bindingFailure) {
        log.warn(bindingFailure.logFields, bindingFailure.error)
        return reply.status(400).send({ verified: false, error: bindingFailure.error })
      }
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
      log.error(
        { err, event: "error", durationMs: Date.now() - startedAt },
        "Proof verification threw",
      )
      return reply.status(400).send({ verified: false, error: message })
    }
  }

  fastify.post<{ Body: VerifyParams; Reply: VerifyResponse }>("/verify", handler)
}
