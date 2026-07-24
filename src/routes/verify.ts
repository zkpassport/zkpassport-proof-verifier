import type { FastifyInstance, RouteHandler } from "fastify"
import { verifyProofs, type VerifyParams, type VerifyResult } from "../verification"

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
        devMode: body.devMode === true,
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
