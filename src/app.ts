import Fastify, { type FastifyServerOptions } from "fastify"
import cors from "@fastify/cors"
import { verifyOprfRoute } from "./routes/verify-oprf"
import { verifyRoute } from "./routes/verify"
import {
  verifyPassportProofRoute,
  type VerifyPassportProofOptions,
} from "./routes/verify-passport-proof"

export function buildApp(
  opts: {
    logger?: FastifyServerOptions["logger"]
    verifyPassportProof?: VerifyPassportProofOptions
  } = {},
) {
  const fastify = Fastify({
    logger: opts.logger ?? false,
  })

  // Browsers call this API from customer domains, so any origin is allowed
  fastify.register(cors)

  fastify.get("/health", async () => {
    return { status: "ok" }
  })

  fastify.get("/", async () => {
    return { status: "ok" }
  })

  fastify.register(verifyOprfRoute)
  fastify.register(verifyRoute)
  fastify.register(verifyPassportProofRoute, opts.verifyPassportProof ?? {})

  return fastify
}
