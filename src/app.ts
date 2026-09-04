import Fastify, { type FastifyServerOptions } from "fastify"
import cors from "@fastify/cors"
import { verifyOprfRoute } from "./routes/verify-oprf"
import { verifyRoute } from "./routes/verify"

export function buildApp(opts: { logger?: FastifyServerOptions["logger"] } = {}) {
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

  return fastify
}
