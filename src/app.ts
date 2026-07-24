import Fastify from "fastify"
import { verifyOprfRoute } from "./routes/verify-oprf"
import { verifyRoute } from "./routes/verify"

export function buildApp() {
  const fastify = Fastify({
    logger: false,
  })

  fastify.get("/health", async () => {
    return { status: "ok" }
  })

  fastify.register(verifyOprfRoute)
  fastify.register(verifyRoute)

  return fastify
}
