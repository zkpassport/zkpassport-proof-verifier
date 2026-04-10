import Fastify from "fastify"
import { verifyOprfRoute } from "./routes/verify-oprf"

export function buildApp() {
  const fastify = Fastify({
    logger: false,
  })

  fastify.get("/health", async () => {
    return { status: "ok" }
  })

  fastify.register(verifyOprfRoute)

  return fastify
}
