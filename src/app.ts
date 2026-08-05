import path from "path"
import Fastify, { type FastifyServerOptions } from "fastify"
import cors from "@fastify/cors"
import rateLimit from "@fastify/rate-limit"
import fastifyStatic from "@fastify/static"
import { verifyOprfRoute } from "./routes/verify-oprf"
import { verifyRoute } from "./routes/verify"

export function buildApp(opts: { logger?: FastifyServerOptions["logger"] } = {}) {
  const fastify = Fastify({
    logger: opts.logger ?? false,
    // Requests arrive via Google's load balancer, which appends the real client IP
    // to x-forwarded-for. Trust exactly that hop — callers can fake anything before it
    trustProxy: 2,
  })

  // Browsers call this API from customer domains, so any origin is allowed
  fastify.register(cors)

  // Each verification burns seconds of CPU, so cap what a single client can ask for
  fastify.register(rateLimit, { max: 60, timeWindow: "1 minute" })

  fastify.register(fastifyStatic, {
    root: path.join(__dirname, "..", "circuits"),
    prefix: "/circuits",
    decorateReply: false,
  })

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
