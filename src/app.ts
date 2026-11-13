import Fastify, { type FastifyServerOptions } from "fastify"
import cors from "@fastify/cors"
import { verifyOprfRoute } from "./routes/verify-oprf"
import { verifyRoute } from "./routes/verify"
import { oprfV2Routes, type OprfOptions } from "./routes/oprf-v2"
import { circuitsStaticRoutes } from "./circuits-static"

export function buildApp(
  opts: {
    logger?: FastifyServerOptions["logger"]
    /** Options of the OPRF routes (v1 and v2) */
    oprf?: OprfOptions
    /** Packaged circuits to serve under /circuits, see circuits-static.ts */
    circuitsDir?: string
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

  if (opts.circuitsDir) fastify.register(circuitsStaticRoutes, { dir: opts.circuitsDir })
  fastify.register(verifyOprfRoute, opts.oprf ?? {})
  fastify.register(verifyRoute)
  fastify.register(oprfV2Routes, opts.oprf ?? {})

  return fastify
}
