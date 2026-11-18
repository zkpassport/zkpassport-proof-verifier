import Fastify, { type FastifyServerOptions } from "fastify"
import cors from "@fastify/cors"
import { verifyOprfRoute } from "./routes/verify-oprf"
import { verifyRoute } from "./routes/verify"
import { oprfV2Routes, type OprfOptions } from "./routes/oprf-v2"
import { circuitsStaticRoutes } from "./circuits-static"
import { getCircuitsUrl } from "./oprf-v2/config"
import { RegistryProofBackend, sharedBackends } from "./oprf-v2/proof-backend"

export function buildApp(
  opts: {
    logger?: FastifyServerOptions["logger"]
    oprf?: OprfOptions
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
  const { circuitsUrl: circuitsUrlOption, createBackend, ...oprf } = opts.oprf ?? {}
  const circuitsUrl = opts.oprf && "circuitsUrl" in opts.oprf ? circuitsUrlOption : getCircuitsUrl()
  // bb and the circuit vkeys are expensive to set up, so every request shares them
  const backends = sharedBackends(
    createBackend ?? ((devMode) => new RegistryProofBackend({ devMode, circuitsUrl })),
  )
  fastify.addHook("onClose", () => backends.close())

  fastify.register(verifyOprfRoute, { getBackend: backends.get })
  fastify.register(verifyRoute)
  fastify.register(oprfV2Routes, { ...oprf, getBackend: backends.get })

  return fastify
}
