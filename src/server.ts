import path from "node:path"
import { buildApp } from "./app"
import { loggerOptions } from "./logger"
import { getCircuitsUrl } from "./oprf-v2/config"
import { hasPackagedCircuits } from "./circuits-static"

const port = parseInt(process.env.PORT || "8080", 10)
const host = process.env.HOST || "0.0.0.0"

async function main() {
  // CIRCUITS_URL, else a packaged directory the oracle serves itself, else the public registry
  const circuitsDir = path.resolve(process.env.CIRCUITS_DIR || "packaged")
  const servesCircuits = await hasPackagedCircuits(circuitsDir)
  const circuitsUrl =
    getCircuitsUrl() ?? (servesCircuits ? `http://127.0.0.1:${port}/circuits` : undefined)

  const app = buildApp({
    logger: loggerOptions,
    circuitsDir: servesCircuits ? circuitsDir : undefined,
    oprf: { circuitsUrl },
  })
  app.log.info(
    { circuitsUrl: circuitsUrl ?? "public registry", circuitsDir: servesCircuits ? circuitsDir : undefined },
    "circuit source",
  )

  app.listen({ port, host }, (err) => {
    if (err) {
      app.log.error(err)
      process.exit(1)
    }
  })
}

main()
