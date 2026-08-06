import path from "path"
import fastifyStatic from "@fastify/static"
import { buildApp } from "./app"
import { loggerOptions } from "./logger"

const app = buildApp({ logger: loggerOptions })

// Temporarily bundled circuit vkeys for circuit versions not yet in the public registry
app.register(fastifyStatic, {
  root: path.join(__dirname, "..", "circuits"),
  prefix: "/circuits",
  decorateReply: false,
})

const port = parseInt(process.env.PORT || "8080", 10)
const host = process.env.HOST || "0.0.0.0"

app.listen({ port, host }, (err) => {
  if (err) {
    app.log.error(err)
    process.exit(1)
  }
})
