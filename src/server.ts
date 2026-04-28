import path from "path"
import Fastify from "fastify"
import fastifyStatic from "@fastify/static"
import { verifyOprfRoute } from "./routes/verify-oprf"

const app = Fastify({ logger: true })

app.register(fastifyStatic, {
  root: path.join(__dirname, "..", "circuits"),
  prefix: "/circuits",
  decorateReply: false,
})

app.get("/health", async () => {
  return { status: "ok" }
})

app.get("/", async () => {
  return { status: "ok" }
})

app.register(verifyOprfRoute)

const port = parseInt(process.env.PORT || "8080", 10)
const host = process.env.HOST || "0.0.0.0"

app.listen({ port, host }, (err) => {
  if (err) {
    app.log.error(err)
    process.exit(1)
  }
})
