import { buildApp } from "./app"
import { loggerOptions } from "./logger"

const app = buildApp({ logger: loggerOptions })

const port = parseInt(process.env.PORT || "8080", 10)
const host = process.env.HOST || "0.0.0.0"

app.listen({ port, host }, (err) => {
  if (err) {
    app.log.error(err)
    process.exit(1)
  }
})
