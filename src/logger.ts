import type { LoggerOptions } from "pino"

export const loggerOptions: LoggerOptions = {
  level: process.env.LOG_LEVEL || "info",
  formatters: {
    level(label) {
      return { level: label }
    },
  },
  timestamp: () => `,"time":"${new Date().toISOString()}"`,
}
