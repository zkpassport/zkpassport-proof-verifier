import type { FastifyInstance, FastifyReply } from "fastify"
import { access, readFile } from "node:fs/promises"
import path from "node:path"

export async function hasPackagedCircuits(dir: string): Promise<boolean> {
  try {
    await access(path.join(dir, "manifest.json"))
    return true
  } catch {
    return false
  }
}

type Manifest = { version: string; root: string; circuits: Record<string, { hash: string }> }

const normaliseHash = (hash: string) => hash.toLowerCase().replace(/^0x/, "").replace(/^0+/, "")

// Serves a packaged circuits directory (target/packaged of the circuits repo) with the registry URL
// layout. Only the manifest's own version and root are served, so a proof of another version is
// never checked against the wrong vkey
export async function circuitsStaticRoutes(fastify: FastifyInstance, opts: { dir: string }) {
  let manifest: Promise<Manifest> | undefined
  const getManifest = () => {
    manifest ??= readFile(path.join(opts.dir, "manifest.json"), "utf8").then(JSON.parse)
    return manifest
  }
  const notFound = (reply: FastifyReply) => reply.status(404).send({ error: "Not found" })
  const sendManifest = async (reply: FastifyReply, wanted: (m: Manifest) => boolean) => {
    const m = await getManifest()
    return wanted(m) ? reply.type("application/json").send(JSON.stringify(m)) : notFound(reply)
  }

  fastify.get<{ Params: { version: string } }>(
    "/circuits/by-version/:version/manifest.json",
    (request, reply) => sendManifest(reply, (m) => m.version === request.params.version),
  )
  fastify.get<{ Params: { root: string } }>("/circuits/by-root/:root/manifest.json", (request, reply) =>
    sendManifest(reply, (m) => normaliseHash(m.root) === normaliseHash(request.params.root)),
  )
  fastify.get<{ Params: { file: string } }>("/circuits/by-hash/:file", async (request, reply) => {
    const match = request.params.file.match(/^(0x)?([0-9a-fA-F]+)\.json$/)
    if (!match) return notFound(reply)
    const wanted = normaliseHash(match[2])
    const { circuits } = await getManifest()
    const name = Object.keys(circuits).find((n) => normaliseHash(circuits[n].hash) === wanted)
    if (!name) return notFound(reply)
    try {
      const data = await readFile(path.join(opts.dir, "circuits", `${name}.json`), "utf8")
      return reply.type("application/json").send(data)
    } catch {
      return notFound(reply)
    }
  })
}
