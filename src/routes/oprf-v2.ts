import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify"
import { z } from "zod"
import type { ProofResult } from "@zkpassport/utils"
import {
  BN254_FR_MODULUS,
  getCircuitsUrl,
  getRegistrationOprfPublicKey,
  type Point,
} from "../oprf-v2/config"
import { verifyFacematchWithSdk } from "../oprf-v2/facematch"
import { RegistryProofBackend, type ProofBackend } from "../oprf-v2/proof-backend"
import {
  MODES,
  verifyBundle,
  type FacematchVerifier,
  type Mode,
} from "../oprf-v2/verify-bundle"

const isObject = (value: unknown) => typeof value === "object" && value !== null

// A BN254 field element as a decimal or 0x-prefixed hex string
const fieldElement = z.string().transform((value, ctx) => {
  let parsed: bigint
  try {
    if (!/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) throw new Error()
    parsed = BigInt(value)
  } catch {
    ctx.addIssue({ code: "custom", message: "Expected a decimal or 0x-prefixed hex number" })
    return z.NEVER
  }
  if (parsed >= BN254_FR_MODULUS) {
    ctx.addIssue({ code: "custom", message: "Not a BN254 field element" })
    return z.NEVER
  }
  return parsed
})

// "0x<x><y>", 32 bytes each: the encoding the node uses for v1 blinded_unique_identifier
const hexPoint = z
  .string()
  .regex(/^0x[0-9a-fA-F]{128}$/, "Expected 0x followed by 64 bytes of hex (x then y)")
  .transform((value): Point => ({
    x: BigInt(`0x${value.slice(2, 66)}`),
    y: BigInt(`0x${value.slice(66)}`),
  }))

/**
 * Request body. Points and field elements use the same JSON encoding as the node's types:
 * I as `SaltedIdentifier` (decimal strings [x, y]), commitment as `AuthCommitment` (decimal string).
 * Which of the optional fields a step needs is checked by `verifyBundle`.
 */
const requestSchema = z.object({
  proofs: z.array(z.custom<ProofResult>(isObject, "Expected an object")).min(1),
  blinded_query: hexPoint.optional(),
  I: z
    .tuple([fieldElement, fieldElement])
    .transform(([x, y]): Point => ({ x, y }))
    .optional(),
  commitment: fieldElement.optional(),
})

interface OprfV2Response {
  verified: boolean
  error?: string
}

export type OprfOptions = {
  /** Fetch circuits from here instead of the public registry (`CIRCUITS_URL`) */
  circuitsUrl?: string
  /** Overrides for tests */
  createBackend?: (devMode: boolean) => ProofBackend
  verifyFacematch?: FacematchVerifier
  registrationPublicKey?: Point
}

/**
 * POST /oprf/v2/{identify,register,query,rotate}: verifies the proof bundle of one OPRF v2
 * protocol step for the OPRF nodes. See `verifyBundle` for what each step checks.
 *
 * 200 `{ verified: true }`; 400 `{ verified: false, error }` when the bundle is rejected; 503 when
 * the check could not run (registry or RPC unreachable), which the nodes retry.
 */
export async function oprfV2Routes(fastify: FastifyInstance, opts: OprfOptions) {
  // Read once at startup so a bad value fails the boot instead of every request
  const circuitsUrl = "circuitsUrl" in opts ? opts.circuitsUrl : getCircuitsUrl()
  const registrationPublicKey =
    "registrationPublicKey" in opts ? opts.registrationPublicKey : getRegistrationOprfPublicKey()
  const createBackend =
    opts.createBackend ??
    ((devMode: boolean) => new RegistryProofBackend({ devMode, circuitsUrl }))
  const verifyFacematch = opts.verifyFacematch ?? verifyFacematchWithSdk

  const handle = async (
    mode: Mode,
    request: FastifyRequest<{ Body: unknown }>,
    reply: FastifyReply,
  ): Promise<OprfV2Response> => {
    const startedAt = Date.now()
    const log = request.log.child({ route: `oprf/v2/${mode}` })
    const devMode = (request.query as any)?.devmode === "true"

    const parsed = requestSchema.safeParse(request.body)
    if (!parsed.success) {
      const error = parsed.error.issues
        .map((issue) => `${issue.path.join(".") || "body"}: ${issue.message}`)
        .join("; ")
      log.warn({ event: "bad_request", error }, "oprf v2 request failed validation")
      return reply.status(400).send({ verified: false, error })
    }
    const body = parsed.data

    log.info(
      {
        event: "received",
        mode,
        proofs: body.proofs.map((p) => `${p.name}@${p.version}`),
        devMode,
      },
      "oprf v2 request received",
    )

    const backend = createBackend(devMode)
    try {
      const verdict = await verifyBundle(
        {
          mode,
          proofs: body.proofs,
          blindedQuery: body.blinded_query,
          registrationId: body.I,
          commitment: body.commitment,
        },
        { backend, registrationPublicKey, verifyFacematch, devMode },
      )
      if (!verdict.verified) {
        const level = verdict.status === 400 ? "warn" : "error"
        log[level](
          { event: "rejected", mode, status: verdict.status, error: verdict.error, durationMs: Date.now() - startedAt },
          "oprf v2 request rejected",
        )
        return reply.status(verdict.status).send({ verified: false, error: verdict.error })
      }
      log.info({ event: "verified", mode, durationMs: Date.now() - startedAt }, "oprf v2 request verified")
      return reply.send({ verified: true })
    } catch (err) {
      log.error({ err, event: "error", durationMs: Date.now() - startedAt }, "oprf v2 request threw")
      return reply.status(500).send({ verified: false, error: "Internal verification error" })
    } finally {
      await backend.close()
    }
  }

  for (const mode of MODES) {
    fastify.post<{ Body: unknown; Reply: OprfV2Response }>(`/oprf/v2/${mode}`, (request, reply) =>
      handle(mode, request, reply),
    )
  }
}
