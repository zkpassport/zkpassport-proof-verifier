import type { FastifyInstance, RouteHandler } from "fastify"
import type { ProofResult } from "@zkpassport/utils"
import {
  getProofData,
  getNumberOfPublicInputs,
  getCommitmentInFromDisclosureProof,
} from "@zkpassport/utils"
import { ZKPassport } from "@zkpassport/sdk"

interface VerifyOprfRequest {
  blinded_unique_identifier: string
  proofs: ProofResult[]
}

interface VerifyOprfResponse {
  verified: boolean
  error?: string
}

// oprf_auth circuit has 3 public inputs: comm_in (1 input) + (x, y) blinded query point (2 outputs)
const OPRF_AUTH_PUBLIC_INPUT_COUNT = 3

export async function verifyOprfRoute(fastify: FastifyInstance) {
  const handler: RouteHandler<{ Body: VerifyOprfRequest; Reply: VerifyOprfResponse }> = async (
    request,
    reply,
  ) => {
    const startedAt = Date.now()
    const log = request.log.child({ route: "verify-oprf-auth" })

    const { blinded_unique_identifier, proofs } = request.body

    // const isDevMode = request.query && (request.query as any).devmode === "true"
    const isDevMode = false;

    log.info(
      { event: "received", proofCount: Array.isArray(proofs) ? proofs.length : null, devMode: isDevMode },
      "verify-oprf-auth request received",
    )

    if (!blinded_unique_identifier || !proofs || !Array.isArray(proofs)) {
      log.warn({ event: "bad_request", reason: "missing_fields" }, "Missing required fields")
      return reply.status(400).send({
        verified: false,
        error: "Missing required fields: blinded_unique_identifier, proofs",
      })
    }

    if (proofs.length !== 5) {
      log.warn(
        { event: "bad_request", reason: "proof_count", proofCount: proofs.length },
        "Unexpected number of subproofs",
      )
      return reply.status(400).send({
        verified: false,
        error: `Expected 5 subproofs (3 base + facematch + oprf_auth), got ${proofs.length}`,
      })
    }

    try {
      // Verify proofs include a facematch and an oprf_auth proof
      const facematchProof = proofs.find((p) => p.name?.startsWith("facematch"))
      const oprfAuthProof = proofs.find(
        (p) => p.name?.startsWith("oprf_auth") || p.name?.startsWith("oprf-auth"),
      )

      if (!facematchProof?.proof) {
        log.warn({ event: "missing_proof", proof: "facematch" }, "Missing required facematch proof")
        return reply.status(400).send({
          verified: false,
          error: "Missing required facematch proof",
        })
      }

      if (!oprfAuthProof?.proof) {
        log.warn({ event: "missing_proof", proof: "oprf_auth" }, "Missing required oprf_auth proof")
        return reply.status(400).send({
          verified: false,
          error: "Missing required oprf_auth proof",
        })
      }

      // Verify blinded_unique_identifier matches oprf_auth public output
      // oprf_auth outputs (x, y) on BabyJubJub as public outputs (indices 1 and 2)
      const oprfAuthData = getProofData(oprfAuthProof.proof, OPRF_AUTH_PUBLIC_INPUT_COUNT)
      const blindedX = BigInt(oprfAuthData.publicInputs[1]).toString(16).padStart(64, "0")
      const blindedY = BigInt(oprfAuthData.publicInputs[2]).toString(16).padStart(64, "0")
      const expectedBlindedId = `0x${blindedX}${blindedY}`

      if (blinded_unique_identifier.toLowerCase() !== expectedBlindedId.toLowerCase()) {
        log.warn(
          { event: "mismatch", check: "blinded_unique_identifier" },
          "blinded_unique_identifier does not match oprf_auth proof output",
        )
        return reply.status(400).send({
          verified: false,
          error: "blinded_unique_identifier does not match oprf_auth proof output",
        })
      }
      const facematchData = getProofData(
        facematchProof.proof,
        getNumberOfPublicInputs(facematchProof.name!),
      )
      const facematchCommIn = getCommitmentInFromDisclosureProof(facematchData)
      const oprfAuthCommIn = BigInt(oprfAuthData.publicInputs[0])

      if (facematchCommIn !== oprfAuthCommIn) {
        log.warn(
          { event: "mismatch", check: "comm_in" },
          "oprf_auth comm_in does not match facematch comm_in",
        )
        return reply.status(400).send({
          verified: false,
          error: "oprf_auth comm_in does not match facematch comm_in",
        })
      }

      // Use ZKPassport SDK to verify all proofs (commitment chain + cryptographic verification).
      log.info({ event: "sdk_verify_start" }, "Running ZKPassport SDK proof verification")
      const zkpassport = new ZKPassport(" ")
      const { verified, queryResultErrors } = await zkpassport.verify({
        proofs,
        // Ignore facematch validation in dev mode
        originalQuery: { facematch: { mode: isDevMode ? "regular" : "strict", passed: true } },
        queryResult: { facematch: { mode: isDevMode ? "regular" : "strict", passed: true } },
        devMode: isDevMode,
      } as any)

      if (!verified) {
        log.warn(
          { event: "verification_failed", durationMs: Date.now() - startedAt, queryResultErrors },
          "SDK reported proof verification failed",
        )
        return reply.status(400).send({
          verified: false,
          error: `Proof verification failed: ${JSON.stringify(queryResultErrors ?? {})}`,
        })
      }

      log.info(
        { event: "verified", durationMs: Date.now() - startedAt },
        "verify-oprf-auth succeeded",
      )
      return reply.send({ verified: true })
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown verification error"
      log.error({ err, event: "error", durationMs: Date.now() - startedAt }, "Proof verification threw")
      return reply.status(400).send({
        verified: false,
        error: message,
      })
    }
  }

  fastify.post<{ Body: VerifyOprfRequest; Reply: VerifyOprfResponse }>("/verify-oprf-auth", handler)
  fastify.post<{ Body: VerifyOprfRequest; Reply: VerifyOprfResponse }>("/oprf/verify", handler)
}
