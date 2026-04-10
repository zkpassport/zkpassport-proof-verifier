import type { FastifyInstance } from "fastify"
import type { ProofResult } from "@zkpassport/utils"
import { getProofData } from "@zkpassport/utils"
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
  fastify.post<{
    Body: VerifyOprfRequest
    Reply: VerifyOprfResponse
  }>("/oprf/verify", async (request, reply) => {
    const { blinded_unique_identifier, proofs } = request.body

    if (!blinded_unique_identifier || !proofs || !Array.isArray(proofs)) {
      return reply.status(400).send({
        verified: false,
        error: "Missing required fields: blinded_unique_identifier, proofs",
      })
    }

    if (proofs.length !== 5) {
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
        return reply.status(400).send({
          verified: false,
          error: "Missing required facematch proof",
        })
      }

      if (!oprfAuthProof?.proof) {
        return reply.status(400).send({
          verified: false,
          error: "Missing required oprf_auth proof",
        })
      }

      // Verify blinded_unique_identifier matches oprf_auth public output
      // oprf_auth outputs (x, y) on BabyJubJub as public outputs (indices 1 and 2)
      const oprfAuthData = getProofData(oprfAuthProof.proof, OPRF_AUTH_PUBLIC_INPUT_COUNT, 4)
      const blindedX = BigInt(oprfAuthData.publicInputs[1]).toString(16).padStart(64, "0")
      const blindedY = BigInt(oprfAuthData.publicInputs[2]).toString(16).padStart(64, "0")
      const expectedBlindedId = `0x${blindedX}${blindedY}`

      if (blinded_unique_identifier.toLowerCase() !== expectedBlindedId.toLowerCase()) {
        return reply.status(400).send({
          verified: false,
          error: "blinded_unique_identifier does not match oprf_auth proof output",
        })
      }

      // Use ZKPassport SDK to verify all proofs (commitment chain + cryptographic verification)
      const zkpassport = new ZKPassport("localhost")
      const { verified } = await zkpassport.verify({
        proofs,
        queryResult: {},
      } as any)

      if (!verified) {
        return reply.status(400).send({
          verified: false,
          error: "Proof verification failed",
        })
      }

      return reply.send({ verified: true })
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown verification error"
      fastify.log.error(err, "Proof verification failed")
      return reply.status(400).send({
        verified: false,
        error: message,
      })
    }
  })
}
