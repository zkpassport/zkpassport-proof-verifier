export type Point = { x: bigint; y: bigint }

// BN254 scalar field modulus: every public input, and both coordinates of a BabyJubJub point,
// is an element of this field
export const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

/**
 * Public key of the registration OPRF key k_reg, pinned by the operator.
 *
 * The oprf_registration circuit takes the OPRF public key as a public input and only checks the
 * DLOG proof against it, so the oracle MUST pin it: otherwise a client could evaluate the OPRF
 * under a key of its own choosing and register an arbitrary identifier.
 *
 * Set as `OPRF_REGISTRATION_PUBLIC_KEY="<x>,<y>"` (decimal or 0x-prefixed hex).
 */
export function getRegistrationOprfPublicKey(
  env: NodeJS.ProcessEnv = process.env,
): Point | undefined {
  const raw = env.OPRF_REGISTRATION_PUBLIC_KEY?.trim()
  if (!raw) return undefined
  const parts = raw.split(",").map((part) => part.trim())
  if (parts.length !== 2) {
    throw new Error("OPRF_REGISTRATION_PUBLIC_KEY must be formatted as <x>,<y>")
  }
  const [x, y] = parts.map((part) => {
    const value = BigInt(part)
    if (value < 0n || value >= BN254_FR_MODULUS) {
      throw new Error("OPRF_REGISTRATION_PUBLIC_KEY coordinates must be BN254 field elements")
    }
    return value
  })
  return { x, y }
}
