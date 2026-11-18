export type Point = { x: bigint; y: bigint }

export const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

// OPRF_REGISTRATION_PUBLIC_KEY="<x>,<y>". The circuit only checks the DLOG proof against the key it is
// given, so without a pinned k_reg a client could register under a key of its own
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

// CIRCUITS_URL: a base URL with the registry layout, used instead of the public circuit registry
export function getCircuitsUrl(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = env.CIRCUITS_URL?.trim()
  return raw ? raw.replace(/\/+$/, "") : undefined
}
