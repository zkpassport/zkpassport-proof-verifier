import type { CircuitManifest, ProofResult } from "@zkpassport/utils"
import { getProofData } from "@zkpassport/utils"
import { createRegistryClient, type RegistryClient } from "@zkpassport/registry"

/** The check could not run; not a verdict on the proofs */
export class ServiceUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = "ServiceUnavailableError"
  }
}

export interface ProofBackend {
  isCertificateRootValid(root: bigint): Promise<boolean>
  verifyProof(proof: ProofResult, publicInputCount: number): Promise<boolean>
  close(): Promise<void>
}

type BBVersion = "v5" | "v6"

// Circuits from 0.22.0 on are built with bb 6 (same rule as the SDK)
export function getBBVersionForCircuitVersion(circuitVersion: string): BBVersion {
  const parts = circuitVersion.split(".").map(Number)
  if (parts.length !== 3 || parts.some(Number.isNaN)) return "v6"
  const [major, minor] = parts
  return major > 0 || minor >= 22 ? "v6" : "v5"
}

interface LoadedVerifier {
  verifyProof(data: {
    proof: Uint8Array
    publicInputs: string[]
    verificationKey: Uint8Array
  }): Promise<boolean>
  destroy(): Promise<void>
}

async function loadVerifier(version: BBVersion): Promise<LoadedVerifier> {
  const { UltraHonkVerifierBackend, Barretenberg } =
    version === "v5" ? await import("@aztec/bb.js") : await import("@aztec-foundation/bb.js")
  const barretenberg = await Barretenberg.new({ crsPath: "/tmp/.bb-crs" })
  const verifier = new UltraHonkVerifierBackend(barretenberg as any)
  return {
    verifyProof: (data) => verifier.verifyProof(data as any),
    destroy: () => barretenberg.destroy(),
  }
}

export function circuitUrlOverrides(baseUrl: string) {
  const base = baseUrl.replace(/\/+$/, "")
  return {
    circuitManifestUrlGenerator: (
      _chainId: number,
      { root, version }: { root?: string; version?: string },
    ) =>
      root
        ? `${base}/by-root/${root}/manifest.json`
        : `${base}/by-version/${version}/manifest.json`,
    packagedCircuitUrlGenerator: (_chainId: number, hash: string) => `${base}/by-hash/${hash}.json`,
  }
}

// Unlike the SDK, looks every proof up under its own version: a cached base proof can be older
// than a fresh OPRF proof. Circuits served at `circuitsUrl` take precedence; anything they do not
// list (another circuit, another version) comes from the public registry
export class RegistryProofBackend implements ProofBackend {
  private readonly registry: RegistryClient
  private readonly local?: RegistryClient
  private readonly manifests = new Map<string, Promise<CircuitManifest | undefined>>()
  private readonly verifiers = new Map<BBVersion, Promise<LoadedVerifier>>()

  constructor({
    devMode,
    circuitsUrl,
    createClient = createRegistryClient,
  }: {
    devMode: boolean
    circuitsUrl?: string
    createClient?: typeof createRegistryClient
  }) {
    const chain = devMode ? "ethereum_sepolia" : "ethereum"
    this.registry = createClient(chain, {})
    this.local = circuitsUrl ? createClient(chain, circuitUrlOverrides(circuitsUrl)) : undefined
  }

  async isCertificateRootValid(root: bigint): Promise<boolean> {
    try {
      return await this.registry.isCertificateRootValid(root.toString(16))
    } catch (cause) {
      throw new ServiceUnavailableError("Could not check the certificate registry root", { cause })
    }
  }

  private getManifest(client: RegistryClient, version: string) {
    const key = `${client === this.local ? "local" : "registry"}:${version}`
    let manifest = this.manifests.get(key)
    if (!manifest) {
      manifest = client.getCircuitManifest(undefined, { version })
      // The local source only has one version, so a miss there is expected
      if (client === this.local) manifest = manifest.catch(() => undefined)
      this.manifests.set(key, manifest)
    }
    return manifest
  }

  private async getVkey(name: string, version: string): Promise<Uint8Array | undefined> {
    for (const client of this.local ? [this.local, this.registry] : [this.registry]) {
      const manifest = await this.getManifest(client, version)
      if (!manifest?.circuits[name]) continue
      const circuit = await client.getPackagedCircuit(name, manifest, { validate: true })
      return new Uint8Array(Buffer.from(circuit.vkey, "base64"))
    }
    return undefined
  }

  async verifyProof(proof: ProofResult, publicInputCount: number): Promise<boolean> {
    const name = proof.name!
    const version = proof.version!
    let vkey: Uint8Array | undefined
    try {
      vkey = await this.getVkey(name, version)
    } catch (cause) {
      throw new ServiceUnavailableError(`Could not fetch circuit ${name}@${version}`, { cause })
    }
    if (!vkey) return false

    const bbVersion = getBBVersionForCircuitVersion(version)
    let verifier = this.verifiers.get(bbVersion)
    if (!verifier) {
      verifier = loadVerifier(bbVersion)
      this.verifiers.set(bbVersion, verifier)
    }
    let loaded: LoadedVerifier
    try {
      loaded = await verifier
    } catch (cause) {
      this.verifiers.delete(bbVersion)
      throw new ServiceUnavailableError(`Could not load the bb ${bbVersion} verifier`, { cause })
    }
    try {
      const proofData = getProofData(proof.proof as string, publicInputCount)
      return await loaded.verifyProof({
        proof: Buffer.from(proofData.proof.join(""), "hex"),
        publicInputs: proofData.publicInputs,
        verificationKey: vkey,
      })
    } catch {
      return false
    }
  }

  async close(): Promise<void> {
    const verifiers = [...this.verifiers.values()]
    this.verifiers.clear()
    await Promise.all(
      verifiers.map(async (verifier) => {
        try {
          await (await verifier).destroy()
        } catch {
          // already gone
        }
      }),
    )
  }
}
