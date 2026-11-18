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

export type GetBackend = (devMode: boolean) => ProofBackend

/** One backend per network, created on first use and kept until `close` */
export function sharedBackends(create: (devMode: boolean) => ProofBackend) {
  const backends = new Map<boolean, ProofBackend>()
  return {
    get: ((devMode) => {
      let backend = backends.get(devMode)
      if (!backend) {
        backend = create(devMode)
        backends.set(devMode, backend)
      }
      return backend
    }) as GetBackend,
    async close() {
      const all = [...backends.values()]
      backends.clear()
      await Promise.all(all.map((backend) => backend.close()))
    },
  }
}

type BBVersion = "v5" | "v6"

// Circuits from 0.22.0 on are built with bb 6 (same rule as the SDK)
export function getBBVersionForCircuitVersion(circuitVersion: string): BBVersion {
  const parts = circuitVersion.split("-")[0].split(".").map(Number)
  if (parts.length !== 3 || parts.some(Number.isNaN)) return "v6"
  const [major, minor] = parts
  return major > 0 || minor >= 22 ? "v6" : "v5"
}

export interface LoadedVerifier {
  verifyProof(data: {
    proof: Uint8Array
    publicInputs: string[]
    verificationKey: Uint8Array
  }): Promise<boolean>
  destroy(): Promise<void>
}

export async function loadVerifier(version: BBVersion): Promise<LoadedVerifier> {
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
// list (another circuit, another version) comes from the public registry.
// Meant to live as long as the server: bb instances and vkeys are kept across requests, the
// certificate root is checked every time
export class RegistryProofBackend implements ProofBackend {
  private readonly registry: RegistryClient
  private readonly local?: RegistryClient
  private readonly loadVerifier: (version: BBVersion) => Promise<LoadedVerifier>
  // Only hits are kept: the version comes from the request, so misses are not cached
  private readonly vkeys = new Map<string, Promise<Uint8Array | undefined>>()
  private readonly verifiers = new Map<BBVersion, Promise<LoadedVerifier>>()

  constructor({
    devMode,
    circuitsUrl,
    createClient = createRegistryClient,
    loadVerifier: load = loadVerifier,
  }: {
    devMode: boolean
    circuitsUrl?: string
    createClient?: typeof createRegistryClient
    loadVerifier?: (version: BBVersion) => Promise<LoadedVerifier>
  }) {
    const chain = devMode ? "ethereum_sepolia" : "ethereum"
    this.registry = createClient(chain, {})
    this.local = circuitsUrl ? createClient(chain, circuitUrlOverrides(circuitsUrl)) : undefined
    this.loadVerifier = load
  }

  async isCertificateRootValid(root: bigint): Promise<boolean> {
    try {
      return await this.registry.isCertificateRootValid(root.toString(16))
    } catch (cause) {
      throw new ServiceUnavailableError("Could not check the certificate registry root", { cause })
    }
  }

  private getManifest(client: RegistryClient, version: string) {
    const manifest = client.getCircuitManifest(undefined, { version })
    // The local source only has one version, so a miss there is expected
    return client === this.local ? manifest.catch(() => undefined) : manifest
  }

  private async fetchVkey(name: string, version: string): Promise<Uint8Array | undefined> {
    for (const client of this.local ? [this.local, this.registry] : [this.registry]) {
      const manifest: CircuitManifest | undefined = await this.getManifest(client, version)
      if (!manifest?.circuits[name]) continue
      const circuit = await client.getPackagedCircuit(name, manifest, { validate: true })
      return new Uint8Array(Buffer.from(circuit.vkey, "base64"))
    }
    return undefined
  }

  private getVkey(name: string, version: string): Promise<Uint8Array | undefined> {
    const key = `${name}@${version}`
    let vkey = this.vkeys.get(key)
    if (!vkey) {
      vkey = this.fetchVkey(name, version)
      this.vkeys.set(key, vkey)
      vkey.then(
        (found) => {
          if (!found) this.vkeys.delete(key)
        },
        () => this.vkeys.delete(key),
      )
    }
    return vkey
  }

  private async getVerifier(bbVersion: BBVersion): Promise<LoadedVerifier> {
    let verifier = this.verifiers.get(bbVersion)
    if (!verifier) {
      verifier = this.loadVerifier(bbVersion)
      this.verifiers.set(bbVersion, verifier)
    }
    try {
      return await verifier
    } catch (cause) {
      if (this.verifiers.get(bbVersion) === verifier) this.verifiers.delete(bbVersion)
      throw new ServiceUnavailableError(`Could not load the bb ${bbVersion} verifier`, { cause })
    }
  }

  private async replaceVerifier(bbVersion: BBVersion, broken: LoadedVerifier) {
    const current = this.verifiers.get(bbVersion)
    if (!current || (await current.catch(() => undefined)) !== broken) return
    this.verifiers.delete(bbVersion)
    await broken.destroy().catch(() => {})
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

    let data: Parameters<LoadedVerifier["verifyProof"]>[0]
    try {
      const proofData = getProofData(proof.proof as string, publicInputCount)
      data = {
        proof: Buffer.from(proofData.proof.join(""), "hex"),
        publicInputs: proofData.publicInputs,
        verificationKey: vkey,
      }
    } catch {
      return false
    }

    const bbVersion = getBBVersionForCircuitVersion(version)
    const loaded = await this.getVerifier(bbVersion)
    try {
      return await loaded.verifyProof(data)
    } catch {
      // A shared bb instance can die between requests (the native process exits), so a throw is
      // not proof enough that the proof is bad: retry once on a fresh instance
      await this.replaceVerifier(bbVersion, loaded)
    }
    const fresh = await this.getVerifier(bbVersion)
    try {
      return await fresh.verifyProof(data)
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
