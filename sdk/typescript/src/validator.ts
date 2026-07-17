export type TokenClaims = {
  sub: string;
  tenant_id: string;
  scope?: string;
  client_id?: string;
};

export class JwksValidator {
  private keys: Map<string, CryptoKey> = new Map();
  private refreshed = 0;

  constructor(
    private issuer: string,
    private jwksUrl: string,
  ) {}

  async validate(accessToken: string): Promise<TokenClaims> {
    await this.refreshKeys();
    const header = JSON.parse(atob(accessToken.split(".")[0]));
    const key = this.keys.get(header.kid);
    if (!key) throw new Error("unknown kid");

    const { payload } = await jwtVerify(accessToken, key, {
      issuer: this.issuer,
      audience: "authsvc",
    });
    return payload as TokenClaims;
  }

  private async refreshKeys(): Promise<void> {
    if (Date.now() - this.refreshed < 300_000 && this.keys.size > 0) return;
    const res = await fetch(this.jwksUrl);
    const body = await res.json();
    for (const k of body.keys) {
      const key = await importJWK({ kty: k.kty, n: k.n, e: k.e, alg: k.alg }, k.alg);
      this.keys.set(k.kid, key);
    }
    this.refreshed = Date.now();
  }
}

// Minimal JWK import helpers (use jose in production apps)
async function importJWK(jwk: JsonWebKey, alg: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
}

async function jwtVerify(token: string, key: CryptoKey, opts: { issuer: string; audience: string }) {
  // Consumers should use the `jose` package; this stub documents the contract.
  void token; void key; void opts;
  throw new Error("Install jose: npm install jose — see README");
}
