import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export type TokenClaims = JWTPayload & {
  sub: string;
  account_id: string;
  website_id?: string;
  scope?: string;
  client_id?: string;
};

export class JwksValidator {
  private jwks: ReturnType<typeof createRemoteJWKSet>;
  private issuer: string;

  constructor(issuer: string, jwksUrl: string) {
    this.issuer = issuer;
    this.jwks = createRemoteJWKSet(new URL(jwksUrl));
  }

  async validate(accessToken: string): Promise<TokenClaims> {
    const { payload } = await jwtVerify(accessToken, this.jwks, {
      issuer: this.issuer,
      audience: "authsvc",
    });
    return payload as TokenClaims;
  }
}

export type ApiKeyTokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
};

export class ApiKeyClient {
  constructor(
    private tokenUrl: string,
    private apiKey: string,
  ) {}

  async exchangeToken(): Promise<ApiKeyTokenResponse> {
    const res = await fetch(this.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ grant_type: "api_key", api_key: this.apiKey }),
    });
    if (!res.ok) {
      throw new Error(`token exchange failed: ${res.status}`);
    }
    return (await res.json()) as ApiKeyTokenResponse;
  }
}
