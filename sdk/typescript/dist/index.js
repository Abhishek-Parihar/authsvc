import { createRemoteJWKSet, jwtVerify } from "jose";
export class JwksValidator {
    jwks;
    issuer;
    constructor(issuer, jwksUrl) {
        this.issuer = issuer;
        this.jwks = createRemoteJWKSet(new URL(jwksUrl));
    }
    async validate(accessToken) {
        const { payload } = await jwtVerify(accessToken, this.jwks, {
            issuer: this.issuer,
            audience: "authsvc",
        });
        return payload;
    }
}
export class ApiKeyClient {
    tokenUrl;
    apiKey;
    constructor(tokenUrl, apiKey) {
        this.tokenUrl = tokenUrl;
        this.apiKey = apiKey;
    }
    async exchangeToken() {
        const res = await fetch(this.tokenUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ grant_type: "api_key", api_key: this.apiKey }),
        });
        if (!res.ok) {
            throw new Error(`token exchange failed: ${res.status}`);
        }
        return (await res.json());
    }
}
