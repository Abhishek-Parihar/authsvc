import { type JWTPayload } from "jose";
export type TokenClaims = JWTPayload & {
    sub: string;
    tenant_id: string;
    scope?: string;
    client_id?: string;
};
export declare class JwksValidator {
    private jwks;
    private issuer;
    constructor(issuer: string, jwksUrl: string);
    validate(accessToken: string): Promise<TokenClaims>;
}
export type ApiKeyTokenResponse = {
    access_token: string;
    token_type: string;
    expires_in: number;
    scope: string;
};
export declare class ApiKeyClient {
    private tokenUrl;
    private apiKey;
    constructor(tokenUrl: string, apiKey: string);
    exchangeToken(): Promise<ApiKeyTokenResponse>;
}
