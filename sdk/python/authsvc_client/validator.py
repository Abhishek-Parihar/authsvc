"""authsvc Python client — JWKS token validation."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

import jwt
import requests
from jwt import PyJWKClient


@dataclass
class TokenClaims:
    sub: str
    tenant_id: str
    scope: str | None = None
    client_id: str | None = None


class JwksValidator:
    def __init__(self, issuer: str, jwks_url: str) -> None:
        self.issuer = issuer
        self.jwks_url = jwks_url
        self._client = PyJWKClient(jwks_url, cache_keys=True)
        self._refreshed = 0.0

    def validate(self, access_token: str) -> TokenClaims:
        signing_key = self._client.get_signing_key_from_jwt(access_token)
        payload: dict[str, Any] = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            audience="authsvc",
            issuer=self.issuer,
        )
        return TokenClaims(
            sub=payload["sub"],
            tenant_id=payload["tenant_id"],
            scope=payload.get("scope"),
            client_id=payload.get("client_id"),
        )

    def auth_header(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}
