from typing import Optional
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class TokenData(BaseModel):
    sub: str
    name: Optional[str] = None
    key: Optional[str] = None
    privilege: Optional[int] = None
    scopes: list[str] = []


class OAuth2ClientCredentialsRequestForm(BaseModel):
    grant_type: str
    scope: str = ""
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
