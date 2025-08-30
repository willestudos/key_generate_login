from datetime import datetime, timedelta
from typing import Optional, Dict, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from app.config.settings import settings
from app.schemas.oauth_schema import TokenData


class AuthHandler:
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.secret_key = settings.secret_key
        self.algorithm = settings.algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.refresh_token_expire_days = 30  # Default refresh token validity in days

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    def create_access_token(self, data: Dict, expires_delta: Optional[timedelta] = None, scopes: List[str] = None) -> str:
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)

        if scopes:
            to_encode.update({"scopes": scopes})

        to_encode.update({"exp": expire})
        to_encode.update({"iat": datetime.utcnow()})  # Issued at time
        to_encode.update({"token_type": "access_token"})

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(self, data: Dict) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire})
        to_encode.update({"iat": datetime.utcnow()})  # Issued at time
        to_encode.update({"token_type": "refresh_token"})  # Identify token type

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def decode_token(self, token: str) -> TokenData:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            # Verificar se o token não está expirado
            expiration = payload.get("exp")
            if expiration and datetime.utcfromtimestamp(expiration) < datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expirado",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Extrair informações do token
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception

            token_data = TokenData(
                sub=username,
                name=payload.get("name"),
                key=payload.get("key"),
                privilege=payload.get("privilege"),
                scopes=payload.get("scopes", [])
            )
            return token_data

        except JWTError:
            raise credentials_exception

auth_handler = AuthHandler()
