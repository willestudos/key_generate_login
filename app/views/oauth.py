import logging
from fastapi import APIRouter, Depends, status, Form, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm

from app.controllers.auth_controller import AuthenticateController
from app.schemas.oauth_schema import Token, OAuth2ClientCredentialsRequestForm
from app.utils.logger import setup_logger
from typing import Optional

router = APIRouter(prefix='/oauth')
setup_logger()
LOGGER = logging.getLogger(__name__)

@router.post("/token",
             response_model=Token,
             description="OAuth 2.0 token endpoint"
             )
async def oauth_token(
        form_data: Request,
        service: AuthenticateController = Depends(AuthenticateController)
):
    """Endpoint OAuth 2.0 para obtenção de tokens

    Suporta os seguintes grant types:
    - password: Para autenticação com username/password
    - refresh_token: Para renovar um token expirado
    - client_credentials: Para autenticação de aplicações cliente
    """
    # Ler o corpo da requisição para determinar o grant_type
    body = await form_data.form()
    grant_type = body.get("grant_type")

    if not grant_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O parâmetro grant_type é obrigatório"
        )

    if grant_type == "password":
        # Converter para o formato esperado pelo método oauth_login
        password_form = OAuth2PasswordRequestForm(
            grant_type=grant_type,
            username=body.get("username", ""),
            password=body.get("password", ""),
            scope=body.get("scope", ""),
            client_id=body.get("client_id"),
            client_secret=body.get("client_secret")
        )
        return service.oauth_login(password_form)

    elif grant_type == "refresh_token":
        refresh_token = body.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token é obrigatório para grant_type 'refresh_token'"
            )
        return service.refresh_token(refresh_token)

    elif grant_type == "client_credentials":
        # Converter para o formato esperado pelo método client_credentials_login
        client_creds_form = OAuth2ClientCredentialsRequestForm(
            grant_type=grant_type,
            scope=body.get("scope", ""),
            client_id=body.get("client_id"),
            client_secret=body.get("client_secret")
        )
        return service.client_credentials_login(client_creds_form)

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Grant type '{grant_type}' não suportado"
        )
