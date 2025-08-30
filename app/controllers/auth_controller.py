import logging
from datetime import timedelta
from jose import JWTError, jwt

from fastapi import HTTPException, status

from app.auth.authentication import AuthHandler
from app.repository.member_repository import MemberRepository
from app.schemas.oauth_schema import Token
from app.utils.logger import setup_logger
from app.config.settings import settings

setup_logger()
LOGGER = logging.getLogger(__name__)

class AuthenticateController:
    def __init__(self):
        self.member_repository = MemberRepository()
        self.auth_handler = AuthHandler()


    def oauth_login(self, form_data):
        """Login via OAuth 2.0 password grant type"""
        if form_data.grant_type != "password":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported grant type"
            )

        email = form_data.username  # No OAuth, o parâmetro é username, mas usamos email
        password = form_data.password
        requested_scopes = form_data.scope.split() if form_data.scope else []

        # Verificar client_id e client_secret se necessário
        # if form_data.client_id != settings.client_id or form_data.client_secret != settings.client_secret:
        #    raise HTTPException(status_code=401, detail="Invalid client credentials")

        member = self.member_repository.get_member(email)
        if member is None:
            LOGGER.info(f'Email inválido no login OAuth.')
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

        if not self.auth_handler.verify_password(password, member["password"]):
            LOGGER.info(f'Senha inválida no login OAuth.')
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

        # Validar escopos solicitados e determinar quais conceder com base no nível de privilégio
        granted_scopes = self.validate_scopes(requested_scopes, member.get("privilege_level", 1))

        return self.create_oauth_tokens(member, email, granted_scopes)

    def refresh_token(self, refresh_token):
        """Gera um novo access_token usando um refresh_token"""
        try:
            # Decodificar o refresh token
            token_data = self.auth_handler.decode_token(refresh_token)

            # Verificar se é realmente um refresh token
            payload = jwt.decode(refresh_token, self.auth_handler.secret_key, 
                               algorithms=[self.auth_handler.algorithm])
            if payload.get("token_type") != "refresh_token":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token inválido",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Obter usuário associado ao token
            member = self.member_repository.get_member(token_data.sub)
            if not member:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Usuário não encontrado",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Gerar novos tokens
            return self.create_oauth_tokens(
                member, 
                token_data.sub,
                token_data.scopes
            )

        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token inválido",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def validate_scopes(self, requested_scopes, privilege_level):
        """Valida os escopos solicitados com base no nível de privilégio"""
        available_scopes = {
            1: ["read:profile"],  # Nível básico
            2: ["read:profile", "update:profile"],  # Nível intermediário
            3: ["read:profile", "update:profile", "read:admin"],  # Nível avançado
            4: ["read:profile", "update:profile", "read:admin", "write:admin"],  # Admin
            5: ["read:profile", "update:profile", "read:admin", "write:admin", "delete:admin"]  # Super admin
        }

        # Se não houver escopos solicitados, conceda os escopos padrão para o nível de privilégio
        if not requested_scopes:
            return available_scopes.get(privilege_level, available_scopes[1])

        # Verificar quais escopos solicitados podem ser concedidos
        allowed_scopes = available_scopes.get(privilege_level, available_scopes[1])
        granted_scopes = [scope for scope in requested_scopes if scope in allowed_scopes]

        return granted_scopes

    def client_credentials_login(self, form_data):
        """Login via OAuth 2.0 client credentials grant type"""
        if form_data.grant_type != "client_credentials":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported grant type"
            )
        member = self.member_repository.get_member(form_data.client_id)
        if member is None:
            LOGGER.info(f'Email invalido.')
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

        client_id = member.get('email')
        client_secret = member.get('key_member')

        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client ID e Client Secret são obrigatórios"
            )


        if client_id != form_data.client_id or client_secret != form_data.client_secret:
            LOGGER.info(f'Credenciais de cliente inválidas: {client_id}')
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                               detail="Credenciais de cliente inválidas")


        requested_scopes = form_data.scope.split() if form_data.scope else []
        default_scopes = ["read:api", "write:api"]
        granted_scopes = requested_scopes if requested_scopes else default_scopes

        # Criar token para a aplicação cliente
        token_data = {
            "sub": client_id,  # subject é o client_id
            "name": member.get("name"),
            "key": member.get("key_member"),
            "privilege": member.get("privilege_level")
        }

        # Criar access token com tempo de expiração configurado
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = self.auth_handler.create_access_token(
            data=token_data,
            expires_delta=expires_delta,
            scopes=granted_scopes
        )

        # Para client_credentials não fornecemos refresh token por padrão
        LOGGER.info(f'Token OAuth client_credentials gerado para: {client_id}')
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60,  # em segundos
            scope=" ".join(granted_scopes)
        )

    def create_oauth_tokens(self, member, email, scopes=None):
        token_data = {
            "sub": email,
            "name": member.get("name"),
            "key": member.get("key_member"),
            "privilege": member.get("privilege_level")
        }

        # Criar access token com tempo de expiração configurado
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = self.auth_handler.create_access_token(
            data=token_data,
            expires_delta=expires_delta,
            scopes=scopes
        )

        # Criar refresh token
        refresh_token = self.auth_handler.create_refresh_token(data=token_data)

        LOGGER.info(f'Tokens OAuth gerados para: {email}')
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60,  # em segundos
            refresh_token=refresh_token,
            scope=" ".join(scopes) if scopes else ""
        )
