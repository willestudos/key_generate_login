import logging

from fastapi import APIRouter, Depends, status, Header, HTTPException

from app.auth.authentication import auth_handler
from app.controllers.member_controller import MemberController
from app.schemas.member_schema import MemberSchema
from app.utils.logger import setup_logger

router = APIRouter(prefix='/members')
setup_logger()
LOGGER = logging.getLogger(__name__)


@router.post("/register",
             status_code=status.HTTP_201_CREATED,
             description="create members!"
             )
async def create_user(
        user_payload: MemberSchema,
        service: MemberController = Depends(MemberController)
):
    LOGGER.info(f'Payload create user: {user_payload}')
    return service.create_member(user_payload)
