#
import logging

from fastapi import HTTPException

from app.auth.authentication import AuthHandler
from app.repository.member_repository import MemberRepository
from app.utils.logger import setup_logger

setup_logger()
LOGGER = logging.getLogger(__name__)

class ServiceMember:
    def __init__(self):
        self.member_repository = MemberRepository()
        self.auth_handler = AuthHandler()

    def create_member(self, payload):
        response = self.member_repository.create(payload.dict())
        return response
