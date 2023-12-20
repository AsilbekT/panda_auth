from fastapi import APIRouter
from .views import change_password, delete_user, get_active_sessions, logout_session, register, login, logout, verify_token

router = APIRouter()

# Added path as the first argument
router.add_api_route(path='/register', endpoint=register, methods=["POST"])
router.add_api_route(path='/login', endpoint=login,
                     methods=["POST"])
router.add_api_route(path='/logout', endpoint=logout,
                     methods=["POST"])
router.add_api_route(path='/change-password', endpoint=change_password,
                     methods=["POST"])
router.add_api_route(path='/verify-token',
                     endpoint=verify_token, methods=["GET"])
router.add_api_route(path='/sessions/logout',
                     endpoint=logout_session, methods=["POST"])
router.add_api_route(path='/sessions',
                     endpoint=get_active_sessions, methods=["GET"])
router.add_api_route(path='/delete_user', endpoint=delete_user,
                     methods=["DELETE"])
