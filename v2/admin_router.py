# admin_router.py
from fastapi import APIRouter, Depends, HTTPException
from starlette import status

from sqlalchemy.orm import Session
from pydantic import BaseModel
from auth_app.database import get_db
from auth_app.utils import verify_password, create_jwt_token, hash_password
from auth_app.schemas import StandardResponse
import httpx
from .models import AdminUser

router = APIRouter()

class AdminLogin(BaseModel):
    username: str = None
    password: str = None

class AdminRegister(BaseModel):
    username: str
    password: str
    password2: str

async def verify_superuser(admin_credentials: AdminLogin) -> (bool, dict):
    # URL of the external service that verifies superuser tokens
    verify_url = "https://gateway.pandatv.uz/analitics/login/"
    data = {
        "username": admin_credentials.username,
        "password": admin_credentials.password
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(verify_url, json=data)

        if response.status_code == 200:
            user_info = response.json()
            return True, user_info  # Token is valid, return user info
        else:
            return False, {}  # Token is invalid
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while verifying token: {str(e)}")

@router.post("/v2/admin/login")
async def admin_login(admin_credentials: AdminLogin, db: Session = Depends(get_db)) -> StandardResponse:
    # Check for superuser token
    if not (admin_credentials.username and admin_credentials.password):
        raise HTTPException(status_code=400, detail="Missing username or password")

    is_valid, superuser_info = await verify_superuser(admin_credentials)

    if is_valid:
        return StandardResponse(
            status="success",
            message="Superuser login successful",
            data={"access_token": superuser_info['token'], "token_type": "Token"}
        )


    admin_user = db.query(AdminUser).filter(AdminUser.username == admin_credentials.username).first()
    if not admin_user or not verify_password(admin_credentials.password, admin_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"sub": admin_user.id, "username": admin_user.username, "is_admin": True}
    token = create_jwt_token(token_data)
    return StandardResponse(
        status="success",
        message="Admin login successful",
        data={"access_token": token, "token_type": "bearer"}
    )


@router.post("/v2/admin/register", status_code=status.HTTP_201_CREATED)
async def admin_register(admin_data: AdminRegister, db: Session = Depends(get_db)) -> StandardResponse:
    if db.query(AdminUser).filter(AdminUser.username == admin_data.username).first():
        raise HTTPException(status_code=400, detail="Admin username already exists")
    if admin_data.password != admin_data.password2:
        raise HTTPException(status_code=400, detail="Admin passwords don't match")

    hashed_password = hash_password(admin_data.password)
    new_admin = AdminUser(username=admin_data.username, password_hash=hashed_password)
    db.add(new_admin)
    db.commit()

    return StandardResponse(
        status="success",
        message="Admin registered successfully",
        data={"username": admin_data.username}
    )
