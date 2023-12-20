from fastapi import HTTPException, Header, Depends, Request, Query
from .models import User, UserSession
from .utils import (
    SERVICES,
    hash_password,
    create_jwt_token,
    verify_jwt_token,
    verify_password,
    invalidate_token,
    redis_client
)
from .database import get_db
from sqlalchemy.orm import Session
from pydantic import BaseModel
import jwt
import httpx
from .schemas import StandardResponse

MAX_SESSIONS = 3


class UserCreate(BaseModel):
    username: str
    phone_number: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class LogoutSessionRequest(BaseModel):
    session_id: int


class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: str


def get_token(authorization: str = Header(None)) -> str:
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        return token
    raise HTTPException(status_code=401, detail="Invalid token")


async def register(user: UserCreate, db: Session = Depends(get_db)) -> StandardResponse:
    # Check if the user with the given username or phone number already exists
    existing_user = db.query(User).filter(
        (User.username == user.username) | (
            User.phone_number == user.phone_number)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username,
        phone_number=user.phone_number,
        password_hash=hashed_password,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    url = SERVICES['userservice'] + "/users"

    # Username to send (assuming user.username is defined elsewhere in your code)
    data = {
        "username": user.username,
        "phone_number": user.phone_number,
    }

    response = httpx.post(url, json=data)

    if response.status_code != 200:
        return StandardResponse(status="error", message="Failed to create user profile")
    return StandardResponse(
        status="success", message="User created successfully", data={"username": user.username}
    )


async def login(request: Request, user: UserLogin, db: Session = Depends(get_db)) -> StandardResponse:
    client_host = request.client.host
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Get device information and IP address from the request
    request_data = await request.json()
    device_info = request_data.get('device_info')
    client_host = request.client.host

    # Check and manage the number of active sessions
    active_sessions = db.query(UserSession).filter(
        UserSession.username == db_user.username,
        UserSession.logged_out == False
    ).order_by(UserSession.created_at.asc()).all()

    if len(active_sessions) >= MAX_SESSIONS:
        # Log out the oldest session if the maximum number of sessions is exceeded
        oldest_session = active_sessions[0]
        db.delete(oldest_session)

    # Create JWT token first before creating a new session
    token_data = {"sub": db_user.id, "username": db_user.username}
    token = create_jwt_token(token_data)

    # Create a new session
    new_session = UserSession(
        username=db_user.username,
        device_info=device_info,
        ip_address=client_host,
        token=token
    )
    db.add(new_session)
    db.commit()  # Commit the transaction to save the session to the database

    return StandardResponse(
        status="success",
        message="Login successful",
        data={
            "access_token": token,
            "token_type": "bearer"
        }
    )


async def delete_user(token: str = Depends(get_token), db: Session = Depends(get_db)) -> StandardResponse:
    # Retrieve the user
    payload = verify_jwt_token(token)
    username = payload.get("username")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Delete the user's sessions
    db.query(UserSession).filter(UserSession.username == username).delete()

    # Invalidate any tokens associated with the user
    # (Assuming you have a way to retrieve all tokens for a user)

    # Send request to another service about user deletion
    url = SERVICES['userservice'] + "/users"  # Adjust URL as needed
    headers = {'Authorization': f'Bearer {token}'}

    # Send a DELETE request to another service about user deletion
    response = httpx.delete(url, headers=headers)

    if response.status_code != 200:
        invalidate_token(token)
        # Delete the user
        db.delete(user)
        db.commit()
        return StandardResponse(status="error", message="Failed to notify external service about user deletion")
    return StandardResponse(status="success", message="User deleted successfully")


async def logout(token: str = Depends(get_token), db: Session = Depends(get_db)) -> StandardResponse:
    try:
        # Decode the token to get the username
        payload = verify_jwt_token(token)
        username = payload.get("username")

        # Retrieve the user based on the username
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Delete the user's session
    user_session = db.query(UserSession).filter(
        UserSession.username == user.username
    ).first()
    if user_session:
        db.delete(user_session)
        invalidate_token(token)
        db.commit()

    return StandardResponse(status="success", message="Successfully logged out")


async def verify_token(token: str = Depends(get_token)) -> StandardResponse:
    if redis_client.get(token):
        raise HTTPException(
            status_code=401,
            detail="Access denied. The provided token is no longer valid and cannot be used for authentication."
        )
    try:
        payload = verify_jwt_token(token)
        return StandardResponse(status="success", message="Token is valid", data={"username": payload.get("username")})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_active_sessions(token: str = Depends(get_token), username: str = Query(...), db: Session = Depends(get_db)) -> StandardResponse:
    # Retrieve the user based on username
    if redis_client.get(token):
        raise HTTPException(
            status_code=401,
            detail="Access denied. The provided token is no longer valid."
        )

    user = db.query(User).filter(User.username == username).first()

    # Check if the user exists
    if not user:
        return StandardResponse(status="error", message="User not found")

    # Retrieve active sessions for the user
    sessions = user.get_active_sessions(db)
    for i in sessions:
        print(i.token)
    # Check if there are no active sessions
    if not sessions:
        return StandardResponse(status="error", message="No active sessions found for the user")

    # Format the sessions data for the response
    sessions_data = [{"session_id": session.id, "device_info": session.device_info,
                      "created_at": session.created_at.isoformat()} for session in sessions]

    return StandardResponse(status="success", message="Active sessions retrieved successfully", data=sessions_data)


async def logout_session(request: LogoutSessionRequest, token: str = Depends(get_token), db: Session = Depends(get_db)) -> StandardResponse:
    if redis_client.get(token):
        raise HTTPException(
            status_code=401,
            detail="Access denied. The provided token is no longer valid."
        )

    session_id = request.session_id

    # Find the session by ID
    session = db.query(UserSession).filter(
        UserSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Invalidate the token of the session
    invalidate_token(session.token)

    # # Update the session as logged out
    session.logout()
    db.commit()

    return StandardResponse(status="success", message="Logged out from the session successfully", data={})


async def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)) -> StandardResponse:
    user = db.query(User).filter(User.username == request.username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(request.current_password, user.password_hash):
        raise HTTPException(
            status_code=400, detail="Incorrect current password")

    # Here, add additional checks for new password strength if needed

    hashed_new_password = hash_password(request.new_password)
    user.password_hash = hashed_new_password
    db.commit()

    return StandardResponse(status="success", message="Password changed successfully")
