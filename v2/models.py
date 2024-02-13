from sqlalchemy import Column, Integer, String, Boolean
from auth_app.database import Base

class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    is_active = Column(Boolean, default=True)
