from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class UserSession(Base):
    __tablename__ = 'user_sessions'
    id = Column(Integer, primary_key=True)
    username = Column(String, ForeignKey('users.username'))
    # Stores the device information as a text string
    device_info = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="sessions")
    logged_out = Column(Boolean, default=False)
    ip_address = Column(String, nullable=True)
    token = Column(String)

    def logout(self):
        self.logged_out = True


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    phone_number = Column(String)
    password_hash = Column(String)
    creation_date = Column(DateTime, default=datetime.utcnow)
    # One-to-many relationship with UserSession
    sessions = relationship("UserSession", back_populates="user")

    def get_active_sessions(self, db: UserSession):
        return db.query(UserSession).filter(
            UserSession.username == self.username,
            UserSession.logged_out == False
        ).all()
