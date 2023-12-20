# auth_app/database.py

# from sqlalchemy import create_engine
# from sqlalchemy.orm import declarative_base
# from sqlalchemy.orm import sessionmaker
# import os

# POSTGRES_USER = os.getenv("POSTGRES_USER")
# POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
# POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres-service")
# POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
# POSTGRES_DB = os.getenv("POSTGRES_DB", "panda_auth")

# # Construct the DATABASE_URL
# DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

# DATABASE_URL = os.environ.get("DB_CONNECTION_STRING")
DATABASE_URL = "postgresql://asilbek:Asilbek2001@localhost/panda_auth"

# Create a synchronous engine
engine = create_engine(DATABASE_URL, pool_size=20, max_overflow=30)

# Create a session maker class bound to this engine
SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
