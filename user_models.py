from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime
from user_database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    
    email = Column(String(255), unique=True, index=True, nullable=False)
    phone = Column(String(20), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    
    client_id = Column(String(50), unique=True, index=True, nullable=True)
    client_secret_hash = Column(String(255), nullable=True)
    
    registration_date = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=False)