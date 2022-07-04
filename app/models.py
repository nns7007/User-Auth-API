from sqlalchemy import Column, Integer, String

from database import Base


class Users(Base):
    __tablename__ = "Users"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    hashed_password = Column(String)
