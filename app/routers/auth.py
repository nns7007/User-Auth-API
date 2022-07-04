import sys

sys.path.append("..")

from typing import Dict

import jwt
import models
from database import engine, get_db
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

# from models import Users
# from schemas import User

# from jwt import PyJWT


SECRET_KEY = "yBVOIhsbPlV34HHIBNdnBHJSHY78hjHV2jdhbSJ"
ALGORITHM = "HS256"

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
models.Base.metadata.create_all(bind=engine)

oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")

# app = FastAPI()
router = APIRouter()


def get_password_hash(hashed_password):
    return bcrypt_context.hash(hashed_password)


def verify_password(user_password, hashed_password):
    return bcrypt_context.verify(user_password, hashed_password)


def verify_user(username: str, hashed_password: str, db):
    user = (
        db.query(models.Users)
        .filter(models.Users.username == username)
        .first()
    )

    if not user:
        return False
    if not verify_password(hashed_password, user.hashed_password):
        return False
    return user


def create_access_token(id: int, username: str, hashed_password: str):
    encode = {"user_id": id, "username": username, "password": hashed_password}
    return jwt.encode(encode, SECRET_KEY, ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_bearer)) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("username")
        hashed_password = payload.get("password")
        id = payload.get("user_id")
        if username is None:
            raise HTTPException(status_code=404, detail="User Not Found!!")
        return {
            "user_id": id,
            "username": username,
            "password": hashed_password,
        }
    except JWTError:
        raise HTTPException(status_code=404, detail="User Not Found!!")


@router.post("/token")
async def login_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = verify_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=404, detail="user not found!!")
    token = create_access_token(user.id, user.username, user.hashed_password)
    return {"token": token}
