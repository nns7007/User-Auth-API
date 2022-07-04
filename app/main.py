from asyncio.log import logger
from logging import Logger

from fastapi import Depends, FastAPI, HTTPException

# from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

import models
from database import engine, get_db
from routers import auth
from routers.auth import get_current_user, get_password_hash

# from models import Users
from schemas import User

# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


app = FastAPI()


models.Base.metadata.create_all(bind=engine)
app.include_router(auth.router)


@app.get("/")
async def get_user(db: Session = Depends(get_db)):
    return db.query(models.Users).all()


@app.get("/user/{user_id}")
async def read_user_by_ID(id: int, db: Session = Depends(get_db)):
    user_out = db.query(models.Users).filter(models.Users.id == id).first()
    if user_out is not None:
        return user_out
    raise HTTPException(status_code=404, detail="Not Found")


@app.get("/user")
async def get_users(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    if user is None:
        raise HTTPException(status_code=404, detail="Not Found")

    logger.info(user)
    """return (
        db.query(models.Users)
        .filter(
            models.Users.id == user.get("id"),
        )
        .first()
    )"""
    return {"msg": "User Found"}


@app.post("/")
async def create_user(user: User, db: Session = Depends(get_db)):
    user_info = models.Users()
    user_info.id = user.id
    user_info.username = user.username
    # hashed_password = get_password_hash(user.hashed_password)

    user_info.hashed_password = user.hashed_password

    db.add(user_info)
    db.commit()

    return {
        "status_code": 201,
        "result": "Successfully added the user",
    }


@app.post("/create/user")
async def create_new_user(create_user: User, db: Session = Depends(get_db)):
    create_user_model = models.Users()
    create_user_model.email = create_user.id
    create_user_model.username = create_user.username

    hash_password = get_password_hash(create_user.hashed_password)

    create_user_model.hashed_password = hash_password

    db.add(create_user_model)
    db.commit()


"""def get_current_username(
    credentials: HTTPBasicCredentials = Depends(security),
):
    correct_username = secrets.compare_digest(credentials.username, "Namo")
    correct_password = secrets.compare_digest(credentials.password, "123456")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username"""


"""@app.get("/users")
def read_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    return {"username": credentials.username, "password": credentials.password}"""
