from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

import models
from database import engine, get_db

app = FastAPI()

models.Base.metadata.create_all(bind=engine)


@app.get("/")
async def get_user(db: Session = Depends(get_db)):
    return db.query(models.Users).all()
