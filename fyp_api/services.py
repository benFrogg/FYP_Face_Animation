import database as _database, model as _model, schemas as _schemas
import sqlalchemy.orm as _orm
import passlib.hash as _hash
import jwt as _jwt
import fastapi as _fastapi
import fastapi.security as _security
import os as _os
import time

jwtSecret = "FMsecret"

oauth2schema = _security.OAuth2PasswordBearer(tokenUrl="/token")

def create_database():
    return _database.Base.metadata.create_all(bind=_database.engine)

def get_db():
    db = _database.SessionLocal()
    
    try:
        yield db
    finally:
        db.close()

async def get_user_by_email(email: str, db: _orm.Session):
    return db.query(_model.User).filter(_model.User.email == email).first()

async def create_user(user: _schemas.UserCreate, db: _orm.Session):
    user_obj = _model.User(email=user.email, hashed_password=_hash.bcrypt.hash(user.hashed_password))
    
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    
    return user_obj

async def authenticate_user(email: str, password: str, db: _orm.Session):
    user = await get_user_by_email(db=db, email=email)

    if not user: 
        return False

    if not user.verify_password(password):
        return False

    return user

def token_response(token: str):
    return {
        "access_token": token
    }

async def create_token(user: _model.User) -> dict[str, str]:
    user_obj = _schemas.User.from_orm(user)

    payload = {
        "user_id": user_obj,
        "expiry": time.time() + 600
    }

    token = _jwt.encode(payload, jwtSecret)

    # return dict(access_token=token, token_type="bearer")
    return token_response(token)

async def get_current_user(db: _orm.Session = _fastapi.Depends(get_db), token: str = _fastapi.Depends(oauth2schema)):
    try:
        payload = _jwt.decode(token, jwtSecret, algorithms=["HS256"])
        user = db.query(_model.User).get(payload["id"])
    except:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Email or Password")

    return _schemas.User.from_orm(user)

'''async def get_image(directory_name: str) -> str:
    
    return _os(directory_name)'''

def uploaded_image(imagename, data):
    with open(imagename, 'wb') as i:
        i.write(data)
        print(data)
        
