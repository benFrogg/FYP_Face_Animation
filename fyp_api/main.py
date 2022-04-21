'''from fastapi import FastAPI, Path
from typing import Optional
from pydantic import BaseModel

app = FastAPI()

users = {
    1: {
        "username": "FMadmin",
        "password": "+34Myojwa"
    }, 
    2: {
        "username": "FMuser1",
        "password": "thisuser1"
    }
}

class Users(BaseModel):
    username: str
    password: str

@app.get("/")
def index():
    return {"username": "Data 1"}

@app.get("/get-users/{users_id}")
def get_users(users_id: int = Path(None, description="The ID of the user selected", gt=0)):
    return users[users_id]

@app.get("/get-by-username/{users_id}")
def get_username(*, users_id: int, username: Optional[str] = None):
    for users_id in users:
        if users[users_id]["username"] == username:
            return users[users_id]
    return {"Data": "Not found"}'''

'''import pydantic
import jwt

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model
from passlib.hash import bcrypt

app = FastAPI()

jwtSalt = 'jwtsecret'

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)

User_Pydantic = pydantic_model_creator(User, name='User')
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)

    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user

@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm=Depends()):
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid username or password')

    user_obj = await User_Pydantic.from_tortoise_orm(user)
    
    token = jwt.encode(user_obj.dict(), jwtSalt)

    return {'access_token' : token, 'token_type' : 'bearer'}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, jwtSalt, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid username or password')

    return await User_Pydantic.from_tortoise_orm(user)

@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic=Depends(get_current_user)):
    return user

@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)

register_tortoise (
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)'''

import fastapi as _fastapi
import fastapi.security as _security
import sqlalchemy.orm as _orm
import shutil as _shutil
import services as _services, schemas as _schemas

from fastapi import UploadFile, File
from typing import List

app = _fastapi.FastAPI()

@app.post("/users")
async def create_user(user: _schemas.UserCreate, db: _orm.Session = _fastapi.Depends(_services.get_db)):
    db_user = await _services.get_user_by_email(user.email, db)

    if db_user:
        raise _fastapi.HTTPException(status_code=400, detail="Email already in use")

    user = await _services.create_user(user, db)

    return await _services.create_token(user)

@app.post("/token")
async def generate_token(form_data: _security.OAuth2PasswordRequestForm = _fastapi.Depends(), db: _orm.Session = _fastapi.Depends(_services.get_db)):
    user = await _services.authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    return await _services.create_token(user)

@app.get("/users/me", response_model=_schemas.User)
async def get_user(user: _schemas.User=_fastapi.Depends(_services.get_current_user)):
    return user

@app.post("/get-image")
async def get_image(file: UploadFile = File(...)):
    '''with open(f'{file.filename}', "wb") as image:
        _shutil.copyfileobj(file.file, image)

    return {"image_name" : file.filename}'''
    image = await file.read()
    _services.uploaded_image(file.filename, image)

    return {"image_name" : file.filename}