import pydantic

class UserBase(pydantic.BaseModel):
    email: str

class UserCreate(UserBase):
    hash_password: str

    class Config:
        orm_mode = True

class User(UserBase):
    id: int 

    class Config: 
        orm_mode = True
