import sqlalchemy as sql
import sqlalchemy.orm as orm
import passlib.hash as hash
import database as db

class User(db.Base):
    __tablename__ = "users"
    id = sql.Column(sql.Integer, primary_key=True, index=True)
    email = sql.Column(sql.String, unique=True, index=True)
    hashed_password = sql.Column(sql.String)

    def verify_password(self, password: str):
        return hash.bcrypt.verify(password, self.hashed_password)
        