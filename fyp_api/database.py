import sqlalchemy as sql
import sqlalchemy.ext.declarative as decl
import sqlalchemy.orm as orm

DB_URL = "sqlite:///./database.db"

engine = sql.create_engine(DB_URL, connect_args={"check_same_thread": False})

SessionLocal = orm.sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = decl.declarative_base()
