import datetime as _dt
import fastapi as _fastapi
import fastapi.security as _security
import database as _database
import models as _models
import schemas as _schemas
import sqlalchemy.orm as _orm
import passlib.hash as _hash
import jwt as _jwt

oauth2schema = _security.OAuth2PasswordBearer("/api/token")

JWT_SECRET = "TEST"

def get_db():
    db = _database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_user_by_username(username: str, db: _orm.Session):
    return db.query(_models.User).filter(_models.User.username == username).first()

async def create_user(user: _schemas.UserCreate, db: _orm.Session, token: str=_fastapi.Depends(oauth2schema)):
    user_obj = _models.User(username=user.username, hashed_password=_hash.bcrypt.hash(user.hashed_password))
    db.add(user_obj)
    db.commit()

    return user_obj

async def authenticate_user(username: str, password: str, db: _orm.Session):
    user = await get_user_by_username(username, db)

    if not user:
        return False
    
    if not user.verify_password(password):
        return False

    return user

async def create_token(user: _models.User):
    user_obj = _schemas.User.from_orm(user)

    token = _jwt.encode(user_obj.dict(), JWT_SECRET)

    return {"access_token": token, "token_type": "bearer"}

async def get_current_user(token: str = _fastapi.Depends(oauth2schema), db: _orm.Session=_fastapi.Depends(get_db)):
    try:
        payload = _jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = db.query(_models.User).get(payload["id"])
    except:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Username or Password")

    return _schemas.User.from_orm(user)

async def update_user(user: _schemas.User, username: str, password: str, new_username: str, new_password: str, db: _orm.Session):
    if user.username != username:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Username")
    user_obj = await authenticate_user(username, password, db)
    if not user_obj:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Password")    
    if new_username!="":
        user_obj.username = new_username
    if new_password!="":
        user_obj.hashed_password = _hash.bcrypt.hash(new_password)

    db.commit()

async def delete_user(user: _schemas.User, username: str, password: str, db:_orm.Session):
    if user.username != username:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Username")
    user_obj = await authenticate_user(username, password, db)
    if not user_obj:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Password")  

    
    db.delete(user_obj)
    db.commit()

async def create_lead(user: _schemas.User, db:_orm.Session, lead:_schemas.LeadCreate):
    lead = _models.Lead(**lead.dict(), owner_id=user.id)
    db.add(lead)
    db.commit()
    return _schemas.Lead.from_orm(lead)

async def get_leads(user: _schemas.User, db:_orm.Session):
    leads = db.query(_models.Lead).filter_by(owner_id=user.id)

    return list(map(_schemas.Lead.from_orm,leads))

async def _lead_selector(lead_id: int, user: _schemas.User, db:_orm.Session):
    lead = db.query(_models.Lead).filter_by(owner_id=user.id).filter(_models.Lead.id == lead_id).first()

    if lead is None:
        raise _fastapi.HTTPException(status_code=401, detail="Lead dose not exist")

    return lead

async def get_lead(lead_id: int, user: _schemas.User, db:_orm.Session):
    lead = await _lead_selector(lead_id, user, db)

    return _schemas.Lead.from_orm(lead)

async def delete_lead(lead_id: int, user: _schemas.User, db: _orm.Session):
    lead = await _lead_selector(lead_id, user, db)

    db.delete(lead)
    db.commit()

async def update_lead(lead_id: int, lead: _schemas.LeadCreate, user: _schemas.User, db: _orm.Session):
    lead_db = await _lead_selector(lead_id, user, db)

    lead_db.first_name = lead.first_name
    lead_db.last_name = lead.last_name
    lead_db.email = lead.email
    lead_db.company = lead.company
    lead_db.note = lead.note
    lead_db.date_last_updated = _dt.datetime.utcnow()

    db.commit()

    return _schemas.Lead.from_orm(lead_db)