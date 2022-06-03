import fastapi as _fastapi
import fastapi.security as _security
from typing import List

import sqlalchemy.orm as _orm
import services as _services
import schemas as _schemas

app = _fastapi.FastAPI()

@app.post("/api/users")
async def create_user(user: _schemas.UserCreate, db: _orm.Session = _fastapi.Depends(_services.get_db)):
    db_user = await _services.get_user_by_username(user.username, db)
    if db_user:
        raise _fastapi.HTTPException(status_code=400, detail="Username already exists")
    
    await _services.create_user(user, db)

    return await _services.create_token(user)

@app.post("/api/token")
async def generate_token(form_data: _security.OAuth2PasswordRequestForm = _fastapi.Depends(), db: _orm.Session = _fastapi.Depends(_services.get_db)):
    user = await _services.authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise _fastapi.HTTPException(status_code=401, detail="invalid Credentials")

    return await _services.create_token(user)

@app.get("/api/users/me", response_model=_schemas.User)
async def get_user(user: _schemas.User = _fastapi.Depends(_services.get_current_user)):
    return user

@app.put("/api/users/update")
async def update_user(username: str, password: str, new_username: str="", new_password: str="", user: _schemas.User = _fastapi.Depends(_services.get_current_user), db: _orm.Session = _fastapi.Depends(_services.get_db)):
    await _services.update_user(user, username, password, new_username, new_password, db)
    return {"message": "Successfully Updated"}

@app.delete("/api/users/deleete")
async def delete_user(username: str, password: str, user: _schemas.User = _fastapi.Depends(_services.get_current_user), db: _orm.Session = _fastapi.Depends(_services.get_db)):
    return await _services.delete_user(user, username, password, db)
    return {"message": "Successfully Deleted"}

@app.post("/api/leads", response_model=_schemas.Lead)
async def create_lead(lead: _schemas.LeadCreate, user: _schemas.User=_fastapi.Depends(_services.get_current_user), db:_orm.Session=_fastapi.Depends(_services.get_db)):
    return await _services.create_lead(user, db, lead)

@app.get("/api/leads", response_model=List[_schemas.Lead])
async def get_leads(user: _schemas.User=_fastapi.Depends(_services.get_current_user), db:_orm.Session=_fastapi.Depends(_services.get_db)):
    return await _services.get_leads(user, db)

@app.get("/api/leads/{lead_id}", status_code=200)
async def get_lead(lead_id: int, user: _schemas.User=_fastapi.Depends(_services.get_current_user), db:_orm.Session=_fastapi.Depends(_services.get_db)):
    return await _services.get_lead(lead_id, user, db)

@app.delete("/api/leads/{lead_id}", status_code=204)
async def delete_lead(lead_id: int, user: _schemas.User=_fastapi.Depends(_services.get_current_user), db:_orm.Session=_fastapi.Depends(_services.get_db)):
    await _services.delete_lead(lead_id, user, db)
    return {"message": "Successfully Deleted"}

@app.put("/api/leads/{lead_id}", status_code=204)
async def update_lead(lead_id: int, lead: _schemas.LeadCreate, user: _schemas.User=_fastapi.Depends(_services.get_current_user), db:_orm.Session=_fastapi.Depends(_services.get_db)):
    await _services.update_lead(lead_id, lead, user, db)
    return {"message", "Successfully Updated"}