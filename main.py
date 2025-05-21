# /login endpoint 
# username & password 
# return JWT token
# store the username and password in memory with password hashing
# store the token in memory with token expiration
# Use dependency injection for cleaner FastAPI design

# POST /login

# json
# { "username": "admin", "password": "secret" }
# Response:
# json
# { "token": "eyJhbGciOiJIUz..." }

#/data endpoint
# GET /data with Authorization header:

# Authorization: Bearer eyJhbGciOiJIUz...

# Response:

# json

# { "message": "Secure data" }


from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel

# App and Security Setup
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = "supersecretkey"  # Use env var in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# User Database (in-memory)
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("secret")
    }
}

# Pydantic Models
class Token(BaseModel):
    token: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str

# Auth Helper Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return User(username=username)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Dependency: Get current user from JWT token
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return User(username=username)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# POST /login
@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"token": token}

# GET /data - Protected route
@app.get("/data")
def get_data(current_user: User = Depends(get_current_user)):
    return {"message": f"Secure data for {current_user.username}"}
