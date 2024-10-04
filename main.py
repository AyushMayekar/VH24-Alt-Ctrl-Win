from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import uvicorn
from datetime import timedelta, datetime
from jose import jwt, JWTError
from passlib.context import CryptContext
from pymongo import MongoClient, UpdateOne
from pydantic import BaseModel, EmailStr, Field
import os 
from dotenv import load_dotenv
import re

load_dotenv()

#* Connecting Database
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)  
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client[os.getenv('client')]
users_collection = db[os.getenv('users_collection')]


# FastAPI app instance
app = FastAPI()

# Password encryption setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
secret_key = os.getenv('secret_key')
Algo = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic model for user input validation
class UserRegister(BaseModel):
    email: EmailStr  # Ensures the email is valid using Pydantic's built-in validation
    password: str = Field(..., min_length=8, max_length=100)  # Password length constraint
    confirm_password: str  # To confirm password

class User(BaseModel):
    email: EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})  # Add expiration time to the token
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=Algo)  # Create the JWT
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, secret_key, algorithms=[Algo])  # Decode the JWT
        email: str = payload.get("email")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = users_collection.find_one({"email": token_data.email})  # Fetch user from the database
    if user is None:
        raise credentials_exception
    return user

def get_password_hash(password):
    return pwd_context.hash(password)

def is_email_in_use(email: str):
    return users_collection.find_one({"email": email}) is not None

@app.post("/register/")
async def register_user(user: UserRegister):
    # 1. Check if the two passwords match
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # 2. Check if the email format is correct (this is enforced by Pydantic's EmailStr, but we can manually check again)
    email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_pattern, user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # 3. Check if the email is already registered
    if is_email_in_use(user.email):
        raise HTTPException(status_code=400, detail="Email is already in use")

    # 4. Hash the password
    hashed_password = get_password_hash(user.password)

    # 5. Save the user data into MongoDB
    user_data = {
        "email": user.email,
        "hashed_password": hashed_password,
        "lockout_time": None,
        "is_locked": False,
        "failed_attempts": 0
    }
    users_collection.insert_one(user_data)

    # 6. Return a success message
    return {"message": "User registered successfully!"}


@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})  # Find user by email
    if not user :
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    if user.get("is_locked"):
        lockout_time = user.get("lockout_time", None)
        if lockout_time and datetime.utcnow() < lockout_time + LOCKOUT_DURATION:
            remaining_time = (lockout_time + LOCKOUT_DURATION) - datetime.utcnow()
            raise HTTPException(status_code=403, detail=f"Account locked. Try again in {remaining_time.seconds//60} minutes.")
        else:
            users_collection.update_one(
                {"email": form_data.username},
                {"$set": {"is_locked": False, "failed_attempts": 0, "lockout_time": None}}
            )
    if not verify_password(form_data.password, user['hashed_password']):
        failed_attempts = user.get("failed_attempts", 0) + 1      
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            users_collection.update_one(
                {"email": form_data.username},
                {"$set": {"is_locked": True, "lockout_time": datetime.utcnow()}}
            )
            raise HTTPException(status_code=403, detail="Too many failed login attempts. Account locked for 15 minutes.")
        else:
            users_collection.update_one(
                {"email": form_data.username},
                {"$set": {"failed_attempts": failed_attempts}}
            )
            raise HTTPException(status_code=400, detail=f"Incorrect password. {MAX_FAILED_ATTEMPTS - failed_attempts} attempts left.")
        
    users_collection.update_one(
        {"email": form_data.username},
        {"$set": {"failed_attempts": 0, "is_locked": False, "lockout_time": None}}
    )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"email": user['email']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"} 


@app.get("/users/me", response_model= User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")