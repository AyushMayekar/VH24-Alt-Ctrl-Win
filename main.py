from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, OAuth2AuthorizationCodeBearer
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from datetime import timedelta, datetime
from starlette.requests import Request
from starlette.responses import RedirectResponse
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from jose import jwt, JWTError
from passlib.context import CryptContext
from pymongo import MongoClient, UpdateOne
from pydantic import BaseModel, EmailStr, Field
import os, requests
from dotenv import load_dotenv
import re

load_dotenv()

# FastAPI app instance
app = FastAPI()

# Configure CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

# Prerequisit
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
client_id = os.getenv('GOOGLE_CLIENT_ID')
client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
redirect_uri = "http://localhost:8000/auth/callback"

# Connecting Database
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client[os.getenv('client')]
users_collection = db[os.getenv('users_collection')]


# Password encryption setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
secret_key = os.getenv('secret_key')
Algo = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
oauth2_scheme_1 = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl="https://oauth2.googleapis.com/token"
)

# Redirecting to Google Consent 
@app.get("/auth/google")
async def google_login():
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid email profile"
    )
    return RedirectResponse(url=google_auth_url)

# Redirecting to google auth
@app.get("/auth/callback")
async def google_callback(request: Request, code: str):
    # Exchange authorization code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }

    token_response = requests.post(token_url, data=token_data)
    token_json = token_response.json()
    access_token = token_json.get("access_token")
    id_token_val = token_json.get("id_token")

    if not access_token or not id_token_val:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    try:
        # Verify the ID token
        id_info = id_token.verify_oauth2_token(id_token_val, google_requests.Request(), client_id)
        email = id_info["email"]

        # Check if the user exists in the MongoDB database
        user = users_collection.find_one({"email": email})

        if not user:
            return {"message": "UNSUCCESSFULL"}

        if user:
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"email": email}, expires_delta=access_token_expires
            )
        return RedirectResponse(url='http://127.0.0.1:5500/Modern-Login-master/acess.html')
    

    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ID token")


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

class AdminAccessRequest(BaseModel):
    adminemail: str
    adminpassword: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# creating jwt
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})  # Add expiration time to the token
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=Algo)  # Create the JWT
    return encoded_jwt

# getting user info from db
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

# if the email already exists
def is_email_in_use(email: str):
    return users_collection.find_one({"email": email}) is not None

# register logic
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
        "failed_attempts": 0,
        "admin": False
    }
    users_collection.insert_one(user_data)

    # 6. Return a success message
    return {"message": "User registered successfully!"}

# admin api
@app.post("/admin")
async def admin_access(adminemail: str = Form(...), adminpassword: str = Form(...), form_data: OAuth2PasswordRequestForm = Depends()):
    email_pattern = r'^[a-zA-Z0-9_.+-]+@vcet\.edu\.in$'
    passkey_pattern = r'^Fast.{8}API!11$' # FastabcdefghAPI!11, Fast1234abcdAPI!11, Fastx9B#$k8API!11

    if not re.match(email_pattern, adminemail):
        raise HTTPException(status_code=400, detail="Invalid email format.")

    # Validate passkey pattern
    if not re.match(passkey_pattern, adminpassword):
        raise HTTPException(status_code=400, detail="Invalid passkey format")

    # If both checks pass, return success message
    users_collection.update_one(
                {"email": form_data.username},
                {"$set": {"admin": True}}
            )

    return {
        "detail": "Admin access granted!" 
    }

# login logic
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

# extra route
@app.get("/users/me", response_model= User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")