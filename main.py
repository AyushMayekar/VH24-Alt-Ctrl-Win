from fastapi import FastAPI, HTTPException, Depends
import uvicorn
from passlib.context import CryptContext
from pymongo import MongoClient
from pydantic import BaseModel, EmailStr, Field
import os 
from dotenv import load_dotenv
import re

load_dotenv()

#* Connecting Database
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['VH-Alt+Ctrl+Win']
users_collection = db['Users']


# FastAPI app instance
app = FastAPI()

# Password encryption setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic model for user input validation
class UserRegister(BaseModel):
    email: EmailStr  # Ensures the email is valid using Pydantic's built-in validation
    password: str = Field(..., min_length=8, max_length=100)  # Password length constraint
    confirm_password: str  # To confirm password


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
        "hashed_password": hashed_password
    }
    users_collection.insert_one(user_data)

    # 6. Return a success message
    return {"message": "User registered successfully!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")