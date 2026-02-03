from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import jwt
from jwt import PyJWKClient
from datetime import datetime
import os
from appwrite.client import Client
from appwrite.services.account import Account


app = FastAPI(title="Auth Backend API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your Flutter app origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Appwrite configuration
APPWRITE_PROJECT_ID = os.getenv("APPWRITE_PROJECT_ID", "YOUR_PROJECT_ID")
APPWRITE_ENDPOINT = os.getenv("APPWRITE_ENDPOINT", "https://cloud.appwrite.io/v1")

# JWT verification using Appwrite's JWKs endpoint
jwks_url = f"{APPWRITE_ENDPOINT}/jwks/{APPWRITE_PROJECT_ID}"

def verify_jwt_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.replace("Bearer ", "")

    client = Client()
    client.set_endpoint(APPWRITE_ENDPOINT)
    client.set_project(APPWRITE_PROJECT_ID)
    client.set_jwt(token)

    account = Account(client)
    return account.get()


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "message": "Auth Backend API is running",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/auth/verify")
async def verify_token(user_data: dict = Depends(verify_jwt_token)):
    """
    Verify JWT token endpoint
    """
    print('user_data',user_data)
    return {
        "verified": True,
        "user_id": user_data.get("userId"),
        "session_id": user_data.get("sessionId")
    }


@app.get("/api/user/info")
async def get_user_info(user_data: dict = Depends(verify_jwt_token)):
    """
    Get user information - Protected endpoint
    """
    print('user_data',user_data)
    return {
        "user_id": user_data.get("userId"),
        "session_id": user_data.get("sessionId"),
        "verified": True,
        "message": "User authenticated successfully via JWT",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/dashboard")
async def get_dashboard_data(user_data: dict = Depends(verify_jwt_token)):
    """
    Get dashboard data - Protected endpoint
    """
    return {
        "user_id": user_data.get("userId"),
        "total_users": 1250,
        "active_sessions": 42,
        "api_calls": 8735,
        "message": "Welcome to your personalized dashboard!",
        "last_updated": datetime.utcnow().isoformat()
    }


@app.get("/api/profile")
async def get_profile(user_data: dict = Depends(verify_jwt_token)):
    """
    Get user profile - Protected endpoint
    """
    return {
        "user_id": user_data.get("userId"),
        "session_id": user_data.get("sessionId"),
        "profile_data": {
            "bio": "Software Developer",
            "location": "San Francisco, CA",
            "joined": "2024-01-15"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
