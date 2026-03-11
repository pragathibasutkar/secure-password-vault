from fastapi import FastAPI
from supabase import create_client

app = FastAPI()

SUPABASE_URL = "https://aayrdukncfnzdmcchcts.supabase.co"
SUPABASE_KEY = "sb_publishable_lJQoxOT_4NY5WF7FsDvBwA_xk75RNRx"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.get("/")
def home():
    return {"message": "Backend connected to Supabase"}

@app.get("/users")
def get_users():
    response = supabase.table("users").select("*").execute()
    return response.data