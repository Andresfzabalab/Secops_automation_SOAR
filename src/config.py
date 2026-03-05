from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("VT_API_KEY")

if api_key is None:
    raise ValueError("VT_API_KEY is missing. Check your .env file.")