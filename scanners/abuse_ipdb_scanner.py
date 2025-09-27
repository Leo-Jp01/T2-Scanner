#Necessary imports 
from dotenv import load_dotenv
import os


# -------------- Load & Config Abuse_API --------------
load_dotenv()

api_key_abuse = os.getenv("API_KEY_ABUSE")
print(api_key_abuse)

if api_key_abuse == None:
    raise ValueError("We couldn't find your Abuse_API_Key - Please check the .env file")


def abuse_scaner() -> dict:
    pass