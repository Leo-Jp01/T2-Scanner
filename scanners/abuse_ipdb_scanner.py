#Necessary imports 
from dotenv import load_dotenv
import requests
import os


# -------------- Load & Config Abuse_API --------------
load_dotenv()

api_key_abuse = os.getenv("API_KEY_ABUSE")

if api_key_abuse == None:
    raise ValueError("We couldn't find your Abuse_API_Key - Please check the .env file")


# ------------ Main logic for Abuse Scanner --------------

def abuse_scaner(ip:str) -> dict:

    #Basic config for to realize a GET request
    #All about config and api use: -> https://docs.abuseipdb.com/#configuring-fail2ban
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Accept': 'application/json','Key': api_key_abuse}
        params = {'ipAddress': ip,'maxAgeInDays': '90',"Verbose":""}


        response = requests.get(url,params=params,headers=headers,timeout=10)
    
        if response.status_code == 200:
            data = response.json()
            return data
    
    #All about requests exceptions -> https://docs.python-requests.org/en/latest/api/
    except requests.exceptions.RequestException():
        return {"Error": "There was an ambiguous exception that occurred while handling your request."}
    except requests.exceptions.ConnectionError():
        return {"Error": "A Connection error occurred."}
    


print(abuse_scaner("8.221.141.254"))