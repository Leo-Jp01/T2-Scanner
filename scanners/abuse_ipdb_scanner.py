#Necessary imports 
from dotenv import load_dotenv
import requests
import os
from my_validators import is_ip


# -------------- Load & Config Abuse_API --------------
load_dotenv()

api_key_abuse = os.getenv("API_KEY_ABUSE")


if api_key_abuse == None:
    raise ValueError("We couldn't find your Abuse_API_Key - Please check the .env file")


# ------------ Main logic for Abuse Scanner --------------
def abuse_scaner(ip:str) -> dict:
    """_summary_

    Args:
        ip (str): _description_

    Raises:
        ValueError: _description_

    Returns:
        dict: _description_
    """
    
    #Validate if the IP is valid before to start
    if not is_ip(ip):
        raise ValueError({"Error": "ip invalid"})
    
    try:
        #Basic config for to realize a GET request
        #All about config and api use: -> https://docs.abuseipdb.com/#configuring-fail2ban
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Accept': 'application/json','Key': api_key_abuse}
        params = {'ipAddress': ip,'maxAgeInDays': '90',"Verbose":""}


        response = requests.get(url,params=params,headers=headers,timeout=10)
    

        #All data obtained by api
        if response.status_code == 200:
            data = response.json()
            return data
    
    #All about requests exceptions -> https://docs.python-requests.org/en/latest/api/
    except requests.exceptions.RequestException():
        return {"Error": "There was an ambiguous exception that occurred while handling your request."}
    except requests.exceptions.ConnectionError():
        return {"Error": "A Connection error occurred."}
    except requests.exceptions.HTTPError():
        return {"Error": "An HTTP error occurred."}
    except requests.exceptions.TooManyRedirects():
        return {"Error": "Too many redirects."}
    except requests.exceptions.ConnectionError():
        return {"Error": "The request timed out while trying to connect to the remote server."}
    except requests.exceptions.ReadTimeout():
        return {"Error": "The server did not send any data in the allotted amount of time."}
    except requests.exceptions.Timeout():
        return {"Error": "The request timed out."}
    except requests.exceptions.JSONDecodeError():
        return {"Error": "Couldn’t decode the text into json"}
    


print(abuse_scaner("8.221.141.254"))
