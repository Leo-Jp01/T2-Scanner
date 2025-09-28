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


#------------- AbuseConfidenceScore Rank ----------------

def abuse_confidence_score(abuse_confidence: int) -> str:
    """Return a str that is based in a rank of confidence score.

    Args:
        abuse_confidence (int): Take a int that represent an confidence score

    Returns:
        str: return a str describing risk level  based on the abuse_confidense
        IMPORTANT: THAT SCORE IS PERSONAL AND IS NOT BASED ON VALIDATED SCORES BY ANY ORGANIZATION.
        Possible outputs:
            - MALICIOUS >= 75
            - POTENCIALLY MALICIOUS >= 50 and < 75
            - SUSPICIOUS >= 25 and < 50
            - LOW RISK >= 1 and < 25
            - CLEAN == 0
    """     
    if abuse_confidence >= 75:
        return f"MALICIOUS ({abuse_confidence}%)"
    elif abuse_confidence >= 50:
        return f"POTENCIALLY MALICIOUS ({abuse_confidence}%)"
    elif abuse_confidence >= 25:
        return f"SUSPICIOUS ({abuse_confidence}%)"
    elif abuse_confidence >= 1:
        return f"LOW RISK ({abuse_confidence}%)"
    else:
        return f"CLEAN" 

def get_attack_categories(categories: set[int]) -> str:
    
    attack_categories = {1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",5:"FTP Brute-Force",6:"Ping of Death",
                     7:"Phishing",8:"Fraud VoIP",9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",
                     13:"VPN IP",14:"Port Scan",15:"Hacking",16:"SQL Injection",17:"Spoofing",18:"Brute-Force",
                     19:"Bad Web Bot",20:"Exploited Host",21:"Web App Attack",22:"SSH",23:"IoT Targeted"}



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
        params = {'ipAddress': ip,'maxAgeInDays': '90',"verbose":""}


        response = requests.get(url,params=params,headers=headers,timeout=10)
    

        #All data obtained by api
        if response.status_code == 200:
            data = response.json()
            
        #Organized data info
        data_api = data["data"]


        ip_inf = data_api.get("ipAddress")
        ip_version = data_api.get("ipVersion")
        confidence_score = data_api.get("abuseConfidenceScore")
        country = data_api.get("countryName","Unknown")
        isp = data_api.get("isp","Unknown")
        total_reports = data_api.get("totalReports")
        last_reported = data_api.get("lastReportedAt")

        #categories = data_api.get("reports")

        return {
            "IP": f"{ip_inf} - IPv{ip_version}",
            "Confidence Score": abuse_confidence_score(confidence_score),
            "Country": f"{country} | ISP: {isp}",
            "Total reports": total_reports,
            "Last reported": last_reported,
            #"Categories": categories



        }

    
    #All about requests exceptions -> https://docs.python-requests.org/en/latest/api/
    except requests.exceptions.RequestException():
        return {"Error": "There was an ambiguous exception that occurred while handling your request."}
    except requests.exceptions.ConnectionError():
        return {"Error": "A Connection error occurred."}
    except requests.exceptions.HTTPError():
        return {"Error": "An HTTP error occurred."}
    except requests.exceptions.TooManyRedirects():
        return {"Error": "Too many redirects."}
    except requests.exceptions.Timeout():
        return {"Error": "The request timed out."}
    except requests.exceptions.JSONDecodeError():
        return {"Error": "Couldn’t decode the text into json"}
    


print(abuse_scaner("147.185.133.138"))
