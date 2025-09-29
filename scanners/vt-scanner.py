from dotenv import load_dotenv
import os
import vt

# -------------- Load & Config Abuse_API --------------
load_dotenv()

api_key_vt = os.getenv("API_KEY_VT")

if api_key_vt == None:
    raise ValueError("We couldn't find your VT_API_Key - Please check the .env file")

#-------------- Scan & Analysis URL --------------------
def scan_url(url:str) -> dict:
    try:

        with vt.Client(api_key_vt) as client:
            analysis = client.scan_url(url,wait_for_completion=True)
            result = client.get_object(f"/analyses/{analysis.id}")

            data_api_vt =  result.to_dict()["attributes"]["stats"]
            
            return data_api_vt
            
        
    except vt.error.APIError as e:
        return {"Error":f"{e.code} {e.message}" }



# ---------- Main Logic for VT(Virus Total) Scanner ---------
def vt_scanner(url:str) -> dict:
    try:

        pass
            
        
    #More about exceptions: -> https://virustotal.github.io/vt-py/api/client.html#vt.APIError
    except vt.error.APIError as e:
        return {"Error":f"{e.code} {e.message}" }

print(vt_scanner("https://google.com"))