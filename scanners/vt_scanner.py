from dotenv import load_dotenv
import os
import vt
from my_validators import is_valid_file
from my_validators import is_url

# -------------- Load & Config Abuse_API --------------
load_dotenv()

api_key_vt = os.getenv("API_KEY_VT")

if api_key_vt == None:
    raise ValueError("We couldn't find your VT_API_Key - Please check the .env file")

#-------------- Scan & Analysis URL --------------------
def scan_url(url:str) -> dict:
    """Take a url and scan using VT_API to analyze

    Args:
        url (str): Take a url

    Returns:
        dict: return a dict with all results of VT_API.
         Outputs:
            - MALICIOUS
            - SUSPICIOUS
            - UNDETECTED
            - HARMLESS
    """
    try:
        #More about conections -> https://virustotal.github.io/vt-py/quickstart.html
        with vt.Client(api_key_vt) as client:
            analysis_url = client.scan_url(url,wait_for_completion=True)
            result_url = client.get_object(f"/analyses/{analysis_url.id}")

            data_url_vt =  result_url.to_dict()["attributes"]["stats"]

            #Organized data info
            return {
                "MALICIOUS": data_url_vt.get("malicious"),
                "SUSPICIOUS": data_url_vt.get("suspicious"),
                "UNDETECTED": data_url_vt.get("undetected"),
                "HARMLESS": data_url_vt.get("harmless")
            }
        
    except vt.error.APIError as e:
        return {"Error":f"{e.code} {e.message}" }

#------------- Scan & Analysis File ------------------------

def scan_file(file:str) -> dict:
    """Take a file from your computer and scan using VT_API to analyze

    Args:
        file (str): Take a file

    Raises:
        ValueError: analize if a file is empty or exists on the computer

    Returns:
        dict: return a dict with all results of VT_API.
         Outputs:
            - MALICIOUS
            - SUSPICIOUS
            - UNDETECTED
            - HARMLESS
            - TIMEOUT
            - CONFIRMED_TIMEOUT
            - FAILURE
            - UNSUPPORTED
    """
    if not is_valid_file(file):
        raise ValueError({"Error":"Your file doesn't exist or is empty"})

    try:
        with vt.Client(api_key_vt) as client:
            with open(file,"rb") as f:

                analysis_file = client.scan_file(f,wait_for_completion=True)
                result_file = client.get_object(f"/analyses/{analysis_file.id}")

                data_file_vt = result_file.to_dict()["attributes"]["stats"]

                #Organized data info
                return {
                    "MALICIOUS": data_file_vt.get("malicious"),
                    "SUSPICIOUS": data_file_vt.get("suspicious"),
                    "UNDETECTED": data_file_vt.get("undetected"),
                    "HARMLESS": data_file_vt.get("harmless"),
                    "TIMEOUT": data_file_vt.get("timeout"),
                    "CONFIRMED_TIMEOUT": data_file_vt.get("confirmed-timeout"),
                    "FAILURE": data_file_vt.get("failure"),
                    "UNSUPPORTED": data_file_vt.get("type-unsupported")
                    }
    #More about exceptions: -> https://virustotal.github.io/vt-py/api/client.html#vt.APIError
    except vt.error.APIError as e:
        return {"Error":f"{e.code} {e.message}" }



# ---------- Main Logic for VT(Virus Total) Scanner ---------
def vt_scanner(resource:str) -> dict:
    """Take a resource and analize it with file scanner o url scanner

    Args:
        resource (str): Give a resource can be a file or url
    
    Raises:
        ValueError: return an error if the input is not a valid URL or file

    Returns:
        dict: Return a dict but its depend of a type.
         Possible outputs:
            - scan_url: analize an url
            - scan_url: analize a file
    """

    if is_url(resource):
        return scan_url(resource)
    
    if is_valid_file(resource):
        return scan_file(resource)
    

    raise ValueError({"Error":"Your input is neither a valid file nor a valid URL"})

