from urllib.parse import urlparse


#---------------- Url Validator ------------------
def is_url(url:str) -> bool:
    """Takes a url in str format and validate it if meets a protocol and host

    Args:
        url (str): Url in str format

    Returns:
        bool: return False if the URL meets a protocol and host in other case False
    """
    
    url_parse = urlparse(url)

    url_scheme = url_parse.scheme
    url_netloc = url_parse.netloc

    return all([url_scheme,url_netloc])


