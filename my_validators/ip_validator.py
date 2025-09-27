import ipaddress



#---------------- Ip Validator ------------------
def is_ip(ip: str) -> bool:
    """Take a ip in str format and validate if is a valid ip or not

    Args:
        ip (str): ip in str format, it's can be IPv4 or IPv6 

    Returns:
        bool: return True if is a valid ip or False if not
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

