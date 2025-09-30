from pathlib import Path


#---------------- File Validator ------------------
def is_valid_file(file_user: str) -> bool:
    """Funcion that take the path of a file and return True if the file exists and this is 
       not empty in other case return False

    Args:
        file_user (str): Take the path of a file in str format

    Returns:
        bool: True if the file exists and this is not empty, False in other case.
    """
    
    try:
        file = Path(file_user)

        if not file.exists():
            return False
    
        if file.stat().st_size == 0:
            return False

        return True
    
    except OSError:
        return False
