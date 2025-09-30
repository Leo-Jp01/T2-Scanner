from scanners import abuse_scaner
from scanners import vt_scanner
import argparse

def show_results(results: dict) -> None:
    """_summary_

    Args:
        results (_type_): _description_
    """
    print("--------T2-SCANNER--------\n")
    for key,value in results.items():
        print(f"{key}:{value}")

def main():
    """_summary_
    """

    parser = argparse.ArgumentParser(prog="T2-Scanner",description="T2-Scanner (Threat Tool) is a tool for defensive cibersecurity " \
    "with the intention of providing that first look at potential real attack points, "
    "(IP Address, File,Url) with the ability to deliver precise information using the API of well-known and respected cibersecurity " \
    "companies such as VirusTotal and AbuseIPDB")

    parser.add_argument("-i",type=str,help="analyze an IP address using AbuseIPDB")
    parser.add_argument("-u",type=str,help="analyze an url using VirusTotal")
    parser.add_argument("-f",type=str,help="analyze an file using VirusTotal")
    args = parser.parse_args() 

    try:
        if args.i:
            result_ip = abuse_scaner(args.i)
            show_results(result_ip)
        if args.u:
            result_url = vt_scanner(args.u)
            show_results(result_url)
        if args.f:
            result_file = vt_scanner(args.f)
            show_results(result_file)
        else:
            print("")
        
    #
    except ValueError as e:
        print(e.args[0]["Error"])

if __name__ == "__main__":
    main()