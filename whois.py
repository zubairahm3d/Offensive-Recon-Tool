import os

def whois_lookup():
    domain = input("Enter website name: ")

    if "." not in domain:
        print("Error: Please include domain extension like .com, .in, .org")
    else:
        os.system("whois " + domain)
