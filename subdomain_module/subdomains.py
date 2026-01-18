import requests
import sys

def get_subdomains(domain):
  
    subdomains = set() #auto remove dupes
    
    print(f"Scanning {domain}...")

    try:  #src 1, hackertarget for speed
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                if "," in line:
                    sub = line.split(',')[0]
                    if domain in sub:
                        subdomains.add(sub)
    except:
        pass #if src one is down

    if not subdomains:  #scr 2, crt.sh
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                for entry in response.json():
                    sub = entry['name_value']
                    if "\n" in sub:
                        for s in sub.split('\n'): subdomains.add(s)
                    else:
                        subdomains.add(sub)
        except:
            pass

    clean_list = [s for s in subdomains if "*" not in s] #remove wildcard results 
    
    return sorted(clean_list)

if __name__ == "__main__":  #cli usage, as the task requires direct cli usage
    if len(sys.argv) > 1:
        results = get_subdomains(sys.argv[1])
        for r in results:
            print(r)
    else:
        print("Usage: python subdomains.py <domain>")
