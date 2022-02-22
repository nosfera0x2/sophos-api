import requests
import sys
import json
import oauth_central 
import configparser

# Import configuration settings
config = configparser.ConfigParser()
config.read('config.ini')
vt_api = config['virustotal']['vt_api']
client_id = config['sophosCentral']['client_id']
client_secret = config['sophosCentral']['client_secret']

jwt, tenant_id, tenant_type, data_region = oauth_central.Authenticate.auth(client_id,client_secret)

def sophosCentral(sha, comment):
    vt = vt_check(sha)

    if vt['response_code'] ==1: 
        if vt['scans']['Sophos']['detected'] == True:
            print("SHA256 already known bad, not adding to Sophos Central")

        else:
            print('SHA detected by other engines, but not Sophos Central. Adding to Sophos Central')
            requestUrl = f"{data_region}/endpoint/v1/settings/blocked-items"
            requestBody = {
                "type": "sha256",
                "properties": {
                    "sha256": f"{sha}"
                },
                "comment": f"{comment}"
                }
            requestHeaders = {
                "Authorization": f'Bearer {jwt}',
                'X-Tenant-ID': f'{tenant_id}'
            }

            r = requests.post(requestUrl, headers=requestHeaders, json=requestBody)

    else:
        print('SHA not known by VirusTotal, adding to Sophos Central')
        requestUrl = f"{data_region}/endpoint/v1/settings/blocked-items"
        requestBody = {
            "type": "sha256",
            "properties": {
                "sha256": f"{sha}"
            },
            "comment": f"{comment}"
            }
        requestHeaders = {
            "Authorization": f'Bearer {jwt}',
            'X-Tenant-ID': f'{tenant_id}'
        }

        r = requests.post(requestUrl, headers=requestHeaders, json=requestBody)

def vt_check(sha):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': f'{vt_api}', 'resource': f'{sha}'}

    r= requests.get(url, params=params)

    if r.status_code == 200:
        j = json.loads(r.text)
        return j

if __name__ == "__main__":

    sha = sys.argv[1]
    comment = sys.argv[2]

    print(f"Searching for SHA {sha}")
    sophosCentral(sha, comment)
    
    