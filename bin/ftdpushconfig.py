#!/usr/bin/env python3

'''
functions to push config to FTD/FMC using API
'''

import json
import sys
import requests
 
server = "https://10.99.3.204"
 
username = "skipi"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = "johnny"
if len(sys.argv) > 2:
    password = sys.argv[2]



def get_token(username, password, server, headers):
    r = None
#    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path

    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    #    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')

        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")
            sys.exit()
        else:
            return(auth_token)
    except Exception as err:
        print ("Error in generating auth token --> "+str(err))
        sys.exit()


def get_auditrecords(auth_token, server, headers): 
#    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
#    headers['X-auth-access-token']=auth_token
 
    api_path = "/api/fmc_platform/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/audit/auditrecords"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
 
    try:
        r = requests.get(url, headers=headers, verify=False)
        #r = requests.get(url, headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()

def get_anyprotocolportobjects(auth_token, server, headers):
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/anyprotocolportobjects"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
 
    try:
        r = requests.get(url, headers=headers, verify=False)
        #r = requests.get(url, headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()

def insert_hostobject(auth_token, server, headers, hostip, hostdesc, hostid, hostname):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"    # param
    
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    post_data = {"type": "Host","value": hostip,"overridable": False,"description": hostdesc,"id": hostid,"name": hostname}

    try:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        #r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code
        resp = r.text
        json_resp = json.loads(resp)
        if (status_code in (200,201,202,203)):
            print("Put was successful ... error code: ", r.status_code)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))

        elif (status_code == 400):
#            error_message = re.sub(regex2,subst,re.sub(regex1,subst, str(json_resp['error']['messages']), 0), 0)
            print('Problem --> error code 400: ', parseJsonError(json_resp))

        else:
            r.raise_for_status()
            print("Error code --> "+str(status_code))
            print("Error occurred in PUT --> "+str(resp))
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()

def insert_networkgroup(auth_token, server, headers):
# ngtype, ngid, ngname):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
 
    post_data = {
      "name": "networkgroup_obj1",
      "objects": [
        {
          "type": "Network",
          "id": "NetworkObjectUUID"
        },
        {
          "type": "Host",
          "id": "HostObjectUUID"
        },
        {
          "type": "Range",
          "id": "RangeObjectUUID"
        }
      ],
      "literals": [
        {
          "type": "Network",
          "value": "1.2.3.0/24"
        },
        {
          "type": "Host",
          "value": "1.2.3.4"
        }
      ],
      "type": "NetworkGroup"
    }
    

    try:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        #r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code
        resp = r.text
        print("Status code is: "+str(status_code))
        json_resp = json.loads(resp)
        if status_code == 201 or status_code == 202:
            print("Put was successful ... error code: ", r.status_code)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        elif (status_code == 400):
            print('Problem --> error code 400: ', parseJsonError(json_resp))
        else :
            r.raise_for_status()
            print ("Error occurred in POST --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()

def parseJsonError(json_resp):
    import re

    subst = ""
    regex1 = r"^\[\{\'.+\'\:\ \'(\<html\>)\ "
    regex2 = r"\<br\>.+"

    return(re.sub(regex2,subst,re.sub(regex1,subst, str(json_resp['error']['messages']), 0), 0))



################################################################################################################################################

def main():
    import random
#    objnumber = str(random.randrange(1,254))

    result = {}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}    

    auth_token = get_token(username, password, server, headers)

    headers['X-auth-access-token']=auth_token

    for objnumber in (34,45,56):
        hostip = '10.0.0.' + objnumber
        hostdesc = 'SKP test object #' + objnumber
        hostname = 'SkpTestHost' + objnumber
        hostid = 'hostObjectUUID' + objnumber
        insert_hostobject(auth_token, server, headers, hostip, hostdesc, hostid, hostname)
        
#    hostip = '10.0.0.1'
#    hostdesc = 'SKP test object #1'
#    hostname = 'SkpTestHost1'
#    hostid = 'hostObjectUUID1'

#    get_auditrecords(auth_token, server, headers)
#    get_anyprotocolportobjects(auth_token, server, headers)
#    insert_hostobject(auth_token, server, headers, hostip, hostdesc, hostid, hostname)

#    insert_networkgroup(auth_token, server, headers) 
    
main()
