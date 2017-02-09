#!/usr/bin/env python3

'''
functions to push config to FTD/FMC using API
'''

import json
import sys
import requests

def get_token(username, password, server, headers):
    '''
    get auth token from FMC using credentials
    '''

    print("### Getting auth token ...")
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
            print("### Auth_token not found. Exiting...")
            sys.exit()
        else:
            return(auth_token)
    except Exception as err:
        print ("### Error in generating auth token --> "+str(err))
        sys.exit()

def get_auditrecords(auth_token, server, headers): 
    '''
    get audit records from FMC
    '''
#    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
#    headers['X-auth-access-token']=auth_token
 
    print ('### Getting audit records ...')
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
    '''
    get any protocol or port object from FMC
    '''
    print('### Getting all protocol and port objects ...')
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

def insert_hostobject(auth_token, server, headers, hostname, hostip, hostdesc = "", hostid = ""):
    '''
    insert defined host object to FMC	
    '''
    print('### Inserting HOST object into FMC ... ', hostname)
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
            print("HOST insert was successful ... error code: ", r.status_code)
#            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            print('Inserted HOST ID: ', parseJsonError(json_resp, 'hostid'))
            return(parseJsonError(json_resp, 'hostid'))
        elif (status_code == 400):
#            error_message = re.sub(regex2,subst,re.sub(regex1,subst, str(json_resp['error']['messages']), 0), 0)
            print('Problem inserting HOST --> error code 400: ', parseJsonError(json_resp, 'error'))
            return(False)
        else:
            r.raise_for_status()
            print("Error code --> "+str(status_code))
            print("Error occurred in PUT --> "+str(resp))
            return(False)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()


def insert_networkgroup(auth_token, server, headers, ngname, ngitems, objnumber):
    '''
    insert network group into FMC
    '''
    post_data = {"name": ngname}
    tmpobj_data = {}
    tmplist = []

    print('### Inserting NETWORK GROUP into FMC ... ', ngname)
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    for x in ngitems:
         tmplist.insert(1, {"type": "Host","id": ngitems[x]})         
    post_data["objects"] = tmplist
    post_data["type"] = "NetworkGroup"

#    print (tmplist)
#    print (json.dumps(post_data))

    try:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        #r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code
        resp = r.text
        print("Status code is: "+str(status_code))
        json_resp = json.loads(resp)
        if status_code == 201 or status_code == 202:
            print("NETWORK GROUP insert was successful ... error code: ", r.status_code)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        elif (status_code == 400):
            print('Problem inserting NETWORK GROUP --> error code 400: ', parseJsonError(json_resp, 'error'))
        else :
            r.raise_for_status()
            print ("Error occurred in POST --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()

def parseJsonError(json_resp, what):
    '''
    fnc for parsing JSON error response from FMC server
    '''
    print('### Parsing JSON response from FMC ... ')    
    import re

    subst = ""
    if what == 'error':
        regex1 = r"^\[\{\'.+\'\:\ \'(\<html\>)\ "
        regex2 = r"\<br\>.+"
        parsed_response = re.sub(regex2,subst,re.sub(regex1,subst, str(json_resp['error']['messages']), 0), 0)
    elif what == 'hostid':
        parsed_response = json_resp['id']
    return(parsed_response)

################################################################################################################################################

def main():
    import random
    import yaml
    
#    

    config = '../conf/config.yaml'

    print ('### Parsing settings in ', config, '...')
    with open(config, 'r') as yamlfile:
        cfg = yaml.load(yamlfile)
    for section in cfg:
        username = cfg['FMC']['username']
        password = cfg['FMC']['password']
        server = cfg['FMC']['server']
    if len(sys.argv) > 1:
        username = sys.argv[1]
    if len(sys.argv) > 2:
        password = sys.argv[2]

#    result = {}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}    
    auth_token = get_token(username, password, server, headers)
    headers['X-auth-access-token']=auth_token
    inserted_host = {}
    tmp = ''
    
    for i in (1,2,3):
        objnumber = str(random.randrange(1,254))
        hostip = '10.0.0.' + str(objnumber)
        hostdesc = 'SKP test object #' + str(objnumber)
        hostname = 'SkpTestHost' + str(objnumber)
#        hostid = 'hostObjectUUID' + str(objnumber)
        inserted_host[objnumber] = insert_hostobject(auth_token, server, headers, hostname, hostip)
        
    print ('### Inserted hosts: ', inserted_host)
    for x in inserted_host:
        tmp = tmp + '-'+ x

    ngname = 'SkpTestNG' + tmp
    inserted_ng = insert_networkgroup(auth_token, server, headers, ngname, inserted_host, tmp)
    
    print('### Inserted NG ID: ', inserted_ng)
        
#    get_auditrecords(auth_token, server, headers)
#    get_anyprotocolportobjects(auth_token, server, headers)
#    insert_hostobject(auth_token, server, headers, hostip, hostdesc, hostid, hostname)
#    insert_networkgroup(auth_token, server, headers, ngname) 
    
main()
