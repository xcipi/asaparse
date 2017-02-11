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
    #    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify='../conf/FMC.204.pem')

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

####  for x in pgitems:
        if pgitems[x]:
            tmplist.insert(1, {"type": "ProtocolPortObject","id": pgitems[x]})
    post_data["objects"] = tmplist
    post_data["type"] = "PortObjectGroup"

#################
### OBJECTS: ###
#################

def insert_object(auth_token, server, headers, objname, type, para1 = '', para2 = '', para3 = ''):
    '''
    Insert object of defined type and parameters into FMC:
    
    HOST: 		type = 'Host'				para1 = hostip, 	para2 = hostdesc, 	para3 = ''
    NETWORK:		type = 'Network'			para1 = netip,  	para2 = netdesc,  	para3 = ''
    ICMP:		type = 'ICMPV4Object | ICMPV6Object'	para1 = icmptype, 	para2 = code, 		para3 = ''
    PROTO/PORT:		type = 'ProtocolPortObject'		para1 = proto, 	  	para2 = port, 		para3 = ''
    RANGE:		type = 'Range'				para1 = iprange,	para2 = rangedesc,	para3 = ''
    SECZONES:		type = 'SecurityZone'			para1 = interfaceMode	para2 = interfaces{}	para3 = description
    '''
    import string
    
    print('### Inserting ' + type + ' object into FMC ... ', objname)
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/" + type.lower() + "s"    # param
    
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    post_data = {}

    if type == 'Host':
        post_data = {"type": type, "name": objname, "value": para1, "description": para2}
    elif type == 'Network':
        post_data = {"type": type, "name": objname, "value": para1, "description": para2}
    elif type in ('ICMPV4Object','ICMPV6Object'):
        post_data = {"type": type, "name": objname , "icmpType": para1}
    elif type == 'ProtocolPortObject':
        post_data = {"type": type, "name": objname , "protocol": para1, "port": para2}
    elif type == 'Range':
        post_data = {"type": type, "name": objname , "value": para1, "description": para2}
    elif type == 'SecurityZone':
        tmplist = []            # [{'name':'type'},{'name':'type'}]
        for x in para2:
            if x:
                tmplist.insert(1, {"type": x['type'], "name": x['name']})
                print (tmplist)
        post_data["interfaces"] = tmplist
        post_data["type"] = type
        post_data["name"] = objname
        post_data["description"] = para3
        post_data["interfaceMode"] = para1
    else:
        print ('### ERROR: Unknown object type ... ', type)    

    print ('### INSERTING THIS: \n', json.dumps(post_data, sort_keys=True, indent=4), '\n ### INSERTING HERE: ', url)    
    # print(json.dumps({'4': 5, '6': 7}, sort_keys=True, indent=4))
    try:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        #r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code
        resp = r.text
        json_resp = json.loads(resp)
        if (status_code in (200,201)):
            print(type, " object insert was successful ... error code: ", r.status_code)
#            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            print('Inserted ', type, ' object ID: ', parseJsonError(json_resp, 'id'))
            return(parseJsonError(json_resp, 'id'))
        elif (status_code == 400):
#            error_message = re.sub(regex2,subst,re.sub(regex1,subst, str(json_resp['error']['messages']), 0), 0)
            print('Problem inserting ', type, ' object --> error code 400: ', parseJsonError(json_resp, 'error'))
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

#################
### POLICIES: ###
#################

def insert_policy(auth_token, server, headers, objname, type, para1 = '', para2 = '', para3 = ''):
    '''
    Insert policy of defined type and parameters into FMC:
    
    ACL: 		type = 'AccessPolicy'		para1 = hostip, 	para2 = hostdesc, 	para3 = ''
    '''
    import string
    import re
    
    print('### Inserting ' + type + ' policy into FMC ... ', objname)
#    r"^[a-zA-Z]+(Polic)"
#    if type == 'AccessPolicy':
#        url_part = 'accesspolicies'
    
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/" + re.sub(r"^[a-zA-Z]+(Polic)", "", type, 0)    # param
    
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    post_data = {}

    if type == 'AccessPolicy':
        post_data = {"type": type, "name": objname, "value": para1, "description": para2}
#    elif type == 'Network':
#        post_data = {"type": type, "name": objname, "value": para1, "description": para2}
#    elif type in ('ICMPV4Object','ICMPV6Object'):
#        post_data = {"type": type, "name": objname , "icmpType": para1}
#    elif type == 'ProtocolPortObject':
#        post_data = {"type": type, "name": objname , "protocol": para1, "port": para2}
#    elif type == 'Range':
#        post_data = {"type": type, "name": objname , "value": para1, "description": para2}
#    elif type == 'SecurityZone':
#        tmplist = []            # [{'name':'type'},{'name':'type'}]
#        for x in para2:
#            if x:
#                tmplist.insert(1, {"type": x['type'], "name": x['name']})
#                print (tmplist)
#        post_data["interfaces"] = tmplist
#        post_data["type"] = type
#        post_data["name"] = objname
#        post_data["description"] = para3
#        post_data["interfaceMode"] = para1
#    else:
#        print ('### ERROR: Unknown object type ... ', type)    

    print ('### INSERTING THIS: \n', json.dumps(post_data, sort_keys=True, indent=4), '\n ### INSERTING HERE: ', url)    
    try:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        #r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code
        resp = r.text
        json_resp = json.loads(resp)
        if (status_code in (200,201)):
            print(type, " object insert was successful ... error code: ", r.status_code)
#            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            print('Inserted ', type, ' object ID: ', parseJsonError(json_resp, 'id'))
            return(parseJsonError(json_resp, 'id'))
        elif (status_code == 400):
#            error_message = re.sub(regex2,subst,re.sub(regex1,subst, str(json_resp['error']['messages']), 0), 0)
            print('Problem inserting ', type, ' object --> error code 400: ', parseJsonError(json_resp, 'error'))
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

#############################################################







def insert_portobjectgroup(auth_token, server, headers, pgname, pgitems, objnumber):
    '''
    insert port object group into FMC
    '''
    post_data = {"name": pgname}
    tmpobj_data = {}
    tmplist = []

    print('### Inserting PORT GROUP into FMC ... ', ngname)
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/portobjectgroups"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    for x in pgitems:
         if pgitems[x]:
             tmplist.insert(1, {"type": "ProtocolPortObject","id": pgitems[x]})         
    post_data["objects"] = tmplist
    post_data["type"] = "PortObjectGroup"

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
            print("PORT OBJECT GROUP insert was successful ... error code: ", r.status_code)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            return(parseJsonError(json_resp, 'id'))
        elif (status_code == 400):
            print('Problem inserting PORT OBJECT GROUP --> error code 400: ', parseJsonError(json_resp, 'error'))
        else :
            r.raise_for_status()
            print ("Error occurred in POST --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()

#############################################################

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
         if ngitems[x]:
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
            return(parseJsonError(json_resp, 'id'))
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
    elif what == 'id':
        parsed_response = json_resp['id']
    return(parsed_response)

################################################################################################################################################

def main():
    import random
    import yaml

    config = '../conf/config.yaml'

    print ('### Parsing settings in ', config, '...')
    with open(config, 'r') as yamlfile:
        cfg = yaml.load(yamlfile)
    for section in cfg:
        username = cfg['FMC']['username']
        password = cfg['FMC']['password']
        ipserver = cfg['FMC']['server']
    if len(sys.argv) > 1:
        username = sys.argv[1]
    if len(sys.argv) > 2:
        password = sys.argv[2]

#    result = {}
    server = 'https://' + ipserver 
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}    
    auth_token = get_token(username, password, server, headers)
    headers['X-auth-access-token']=auth_token
    inserted_host = {}
    inserted_net = {}
    inserted_icmp = {}
    ifaces_in_zone = []
    tmp = ''

    print ('### WORKING ... ')
### test host + net objs + netgroups 
    '''
    for i in (1,2,3):
        objnumber = str(random.randrange(1,254))
        hostip = '10.0.0.' + str(objnumber)
        netip = '10.0.' + str(objnumber) + '.0/24'
        hostdesc = 'SKP test object #' + str(objnumber)
        netdesc = 'SKP test NETWORK object # ' + str(objnumber)
        hostname = 'SkpTestHost' + str(objnumber)
        netname = 'SkpTestNet' + str(objnumber)
        
        inserted_host[objnumber] = insert_object(auth_token, server, headers, hostname, 'Host', hostip, hostdesc)
        inserted_net[objnumber] = insert_object(auth_token, server, headers, netname, 'Network', netip, netdesc)

    print ('### Inserted HOSTs: ', inserted_host)
    print('### Inserted NETWORKs: ', inserted_net)
    for x in inserted_host:
        tmp = tmp + '-'+ x

    ngname = 'SkpTestNG' + tmp
    inserted_ng = insert_networkgroup(auth_token, server, headers, ngname, inserted_host, tmp)
    
    if inserted_ng:
        print('### Inserted NG ID: ', inserted_ng)

### test icmp objects + groups
    for i in (0,8):
        inserted_icmp[i] = insert_object(auth_token, server, headers, 'echo_'+str(i), 'ICMPV4Object', i)
    if inserted_icmp:
        print(inserted_icmp)
    '''
   
### test securityzones
#    iftype = 'PhysicalInterface'
#    for x in (1,2,3,4,5):
#        ifname = 'eth' + str(x)
#        print(ifname)
#        ifaces_in_zone.insert(1, {'name':ifname, 'type': iftype})
#        print (ifaces_in_zone)
#    inserted_zone = insert_object(auth_token, server, headers, 'SkpTestZone', 'SecurityZone', 'INLINE', ifaces_in_zone)
    
    print('### DONE ...')
main()
#                tmplist.insert(1, {"type": para2[1], "name": para2[2]})
