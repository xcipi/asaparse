#!/usr/bin/env python3

from ciscoconfparse import CiscoConfParse 
import re
import pprint


class Acl:
    '''ACL class holds whole ACL'''
    
    def __init__(self):
        self.acl_list = []
        self.aclname = ""
        self.ace = []
        self.aces = {}
        self.objects = []
                   
    def append_ace(self,ace,linenum):
        if self.match_extended(ace):
#            print ('### APPENDING EXTENDED ACE')
            (self.ace).append(self.parse_extended(ace,linenum))
#            return self.parse_extended(ace)        
        if self.match_remark(ace):
#            print ('### APPENDIGN REMARK ACL')
            (self.ace).append(self.parse_remark(ace,linenum))
            return self.parse_remark(ace,linenum)

    def match_extended(self,ace_part):
        return re.search('^extended$', ace_part[2])

    def is_object(self,item):
        if re.search('^object',item):  
            return(True)
    
    
    def src_object(self,item):
        if re.search('^object$',item):
            return(True)
            
    def is_host(self,item):
        if item == 'host':
            return(True)
            
    def is_obj(self,item):
        if re.search(r"^(src|dst)_obj",item):
            return('net')
        elif re.search(r"^(src|dst)_port_obj",item):
            return('port')
        else:
            return(False)

    def is_equation(self,item):
        if item in ('eq' , 'gt' , 'lt'):
            return(True)

    def in_list(self, item, list):
        if list == []:
            return(False)
        else:
            for idx, items in enumerate(list):
                if item in items:
                    return(True)
                else:
                    return(False)
        
    def find_objects(self,type):
        '''
        find object items used in acl and return list of them
        type = type of objects to return (net, proto)
        '''
        acl_objects = []
#        print('# hladam typ: ',type, ' v ', self.aces)
        for ace in self.aces:
            for item in self.aces[ace]:
                if self.is_obj(item) == type:
#                    print ('++ object', item,' je spravneho typu...')
                    if not self.in_list(self.aces[ace][item], acl_objects):
#                        print('+++ object',self.aces[ace][item],' nieje duplicitny...')
                        acl_objects.append(self.aces[ace][item])
#                    else: print ('--- object ', self.aces[ace][item],' je duplicitny...')
#                else: print ('-- object ', item,' nam nesedi do kramu...' )
        return(list(set(acl_objects)))
                               
    def parse_extended(self,ace, linenum):
        parsed_acl = {}
        parsed = {'linenum':linenum}
        flags = {'src_is_object':0, 'src_obj':0, 'src_host':0, 'src_done':0, 'dst_obj':0, 'dstport_obj':0, 'dst_host':0, 'src_ip_done':0, 'dst_ip_done':0, 'dst_port_eq':0, 'dst_done':0}
        tmp = ""      
 
        for i, subList in enumerate(ace):
            ace[i] = str(ace[i]).strip()
            if i == 2:
                parsed['acl_type'] = ace[2]
            if i == 3:
#                print('*** PARSING 3: ', ace[3])
                parsed['action'] = ace[3]
            if i == 4:
#                print('*** PARSING 4: ', ace[4])
                if self.is_object(ace[4]):
                    flags['dstport_obj'] = 1
                else:
                    parsed['proto'] = ace[4]
            if i == 5:
#                print('*** PARSING 5: ', ace[5])
                if flags['dstport_obj'] == 1:
#                    print ('dstport_obj == 1 a teda parsed[dst_port_obj] = ', ace[5])
                    parsed['dst_port_obj'] = ace[5]
                elif self.is_object(ace[5]):
#                    print ('nastavujem flag src_obj = 1')
                    flags['src_obj'] = 1 
                elif self.is_host(ace[5]):
#                    print('nastavuje flag src_host = 1')
                    flags['src_host'] = 1
                else:
#                    print ('es=lse parsed[src_ip] = ',ace[5])
                    parsed['src_ip'] = ace[5]
                    flags['src_ip_done'] = 1
                    flags['src_done'] = 1
            if i == 6:
#                print('*** PARSING 6: ', ace[6])
                if flags['src_done'] == 0:
#                    print('src_done == 0')
                    if flags['src_ip_done'] == 1:
#                        print('src_ip_done == 1 a teda parsed[src_mask] = ', ace[6])
                        parsed['src_mask'] = ace[6]
                        flags['src_done'] = 1
                    elif flags['src_obj'] == 1:
#                        print('src_obj == 1 a teda parsed[src_obj] = ', ace[6])
                        parsed['src_obj'] = ace[6]
                        flags['src_done'] = 1
                    elif self.is_object(ace[6]):
                        flags['src_obj'] = 1
                        if self.src_object(ace[6]):
#                            print('nastavujem flag src_is_object')
                            flags['src_is_object'] = 1
                    else:
                        parsed['src_ip'] = ace[6]
#                        print ('inak parsed[src_ip] = ', ace[6])
                        flags['src_ip_done'] = 1
                        flags['src_done'] = 1
                elif self.is_object(ace[6]):
                    flags['dst_obj'] = 1
                elif self.is_host(ace[6]):
                    flags['dst_host'] = 1
                else:
                    parsed['dst_ip'] = ace[6]
                    flags['dst_ip_done'] = 1
                    
            if i == 7:
#                print('*** PARSING 7: ', ace[7])
                if ace[7] == 'log':
                    parsed['adv_action'] = 'log'
                elif ace[4] == 'icmp':
                    parsed['icmp_type'] = ace[7]
                elif flags['src_done'] == 0:
                    parsed['src_obj'] = ace[7]
                    flags['src_ip_done'] = 1
                    flags['src_done'] = 1
                elif flags['dst_obj'] == 1:
                    parsed['dst_obj'] = ace[7]
                    flags['dst_done'] = 1
                elif flags['dst_host'] == 1:
                    parsed['dst_ip'] = ace[7]
                    flags['dst_done'] = 1
                elif self.is_object(ace[7]):
                    flags['dst_obj'] = 1
#                    print('nastavuje dst_obj')
                elif self.is_host(ace[7]):
                    flags['dst_host'] = 1
                elif flags['dst_ip_done'] == 1:
                    parsed['dst_mask'] = ace[7]
                    flags['dst_done'] = 1
                else:
                    parsed['dst_ip'] = ace[7]

            if i == 8:
#                print('*** PARSING 8: ', ace[8])

                if ace[8] == 'log':
                    parsed['adv_action'] = 'log'
                elif self.is_equation(ace[8]):
                    parsed['dst_port_eq'] = ace[8]
                    flags['dst_port_eq'] = 1
                elif flags['dst_obj'] == 1:
                    parsed['dst_obj'] = ace[8]
                    flags['dst_done'] = 1
                elif flags['dst_host'] == 1:
                    parsed['dst_ip'] = ace[8]
                    flags['dst_done'] = 1
                elif self.is_object(ace[8]):
                    flags['dst_obj'] = 1
                elif self.is_host(ace[8]):
                    flags['dst_host'] = 1
                elif flags['dst_ip_done'] == 1:
                    parsed['dst_mask'] = ace[8]
                    flags['dst_done'] = 1
                else:
                    parsed['dst_ip'] = ace[8]

            if i == 9:
#                print('*** PARSING 9: ', ace[9])
                if ace[9] == 'log':
                    parsed['adv_action'] = 'log'
                elif self.is_equation(ace[9]):
                    parsed['dst_port_eq'] = ace[9]
                    flags['dst_port_eq'] = 1
                elif flags['dst_port_eq'] == 1:
                    parsed['dst_port'] = ace[9]
                elif flags['dst_done'] == 0:
                    if flags['dst_obj'] == 1:
                        parsed['dst_obj'] = ace[9]
                        flags['dst_done'] = 1
                    elif flags['dst_host'] == 1:
                        parsed['dst_ip'] = ace[9]
                        flags['dst_done'] = 1
                    elif self.is_object(ace[9]):
                        flags['dst_obj'] = 1
                        print('nastavuje dst_obj')
                    elif self.is_host(ace[9]):
                        flags['dst_host'] = 1
                    elif flags['dst_ip_done'] == 1:
                        parsed['dst_mask'] = ace[9]
                        flags['dst_done'] = 1
                    else:
                        parsed['dst_ip'] = ace[9]
                        flags['dst_done'] = 1
            if i == 10:
#                print('*** PARSING 10: ', ace[10])
                if ace[10] == 'log':
                    parsed['adv_action'] = 'log'
                elif flags['dst_port_eq'] == 1:
                    parsed['dst_port'] = ace[10]
            
            if i == 11:
#                print ('### PARSINT 11: ', ace[11])
                if ace[11] == 'log':
                    parsed['adv_action'] = 'log'
                elif flags['dst_port_eq'] == 1:
                    parsed['dst_port'] = ace[11]

            if i > 11:
                tmp = tmp + ' ' + ace[i]
        parsed_acl[linenum] = parsed
        (self.aces).update(parsed_acl)

    def match_remark(self,ace_part):
        return re.search('^remark$', ace_part[2])

    def parse_remark(self,ace,linenum):
        remark = ""
        parsed_acl = {}
        for i, subList in enumerate(ace):
            if i > 2:
                remark = remark + ' ' +ace[i]         
        parsed = {'linenum':linenum, 'acl_type':ace[2], 'remark':remark}
        parsed_acl[linenum] = parsed
        (self.aces).update(parsed_acl)


def resolve_object(objname):
    '''
    find and parse object by its name
    out: dict: type: OBJTYPE, name: OBJNAME, paramType: PARAMTYPE, parameter:PARAMETER
    r"object (network|port|range) .+$" 
    '''
    
    obj_dict = {}
    obj = cisco_cfg.find_children(r"object (service|network) " + objname + "$")
    if obj: 
        n=0
        for item in obj:
            lineSplit = item.split()
            if n == 0:
                obj_dict['type'] = lineSplit[1]
                obj_dict['name'] = lineSplit[2]
            else:
                if obj_dict['type'] == 'network': 
                    obj_dict['paramType'] = lineSplit[0]
                    obj_dict['IpAddress'] = lineSplit[1]
                    if len(lineSplit)>2:
                        obj_dict['NetMask'] = lineSplit[2]
                elif obj_dict['type'] == 'service':
                    obj_dict['paramType'] = lineSplit[0]
                    obj_dict['proto'] = lineSplit[1]
                    obj_dict['srcdest'] = lineSplit[2]
                    obj_dict['oper'] = lineSplit[3]
                    obj_dict['port'] = lineSplit[4]
            n+=1
        return (obj_dict)
    else:
        return (False)


def resolve_group(grpname):
    '''
    find and parse object group by its name
    r"object-group (network|port|range) .+$" 
    '''
    
    grp_dict = {}
    grp = cisco_cfg.find_children(r"object-group (service|network) " + grpname)
    if grp: 
        n=0
        for item in grp:
            lineSplit = item.split()
#            print(lineSplit)
            if n == 0:
                grp_dict['type'] = lineSplit[1]
                grp_dict['name'] = lineSplit[2]
                if len(lineSplit) == 4: grp_dict['proto'] = lineSplit[3]
            elif grp_dict['type'] == 'network':
                print(lineSplit)
                grp_dict['itemtype'] = lineSplit[1]
                grp_dict['itemname'] = lineSplit[2]
 #               print ('netgrp')
            elif grp_dict['type'] == 'service':
                if lineSplit[0] == 'description':
                    print ('desc')
                elif lineSplit[0] == 'service-object':
                    grp_dict['proto'] = lineSplit[1]
                    if lineSplit[1] == 'icmp':
                        grp_dict['code'] = lineSplit[2]
                    else:
                        grp_dict['srcdst'] = lineSplit[2]
                        grp_dict['oper'] = lineSplit[3]
                        grp_dict['port'] = lineSplit[4]
                elif lineSplit[0] == 'port-object':
                    grp_dict['proto'] = lineSplit[1]
                    grp_dict['srcdst'] = lineSplit[2]
            else: print ('FATAL: Unknown group!!!')
            n+=1
        return (grp_dict)
    else:
        return (False)

#################################################################################################
from argparse import ArgumentParser

if __name__ == '__main__':

    parser = ArgumentParser(description='Select options.')

    # Input parameters
    parser.add_argument('-conf', '--conf', type=str, default='',
                        help="ASA config path/filename")
    parser.add_argument('-aclname', '--aclname', type=str, default='',
                        help="Name of ACL to convert. If empty => convert ALL.")
    parser.add_argument('-conftype', '--conftype', type=str, default='asa',
                        help="Type of config file: asa|ios. Default: asa")
        
    args = parser.parse_args()

    conf_file = args.conf
    inputaclname = args.aclname
    conftype = args.conftype
    
    accessList = []
    accessgroup = []
        
    cisco_cfg = CiscoConfParse(conf_file,syntax=conftype)

#        url = "http://" + host + ":" + port + "/restconf/api/running/"

#        headers = {
#           "Content-Type": "application/vnd.yang.datastore+json",
#           "Accept": "application/vnd.yang.datastore+json",
#           }
#        response = requests.request("GET", url, headers=headers, auth=(username,password))

#    print(response.text)


#        cisco_cfg = CiscoConfParse("../inputs/noc-fw-conf.txt",syntax='asa')

al = cisco_cfg.find_objects(r"^access-list " + inputaclname)
ag = cisco_cfg.find_objects(r"^access-group " + inputaclname)

pp = pprint.PrettyPrinter(indent=4)

final = Acl()
#testgrp = ASAObjGroupNetwork()

for item in ag:
    accessgroup = ((item.text).split(" "))[1]    
    al = cisco_cfg.find_objects(r"access-list " + accessgroup)
    tmp = accessgroup
#    print (tmp)
    final.aclname = re.sub(r"-in", "", tmp, 0)

    for i in al:
        final.append_ace(((i.text).split(" ")),i.linenum)

####################################################################################
#######################  GENERATING OBJECTS ########################################
####################################################################################
    final_objects = []
    acl_objects = []
    print ('# Generating OBJECTS for ACL name: ', final.aclname)
    print ('## SERVICE objects: ', final.find_objects('port'))
    
#    for pgname in final.find_objects('port'):
#        result = resolve_object(pgname)
    result = resolve_object('SERVOBJECT1')
    if result: 
        print ('### Resolved SERVICE objects: ',result)
        acl_objects.append(result)
    
    print ('\n## Network objects: ', final.find_objects('net'))
    for ngname in final.find_objects('net'):
        result = resolve_object(ngname)
        if result: 
            print ('### Resolved NET objects: ',result)
            acl_objects.append(result)
                
    print ('\n# Final objects list: ')
    pp.pprint(acl_objects)
    
    print ('=========================================================\n')
    
    acl_groups = []
    final_groups = []
    
    print ('# Generating groups for ACL name: ', final.aclname)
    print ('## Port groups: ', final.find_objects('port'))
    
    for pgname in final.find_objects('port'):
        result = resolve_group(pgname)
        if result: 
            acl_groups.append(result)
            print ('### Resolved PG',result)
    
    print ('\n## Network groups: ', final.find_objects('net'))
    
    for ngname in final.find_objects('net'):
        result = resolve_group(ngname)
        if result: 
            acl_groups.append(result)
            print ('### Resolved network-groups ',result)
    
    print ('\n# Final object-groups list: ')
    pp.pprint(acl_groups)
    
'''
    object moze obsahovat:
    - network
     - host IP
     - range IP_first IP_last
     - 
    object-group moze obsahovat:
    - network
     - network-object object NAME
     
    - service 
     - service-object PROTO destination eq PORT
'''