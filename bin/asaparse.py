#!/usr/bin/env python3



from ciscoconfparse import CiscoConfParse 
import re

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
#        print ('!!!!!!!!!!!!! Vstupujem do find_obj')
        acl_objects = []
#        print (type)
        for ace in self.aces:
            for item in self.aces[ace]:
#                print('########################\nPrva cast podmienky: ', self.is_obj(item))
                if self.is_obj(item) == type:
                    if not self.in_list(self.aces[ace][item], acl_objects):
#                        print('##############\n druha cast: ', self.in_list(self.aces[ace][item], acl_objects))
#                        print ('### APPENDING ', self.aces[ace][item], ' in list\n')
                        acl_objects.append(self.aces[ace][item])
#                        print (acl_objects)
#                    else:
#                        print ('### vyzera ze je v liste')
#                else:
#                    print('### NBIEJE objekt NET')
#                print ('\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        return(list(set(acl_objects)))
                               
    def parse_extended(self,ace, linenum):
#        print ("### parsing extended ACE ", linenum)  
        parsed_acl = {}
        parsed = {'linenum':linenum}
        flags = {'src_obj':0, 'src_host':0, 'src_done':0, 'dst_obj':0, 'dstport_obj':0, 'dst_host':0, 'src_ip_done':0, 'dst_ip_done':0, 'dst_port_eq':0}
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
                    parsed['dst_port_obj'] = ace[5]
                elif self.is_object(ace[5]):
                    flags['src_obj'] = 1 
                elif self.is_host(ace[5]):
                    flags['src_host'] = 1
                else:
                    parsed['src_ip'] = ace[5]
                    flags['src_ip_done'] = 1
                    flags['src_done'] = 1
            if i == 6:
 #               print('*** PARSING 6: ', ace[6])
                if flags['src_done'] == 0:
                    if flags['src_ip_done'] == 1:
                        parsed['src_mask'] = ace[6]
                    if flags['src_obj'] == 1:
                        parsed['src_obj'] = ace[6]
                    else:
                        parsed['src_ip'] = ace[6]
                elif self.is_object(ace[6]):
                    flags['dst_obj'] = 1
                elif self.is_host(ace[6]):
                    flags['dst_host'] = 1
                else:
                    parsed['dst_ip'] = ace[6]
                    flags['dst_ip_done'] = 1
                    
            if i == 7:
 #               print('*** PARSING 7: ', ace[7])
                if ace[7] == 'log':
                    parsed['adv_action'] = 'log'
                elif ace[4] == 'icmp':
                    parsed['icmp_type'] = ace[7]
                elif flags['dst_obj'] == 1:
                    parsed['dst_obj'] = ace[7]
                elif flags['dst_host'] == 1:
                    parsed['dst_ip'] = ace[7]
                elif self.is_object(ace[7]):
                    flags['dst_obj'] = 1
                elif self.is_host(ace[7]):
                    flags['dst_host'] = 1
                elif flags['dst_ip_done'] == 1:
                    parsed['dst_mask'] = ace[7]
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
                elif flags['dst_host'] == 1:
                    parsed['dst_ip'] = ace[8]
                elif self.is_object(ace[8]):
                    flags['dst_obj'] = 1
                elif self.is_host(ace[8]):
                    flags['dst_host'] = 1
                elif flags['dst_ip_done'] == 1:
                    parsed['dst_mask'] = ace[8]
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
                elif flags['dst_obj'] == 1:
                    parsed['dst_obj'] = ace[9]
                elif flags['dst_host'] == 1:
                    parsed['dst_ip'] = ace[9]
                elif self.is_object(ace[9]):
                    flags['dst_obj'] = 1
                elif self.is_host(ace[9]):
                    flags['dst_host'] = 1
                elif flags['dst_ip_done'] == 1:
                    parsed['dst_mask'] = ace[9]
                else:
                    parsed['dst_ip'] = ace[9]

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


from argparse import ArgumentParser

if __name__ == '__main__':

    parser = ArgumentParser(description='Select options.')

    # Input parameters
    parser.add_argument('-conf', '--conf', type=str, required=True,
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

final = Acl()

for item in ag:
    accessgroup = ((item.text).split(" "))[1]    
    al = cisco_cfg.find_objects(r"access-list " + accessgroup)
    tmp = accessgroup
    print (tmp)
    final.aclname = re.sub(r"-in", "", tmp, 0)

    for i in al:
        final.append_ace(((i.text).split(" ")),i.linenum)

    print ('Generating objects for ACL name: ', final.aclname)
    print ('Port objects: ', final.find_objects('port'))
    print ('Network objects: ', final.find_objects('net'))
