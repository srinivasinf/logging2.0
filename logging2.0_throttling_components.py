
#!/usr/bin/env python3
"""
Author: Srinivas Yadam (syadam@cisco.com)
Version: 1.0
Date: 2021-10-29
Copyright Cisco Systems 2021
Cisco Confidential

Script to find which components are having the throttling and collects the bloggerd logs
script usage: python logging2.0_throttling_components.py -i <switch-ip> -u <switch-mgmt-user-id> -p <pwd> -s <switch-name> -m <module#>
example script usage: python logging2.0_throttling_components.py -i 172.22.144.250 -u dcnmadmin -p Insieme123 -s eor1-3 -m 1

Based on the timestamps you got by runing this script for each component which is throttling, 
use the below script to collect the logging2.0 logs from receiver.
script usage: /ws/syadam-sjc/nxos-systest-1/nxos/test/system/testbeds/syadam_tahoe_l2l3_9508/extract_logging2.sh <logging2.0 receiver ip> <receiver-login> <receiver-pwd> -d <directory where you want to copy the logs>  <timestamp from where you need the logs> <host-name> --posttime <timeduration you want the logs>
example script usage: 
/ws/syadam-sjc/nxos-systest-1/nxos/test/system/testbeds/syadam_tahoe_l2l3_9508/extract_logging2.sh 172.22.135.11 root Insieme123! -d /auto/dcg-ast/syadam/kr3f_logs/logs_dummy/  2022 Mar 02 13:30:00 eor1-3 --posttime 10

"""

'''
#todo
operation not permitted/no space left al
getting the logs from receiver based on the timestamp of throttling
Will try to figure out whether we can differentiate the throttling is before/after trigger…
'''

import pprint
import os
import re
import time
import pdb
import json
from datetime import datetime
from unicon import Connection
import sys, getopt
import collections
from pprint import pprint
import operator
import sys
#### Section to get command line args

argv = sys.argv[1:]  
try:
    opts, args = getopt.getopt(argv,"h:i:u:p:s:m:c",["ipaddress=","username=","password=","switchname=","module="])
except getopt.GetoptError:
    print ('script_file.py -i <ipaddress> -u <username> -p <password> -s <switchname> -m <module> << for SUP, module number is 0/27/28')
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print ('script_file.py -i <ipaddress> -u <username> -p <password> -s <switchname> -m <module> << for SUP, module number is 0/27/28')
        sys.exit()
    elif opt in ("-i", "--ipaddress"):
        ipaddress = arg
    elif opt in ("-u", "--username"):
        username = arg
    elif opt in ("-p", "--password"):
        password = arg
    elif opt in ("-s", "--switchname"):
        switchname = arg
    elif opt in ("-m", "--module"):
        module = arg

print ('Ip Address is ', ipaddress)
print ('username is ', username)
print ('Password is ', password)
print ('Switchname is ', switchname)
print ('module number is ', module)

dev = Connection(hostname=switchname, 
                 start=['ssh ' + ipaddress], 
                 credentials={'default': {'username': username, 'password': password}}, 
                 os='nxos') 
dev.connect()

def getSapIdNames(dev, module_number):
    if (module_number == 0):
        cli_output = dev.execute('show system internal sysmgr service all', timeout=60*10)
    else:
        cli_output = dev.execute('slot ' + str(module_number) + ' quoted ' + '\"show system internal sysmgr service all\"', timeout=60*10)

    cli_output_split = cli_output.splitlines()

    #just for reference, not using anywhere
    # lookingPatten = ''' PFMCLNT           0x00000500    7662    158  s0009              1             N/A           0  
    #                 aclqos            0x0000016E    8778    190  s0009              1             N/A           0  
    #                 bfdc              0x000002C7    8766   1008  s0009              1             N/A           0  
    #                 bloggerd          0x00000474    8585    856  s0009              1             N/A           0  
    #                 capability        0x00000087    8604    949  s0009              1             N/A           0  
    #                 cardclient        0x0000013B    8610    901  s0009              1             N/A           0  
    #             '''

    patternMatch =  r"([\S\d_-]+)\s+([\S\d]+)\s+(\d+)\s+(\d+)\s+([\S\d]+)\s+(\d+)\s+([\S\/\d]+)\s+(\d+)"

    #just for reference, not using anywhere
    #first = " 2021 Mar 18 00:42:52.632027: E_STRING tahusd [16444]: [tahusd_read_intr (1541)] Inside roc_hom_prx_int_rx_err_0"
    #regex = r"2021 Mar (\d+) [\d:.]+ \S+\s+(\S+) \[(\d+)\]: \[(\S+) \(\d+\)\] (.+)"
    #sixth = '[1245] 2021 Mar 18 13:14:09.256176 [tahusd] E_STRING    (SDK_L3_T) tah_sdk_insert_nh_into_l2_dleft(2845): dleft existed p_dleft->ownder_flags 0x3'
    #regex = r"\[\d+\] 2021 Mar (\d+) [\d:.]+ \[(\S+)\] \S+\s+\([\d\S_]+\) \[?(\S+)\s*(\(\d+\))?\]?:? (.+)"

    all_sap_names_numbers = collections.defaultdict(int)
    for line in cli_output_split:
        match = re.match(patternMatch, line)
        if match:
            all_sap_names_numbers[match.group(4)] = match.group(1)
    return all_sap_names_numbers

def getSapId(dev, service):
    notRunningPat = "-- Currently not running --"
    sapIdPattern = "SAP = (\d+)"
    process = dev.execute('show system internal sysmgr service name '+ str(service))
    notRunning = re.search(notRunningPat, process)
    print("inside getSapId")
    if (notRunning is not None):
        return None
    else:
        proc = re.search(sapIdPattern, process)
        if (proc is None):
            return None
        else:
            sapId = proc.group(1)
            return sapId

def getEOR(dev):
    stringPattern = "-FM-"
    cli_output = dev.execute('show module')
    patternMatched = re.search(stringPattern, cli_output)
    if (patternMatched is None):
        return 0
    else:
        return 1

def getRollOver(dev , i , module_number):
    # rollOverDict = {}
    # rollover = 0
    if (module_number == 0):
        cli_output = dev.execute('show system internal sdwrap buffers sap ' + i + ' detailed', timeout=60*10)
    else:
        cli_output = dev.execute('slot ' + str(module_number) + ' quoted ' + '\"show system internal sdwrap buffers sap ' + i + ' detailed \"', timeout=60*10)

    throttled_Pattern = "Instance: (\d+), Throttled: (\d+)"
    match_rolledover = re.search(throttled_Pattern, cli_output)

    no_space_left_pattern = "No space left on device"
    match_no_space_left_pattern = re.search(no_space_left_pattern, cli_output)

    operation_not_permitted = "Operation not permitted"
    match_operation_not_permitted = re.search(operation_not_permitted, cli_output)

    invalid_argument = "Invalid argument"
    match_invalid_argument = re.search(invalid_argument, cli_output)

    no_such_file_or_directory = "No such file or directory"
    match_no_such_file_or_directory = re.search(no_such_file_or_directory, cli_output)

    no_message_of_desired_type = "No message of desired type"
    match_no_message_of_desired_type = re.search(no_message_of_desired_type, cli_output)

    broken_pipe = "Broken pipe"
    match_broken_pipe = re.search(broken_pipe, cli_output)

    bad_file_descriptor = "Bad file descriptor"
    match_bad_file_descriptor = re.search(bad_file_descriptor, cli_output)

    too_many_open_files = "Too many open files"
    match_too_many_open_files = re.search(too_many_open_files, cli_output)

    if ((match_no_space_left_pattern is not None) or (match_operation_not_permitted is not None) or (match_invalid_argument is not None) or (match_no_such_file_or_directory is not None) or (match_no_message_of_desired_type is not None) or (match_broken_pipe is not None) or (match_bad_file_descriptor is not None) or (match_too_many_open_files is not None)):
        # print("if condtion 1")
        # time.sleep(5)
        dev.execute('term dont-ask ')
        dev.execute('bloggerd log-snapshot all ', timeout=60*10)
        dev.execute('bloggerd log-dump once log-buffer sap 0' , timeout=60*10)
        if (module_number == 0):
            dev.execute('show tech-support bloggerd ' + ' > show_tech_support_bloggerd_detailed_' +  unique_id+'_' +switchname , timeout=60*10)
            dev.execute('show tech-support bloggerd-all ' + ' > show_tech_support_bloggerd_all_detailed_' +  unique_id+'_' +switchname, timeout=60*10)
            dev.execute('show system internal sdwrap buffers detailed ' + ' > show_system_internal_sdwrap_buffers_detailed_' + unique_id+'_'+switchname, timeout=60*10)
        else:
            dev.execute('show tech-support bloggerd ' + ' > show_tech_support_bloggerd_detailed_' +  unique_id+'_' +switchname, timeout=60*10)
            dev.execute('show tech-support bloggerd-all ' + ' > show_tech_support_bloggerd_all_detailed_'+switchname, timeout=60*10)
            dev.execute('slot ' + str(module_number) + ' quoted ' + '\"show system internal sdwrap buffers detailed \"' + ' > show_system_internal_sdwrap_buffers_detailed_'+'module_'+str(module_number) + '_' + unique_id + '_' + switchname, timeout=60*10)

    if (match_no_space_left_pattern is not None):
        print("some components are having \"No space left on device\" error, please contact directly nxos-binlog-infra@cisco.com")
    if (match_operation_not_permitted is not None):
        print("some components are having \"Operation not permitted\" error, please contact directly nxos-binlog-infra@cisco.com")
    if (match_invalid_argument is not None):
        print("some components are having \"Invalid argument\" error, please contact directly nxos-binlog-infra@cisco.com")
    if (match_no_such_file_or_directory is not None):
        print("some components are having \"No such file or directory\" error, please contact directly nxos-binlog-infra@cisco.com")
    if (match_no_message_of_desired_type is not None):
        print("some components are having \"No message of desired type\" error, please contact directly nxos-binlog-infra@cisco.com")
    if (match_broken_pipe is not None):
        print("some components are having \"Broken pipe\" error, please contact directly nxos-binlog-infra@cisco.com")
    if (match_bad_file_descriptor is not None):
        print("some components are having \"Bad file descriptor\" error, please contact directly nxos-binlog-infra@cisco.com")
    if (match_too_many_open_files is not None):
        print("some components are having \"Too many open files\" error, please contact directly nxos-binlog-infra@cisco.com")


    if ((match_no_space_left_pattern is not None) or (match_operation_not_permitted is not None) or (match_invalid_argument is not None) or (match_no_such_file_or_directory is not None) or (match_no_message_of_desired_type is not None) or (match_broken_pipe is not None) or (match_bad_file_descriptor is not None) or (match_too_many_open_files is not None)):
        sys.exit()

    if (match_rolledover is None):
        return None
    else:
        dev.execute('term dont-ask ')
        if (module_number == 0):
            dev.execute('show system internal sdwrap buffers sap ' + i + ' detailed  > show_system_internal_sdwrap_buffers_sap_' + i + '_' + all_sap_ids_names[i] + '_detailed_' + unique_id+'_'+switchname, timeout=60*10)
        else:
            dev.execute('slot ' + str(module_number) + ' quoted ' + '\"show system internal sdwrap buffers sap ' + i + ' detailed \" > show_system_internal_sdwrap_buffers_sap_' + i +'_' + all_sap_ids_names[i] + '_detailed_'+'module_'+str(module_number)+'_'+ unique_id + '_'+switchname, timeout=60*10)
        return i

#main()
is_it_eor = 1
is_it_eor = getEOR(dev)
print("is it eor: ", is_it_eor)
module_number = 0
module_number = int(module)

unique_id = str(time.time()).replace('.', '')[10:]
if (is_it_eor):
    if ((module_number == 0) | (module_number == 27) | (module_number == 28)):
        module_number = 0
    elif(module_number > 28):
        print("wrong module number is entered for the box you are accessing")
        sys.exit()
else:
    if (module_number > 1):
        print("wrong module number is entered for the box you are accessing")
        sys.exit()
print("module_number  :  ", module_number)

all_sap_ids_names = getSapIdNames(dev, module_number)

#sorting the dictionary
sorted(all_sap_ids_names.items(), key = lambda kv:(kv[1], kv[0]))
#pprint(out_dict)

print("all SAP IDs and corresponding names are ::::")
print()
for i in sorted (all_sap_ids_names) :
    print ((i, all_sap_ids_names[i]), end =" ")

# for i in all_sap_ids_names : 
#     sapId = getSapId(dev, all_sap_ids_names[i])
#     print("sapId::::::::::",sapId)

all_saps_rolling_over = collections.defaultdict(int)

some_component_rollover_happening = None

for i in all_sap_ids_names :
    return_value = getRollOver(dev, i, module_number)
    if return_value != None:
        all_saps_rolling_over[i] = all_sap_ids_names[i]
        some_component_rollover_happening = 1

if (some_component_rollover_happening == None):
    print("we are good. no component has any issue")
    sys.exit()
else:
    dev.execute('term dont-ask ')
    dev.execute('bloggerd log-snapshot all ',timeout=60*10)
    if (module_number == 0):
        dev.execute('show tech-support bloggerd ' + ' > show_tech_support_bloggerd_detailed_' +  unique_id+'_' +switchname, timeout=60*10)
        dev.execute('show tech-support bloggerd-all ' + ' > show_tech_support_bloggerd_all_detailed_' + unique_id+'_'+switchname, timeout=60*10)
        dev.execute('show system internal sdwrap buffers detailed ' + ' > show_system_internal_sdwrap_buffers_detailed_' + unique_id+'_'+switchname, timeout=60*10)
        print()
        print("##########################  REPORT ##########################")
        print()
        print("the SAPs which are throttling on SUP are::::")
        print()
        for i in sorted (all_saps_rolling_over) :
            print ((i, all_saps_rolling_over[i]), end =" ")
        print()
        print()
        print("we collected the relevant logging2.0 show-techs in bootflash. please collect problematic listed components show-techs & logs from logging2.0 server for that timestamp")
    else:
        dev.execute('show tech-support bloggerd ' + ' > show_tech_support_bloggerd_detailed_' +  unique_id+'_' +switchname, timeout=60*10)
        dev.execute('show tech-support bloggerd-all ' + ' > show_tech_support_bloggerd_all_detailed_' + unique_id+'_'+switchname, timeout=60*10)
        dev.execute('slot ' + str(module_number) + ' quoted ' + '\"show system internal sdwrap buffers detailed \"' + ' > show_system_internal_sdwrap_buffers_detailed_'+'module_'+str(module_number)+'_' + unique_id+'_'+switchname, timeout=60*10)
        print()
        print("##########################  REPORT ##########################")
        print()
        print("the SAPs which are throttling on module "+str(module_number)+" are:::::")
        print()
        for i in sorted (all_saps_rolling_over) :
            print ((i, all_saps_rolling_over[i]), end =" ")
        print()
        print()
        print("we collected the relevant logging2.0 show-techs in bootflash. please collect problematic listed components show-techs & logs from logging2.0 server for that timestamp")
