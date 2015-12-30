#!/usr/bin/python
import ConfigParser
import syslog
import json
import requests
import time
from common_methods import *
import crits
import qradar
from bro import *
from web_proxy import *
import palo_alto




if __name__ == "__main__":
    
    # reading the settings - upon successful read, the functionality will be dependent on the sections in the configuration file
    config=read_configs('nyx.conf')    
    indicator_index={}
    indicators={'incoming':{'ip':{},'domain':{},'sample':{},'email':{},},
                'outgoing':{'to_add':{'ip':{},'domain':{},'sample':{},'email':{}},
                            'to_remove':{'ip':{},'domain':{},'sample':{},'email':{}},
                            'to_change':{'ip':{},'domain':{},'sample':{},'email':{}}
                            }
                }
    tag_index=[]
    for tool in config.keys():
        syslog.syslog(syslog.LOG_INFO,"nyx: retrieving indicators from %s" % tool)
        if tool == 'palo_alto':
            indicator_index[tool]={'ip':palo_alto.list_ips(config[tool]),
                                   'domain':palo_alto.list_domains(config[tool])}
        elif tool == 'qradar':
            indicator_index[tool]={'ip':qradar.list_ips(config[tool]),
                                   'domain':qradar.list_domains(config[tool])}
        elif tool == 'crits':
            # getting the intel from crits
            for crits_ip in crits.list_ips(config['crits']):
                indicators=crits.normalize_ip(crits_ip,indicators)
            # doing the same for domains
            for crits_domain in crits.list_fqdns(config['crits']):
                indicators=crits.normalize_fqdn(crits_domain,indicators)
            
            #for crits_sample in crits.list_samples(settings[tool],100):
            #    indicators=crits.normalize_sample(crits_sample,indicators)
        else:
            # getting cached intel from the rest of the controls
            syslog.syslog(syslog.LOG_ERR,"nyx: don't quite know what to do about indicators from and to %s. You make your own or tweet @p4ulpc" % tool)
    
                
    for tool in indicator_index.keys():
        for itype in indicator_index[tool].keys():
            for tool_ind in indicator_index[tool][itype]:
                if not tool_ind in indicators['incoming'][itype].keys() and indicator_index[tool][itype][tool_ind] in config[tool]['map'][itype].values():
                    # only removing indicators in the reference sets we actually care aboot
                    syslog.syslog(syslog.LOG_INFO,"nyx (to be implemented): %s (%s) is outdated, removing it" % (tool_ind,indicator_index[tool][itype][tool_ind]))
                    if not tool_ind in indicators['outgoing']['to_remove'][itype].keys():
                        indicators['outgoing']['to_remove'][itype][tool_ind]=[]
                    indicators['outgoing']['to_remove'][itype][tool_ind].append(tool)

    for itype in indicators['incoming'].keys():
        for source_ind in indicators['incoming'][itype]:
            for tool in indicator_index.keys():
                if itype in indicator_index[tool].keys():
                    if indicators['incoming'][itype][source_ind]['confidence'] in ['medium','high'] and not source_ind in indicator_index[tool][itype].keys():
                        if not source_ind in indicators['outgoing']['to_add'][itype].keys():
                            indicators['outgoing']['to_add'][itype][source_ind]={}
                        if not tool in indicators['outgoing']['to_add'][itype][source_ind].keys():
                            syslog.syslog(syslog.LOG_INFO, "nyx: should be adding %s to %s" % (source_ind,tool))
                            indicators['outgoing']['to_add'][itype][source_ind][tool]={
                                'list':config[tool]['map'][itype][indicators['incoming'][itype][source_ind]['confidence']],
                                'tags':indicators['incoming'][itype][source_ind]['tags']}
                            for tag in indicators['incoming'][itype][source_ind]['tags']:
                                if not tag in tag_index:
                                    tag_index.append(tag)
                else:
                    syslog.syslog(syslog.LOG_ERR,"nyx: WATCH OUT! indicator type (%s) not supported yet, silly!" % itype)

    syslog.syslog(syslog.LOG_INFO,"nyx: starting prepwork")
    # prep work starts here.
    # dumping indicators locally (you know, just in case)
    json.dump(indicators,open('temp_indicators.json','w'))
    json.dump(indicator_index,open('temp_index.json','w'))
    # for palo alto, making sure we have all the tags in place
    if 'palo_alto' in config.keys():
        syslog.syslog(syslog.LOG_INFO,"nyx: syncronizing palo alto tags")
        palo_tag_index=palo_alto.list_tags(config['palo_alto'])
        for tag in tag_index:
            palo_tag="dvn_intel_"+tag.replace(" ","_")
            if not palo_tag in palo_tag_index:
                palo_alto.add_tag(palo_tag,config['palo_alto'])
        # and while we're at it, let's make sure we have the tags for the addresses - just in case we're runnig it the first time:
        for tag in config['palo_alto']['map']['ip'].values():
            if not tag in palo_tag_index:
                palo_alto.add_tag_to_panorama(tag,config['palo_alto'])
    syslog.syslog(syslog.LOG_INFO,"nyx: starting to add IPs")
    for add_ip in indicators['outgoing']['to_add']['ip']:
        for tool in indicators['outgoing']['to_add']['ip'][add_ip].keys():
            if tool == 'palo_alto':
                result=palo_alto.add_ip(add_ip,config['palo_alto'],indicators['outgoing']['to_add']['ip'][add_ip]['palo_alto']['list'],indicators['outgoing']['to_add']['ip'][add_ip]['palo_alto']['tags'])
            elif tool == 'qradar':
                result=qradar.add_ip(add_ip,config['qradar'],indicators['outgoing']['to_add']['ip'][add_ip]['qradar']['list'],indicators['outgoing']['to_add']['ip'][add_ip]['qradar']['tags'])
    syslog.syslog(syslog.LOG_INFO,"nyx: starting to add domains")    
    for add_domain in indicators['outgoing']['to_add']['domain']:
        for tool in indicators['outgoing']['to_add']['domain'][add_domain].keys():
            if tool == 'palo_alto':
                result=palo_alto.add_domain(add_domain,config['palo_alto'],indicators['outgoing']['to_add']['domain'][add_domain]['palo_alto']['list'])
            elif tool == 'qradar':
                result=qradar.add_domain(add_domain,config['qradar'],indicators['outgoing']['to_add']['domain'][add_domain]['qradar']['list'],indicators['outgoing']['to_add']['domain'][add_domain]['qradar']['tags'])
                #result=qradar.add_to_reference_set(indicators['outgoing']['to_add']['domain'][add_domain]['qradar']['list'], add_domain, indicators['outgoing']['to_add']['domain'][add_domain]['qradar']['tags'], config['qradar'])
    
    # !!! NOTE !!! make sure to recategorize shit here from high to medium and the other way around
    
    syslog.syslog(syslog.LOG_INFO,"nyx: starting closeut tasks")
    palo_alto.pan_commit(config['palo_alto'])