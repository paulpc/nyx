#!/usr/bin/python

import json
import requests
import time
from common_methods import *
from crits import *
import soltra
from qradar import *
from bro import *
from web_proxy import *
from palo_alto import *
from wise import *


if __name__ == "__main__":
    
    # reading the settings - upon successful read, the functionality will be dependent on the sections in the configuration file
    settings=read_configs('nyx.conf')
    obs_index={'A':{'medium':[],'high':[]},'Address - ipv4-addr':{'medium':[],'high':[]},'md5':{'medium':[],'high':[]},'email':{'medium':[],'high':[]},'userid':{'medium':[],'high':[]}}
    
    intel={}        # validating that the sets in the configuration file are in QRadar
    if 'qradar' in settings.keys():
        validate_qradar(settings['qradar'])
    
    if 'soltra' in settings.keys():
        intel['medium']=soltra.poll_feed(settings['soltra'],'medium')
        intel['high']=soltra.poll_feed(settings['soltra'],'high')
    
    for csi,ivalues in intel.iteritems():
        for ip in ivalues['AddressObjectType']:
            # creating crits-like objects
            observable={"type":"Address - ipv4-addr","source":[{"name":"Soltra-"+csi}],'ip':ip['value']}
            obs_index['Address - ipv4-addr'][csi].append(ip['value'])
            if 'bro' in settings.keys():
                alert_bro(observable,settings['bro'])
            if 'qradar' in settings.keys():
                qradar(observable, settings['qradar'],csi+'_reference_sets')
            if 'palo_alto' in settings.keys() and csi == 'high':
                palo_alto(observable,settings['palo_alto'],'ip_block_list')
            if 'moloch' in settings.keys():
                alert_wise(observable, settings['moloch'],csi)
        for domain in ivalues['DomainNameObjectType']:
            observable={"type":"A","source":[{"name":"Soltra-"+csi}],'domain':domain['value']}
            obs_index['A'][csi].append(domain['value'])
            if 'bro' in settings.keys():
                alert_bro(observable,settings['bro'])
            if 'qradar' in settings.keys():
                qradar(observable, settings['qradar'],csi+'_reference_sets')
            if 'palo_alto' in settings.keys() and csi == 'high':
                 palo_alto(observable,settings['palo_alto'],'url_block_list')
            if 'moloch' in settings.keys():
                alert_wise(observable, settings['moloch'],csi)
        for file_obj in ivalues['FileObjectType']:
            for file_prop in file_obj:
                if 'simple_hash_value' in file_prop.keys():
                    # congratulations, it's a Hash!
                    try:
                        observable={"type":file_prop['type'],"source":[{"name":"Soltra-"+csi}],str(file_prop['type']).lower():file_prop['simple_hash_value']['value'],'filename':False}
                        obs_index['md5'][csi].append(file_prop['simple_hash_value']['value'])
                        if 'bro' in settings.keys():
                            alert_bro(observable,settings['bro'])
                        if 'qradar' in settings.keys():
                            qradar(observable, settings['qradar'],csi+'_reference_sets')
                        if 'moloch' in settings.keys():
                            alert_wise(observable, settings['moloch'],csi)
                        
                    except:
                        print {"type":file_prop['type'],"source":[{"name":"Soltra-"+csi}],str(file_prop['type']):file_prop['simple_hash_value']['value'],'filename':False}
    if 'qradar' in settings.keys():
        qradar_sets_cleanup(obs_index,settings['qradar']) 
