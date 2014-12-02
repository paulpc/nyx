#!/usr/bin/python
import ConfigParser
import syslog
import pprint
import json
import requests
import time
from common_methods import *
from crits import *
from qradar import *
from bro import *
from web_proxy import *
from palo_alto import *



def read_configs(config_file):
    """ read configurations from the config file. if the section exists, then create the config module
    As of right now, it is still in doubt whether to error out on bad configuration, or to just exclude module"""
    config = ConfigParser.SafeConfigParser()
    cfg_success = config.read(config_file)
    if not cfg_success:
        syslog.syslog(syslog.LOG_ERR,'Could not read nyx.conf')
        exit(-1)
    
    configs={}
    
    if config.has_section('crits'):
        #getting the CRITs configurations
        configs['crits']={}
        if config.has_option('crits','username'):
            configs['crits']['username']=config.get('crits','username')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Please make sure that the [crits] section of the nyx.conf file has a username section')
            exit(-1)
            
        if config.has_option('crits','api_key'):
            configs['crits']['api_key']=config.get('crits', 'api_key')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Please make sure that the [crits] section of the nyx.conf file has a api_key section')
            exit(-1)
            
        if config.has_option('crits','url'):
            configs['crits']['url']=config.get('crits','url')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Please make sure that the [crits] section of the nyx.conf file has a url section')
            exit(-1)
            
        if config.has_option('crits','offset'):
            configs['crits']['offset']=int(config.get('crits','offset'))
        else:
            crits_config['offset']=20
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx: minimum sections required for nyx to run: CRITs')
        exit(-1)
    
    if config.has_section('qradar'):
        # getting the QRadar Settings
        configs['qradar']={}
        if config.has_option('qradar','console'):
            configs['qradar']['base_url']=config.get('qradar','console')+'api/'
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the QRadar console address from the configuation file.')
            exit(-1)
        
        if config.has_option('qradar','api_key'):
            configs['qradar']['SEC']=config.get('qradar','api_key')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the QRadar api key from the configuration file')
            exit(-1)
            
        # starting to read and validate the sets:
        if config.has_option('qradar','sets_to_validate'):
            configs['qradar']['sets_to_validate']=json.loads(config.get('qradar','sets_to_validate'))
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the QRadar intel reference sets from the configuation file.')
            exit(-1)
        
        set_test=[]
        
        if config.has_option('qradar','high_reference_sets'):
            configs['qradar']['high_reference_sets']=json.loads(config.get('qradar','high_reference_sets'))
            set_test+=configs['qradar']['high_reference_sets'].values()
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the QRadar intel reference sets from the configuation file.')
            exit(-1)
        
        if config.has_option('qradar','medium_reference_sets'):
            configs['qradar']['medium_reference_sets']=json.loads(config.get('qradar','medium_reference_sets'))
            set_test+=configs['qradar']['medium_reference_sets'].values()
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the QRadar intel reference sets from the configuation file.')
            exit(-1)        
        for qset in set_test:
            if not qset in configs['qradar']['sets_to_validate'].keys():
                configs['qradar']['sets_to_validate'][qset]="ALNIC"
                syslog.syslog(syslog.LOG_ERR,"nyx: Unable to find metadata about the (%s) set in the configuation file. Defaulting to ALNIC" % qset)
        # validating that the sets in the configuration file are in QRadar
        validate_qradar(configs['qradar'])
        
    if config.has_section('bro'):
        #reading BRO settings
        configs['bro']={}
        if config.has_option('bro','filename'):
            configs['bro']['filename']=config.get('bro','filename')
            # truncating the filename to ensure no stale indicators
            with open(configs['bro']['filename'],'w') as bro_file:
                bro_file.write('#fields\tindicator\tindicator_type\tmeta.source\tmeta.do_notice\n')
        else:
            syslog.syslog(syslog.LOG_ERR,'Unable to get the BRO intel file location from the configuation file.')
            exit(-1)
        if config.has_option('bro','indicator_map'):
            configs['bro']['indicator_map']=json.loads(config.get('bro','indicator_map'))
            set_test+=configs['bro']['indicator_map'].keys()
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to load the BRO indicator map from the configuation file.')
            exit(-1)
    
    if config.has_section('palo_alto'):
        # reading palo alto settings
        configs['palo_alto']={}
        if config.has_option('palo_alto','api_key'):
            configs['palo_alto']['api_key']=config.get('palo_alto','api_key')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto api key from the configuation file.')
            exit(-1)
        
        if config.has_option('palo_alto','url'):
            configs['palo_alto']['url']=config.get('palo_alto','url')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto base URL from the configuation file.')
            exit(-1)
        
        if config.has_option('palo_alto','url_alert_list'):
            configs['palo_alto']['url_alert_list']=config.get('palo_alto','url_alert_list')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto BlockList from the configuation file.')
            exit(-1)
            
        if config.has_option('palo_alto','url_block_list'):
            configs['palo_alto']['url_block_list']=config.get('palo_alto','url_block_list')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto Alert List from the configuation file.')
            exit(-1)
            
        if config.has_option('palo_alto','ip_alert_list'):
            configs['palo_alto']['ip_alert_list']=config.get('palo_alto','ip_alert_list')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto BlockList from the configuation file.')
            exit(-1)
            
        if config.has_option('palo_alto','ip_block_list'):
            configs['palo_alto']['ip_block_list']=config.get('palo_alto','ip_block_list')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto Alert List from the configuation file.')
            exit(-1)
            

    if config.has_section('web_proxy'):
        # reading web content gateway settings
        configs['web_proxy']={}
        if config.has_option('web_proxy','filename'):
            configs['web_proxy']['filename']=config.get('web_proxy','filename')
            # truncating the filename to ensure no stale indicators
            with open(configs['web_proxy']['filename'],'w') as wp_file:
                wp_file.write('')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the BRO intel file location from the configuation file.')
            exit(-1)
    return configs

if __name__ == "__main__":
    
    # reading the settings - upon successful read, the functionality will be dependent on the sections in the configuration file
    settings=read_configs('./nyx.conf')
    
    pp = pprint.PrettyPrinter(indent=4)
    

    pp.pprint(settings)
    syslog.syslog(syslog.LOG_INFO,'nyx: Distributing a list of IP adresses')
    for ip in list_ips(settings['crits'],100): #json.load(open('ips.json','rb')):
        try:
            if 'bro' in settings.keys():
                alert_bro(ip,settings['bro'])
            confidence=get_intel_confidence(ip)
            if confidence=="medium":
                if 'qradar' in settings.keys():
                    qradar(ip, settings['qradar'],'medium_reference_sets')
                    # not adding the medium IPs to palo alto, as we have varying sets of limitations for the addresses and address groups.
            elif confidence=="high":
                if 'qradar' in settings.keys():
                    qradar(ip, settings['qradar'],'high_reference_sets')
                if 'palo_alto' in settings.keys():
                    palo_alto(ip,settings['palo_alto'],'ip_block_list')
        except:
            syslog.syslog(syslog.LOG_ERR,'nyx: encountered problems adding the ip indicator: %s' % str(ip))

    syslog.syslog(syslog.LOG_INFO,'nyx: Distributing a list of domains')
    for domain in list_fqdns(settings['crits'],100):#json.load(open('domains.json','rb')):
        try:
            if 'bro' in settings.keys():
                alert_bro(domain,settings['bro'])
            confidence=get_intel_confidence(domain)
            if 'web_proxy' in settings.keys() and confidence=='high':
                # trying to reduce the false positives by only blocking the high confidence Indicators of Compromise 
                add_to_proxy(domain,settings['web_proxy'])
            if confidence=="medium":
                if 'qradar' in settings.keys():
                    qradar(domain, settings['qradar'],'medium_reference_sets')
                if 'palo_alto' in settings.keys():
                    palo_alto(domain,settings['palo_alto'],'url_alert_list')
            elif confidence=="high":
                if 'qradar' in settings.keys():
                    qradar(domain, settings['qradar'],'high_reference_sets')
                if 'palo_alto' in settings.keys():
                    palo_alto(domain,settings['palo_alto'],'url_block_list')
        except:
            syslog.syslog(syslog.LOG_ERR,'nyx: encountered problems adding the domain indicator: %s' % str(domain))
          
    syslog.syslog(syslog.LOG_INFO,'nyx: Distributing a list of samples')
    # this is currently half-baked
    for sample in list_samples(settings['crits'],10):
        try:
            if 'bro' in settings.keys():
                alert_bro(sample,settings['bro'])
            confidence=get_intel_confidence(sample)
            if confidence=="medium":
                if 'qradar' in settings.keys():
                    qradar(sample,settings['qradar'],'medium_reference_sets')
            elif confidence=="high":
                if 'qradar' in settings.keys():
                    qradar(sample,settings['qradar'],'high_reference_sets')
        except:
            syslog.syslog(syslog.LOG_ERR,'nyx: encountered problems adding the sample indicator: %s' % str(sample))
                        
    
    syslog.syslog(syslog.LOG_INFO,'nyx: Distributing a list of targets')
    for target in list_targets(settings['crits']):
        try:
            if 'qradar' in settings.keys():
                qradar(target,settings['qradar'],'high_reference_sets')
        except:
            syslog.syslog(syslog.LOG_ERR,'nyx: encountered problems adding the target: %s' % str(target))
            
    syslog.syslog(syslog.LOG_INFO,'nyx: performing the closing tasks')
    if 'palo_alto' in settings.keys():
        try:
            res=pan_commit(settings['palo_alto'])
            if res and res.status_code==200:
                syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully committed to PAN')
            else:
                syslog.syslog(syslog.LOG_ERR,'nyx->PAN: unsuccessfully committed to PAN')
        except:
            syslog.syslog(syslog.LOG_ERR,'nyx->PAN: error while trying to commit to PAN')
    syslog.syslog(syslog.LOG_INFO,'nyx: Thank you for using Nyx. We hope this has been a pleasant experience and that you will continue to use us')