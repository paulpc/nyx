import ConfigParser
import syslog
import json

def get_sources(indicator):
    """ appends the sources of an indicator in a string"""
    source_arr=[]
    if 'source' in indicator.keys():
        for source in indicator['source']:
            if not source in source_arr:
                source_arr.append(source['name'])
    if source_arr:
        return source_arr
    else:
        return "CRITs"
    
def get_intel_confidence(indicator):
    """ sets the confidence to the highest confidence source.
    I am starting the confidence level with the first campaign, then adding some points for each subsequent one.
    The idea is that the more distinct campaigns this indicator is a part of, the more certain we can be that
    it is not a false positive"""
    initial_score = {'low':30, 'medium':50, 'high':75}
    add_score={'low':5,'medium':10,'high':25}
    # setting the confidence to parrallel the highest-confidence source
    processed_campaigns=[indicator[u'campaign'][0]['name']]
    confidence=initial_score[indicator[u'campaign'][0]['confidence']]
    for campaign in indicator[u'campaign']:
        if not campaign['name'] in processed_campaigns:
            confidence+=add_score[campaign['confidence']]
            processed_campaigns.append(campaign['name'])
    if confidence in range(0,50):
        return 'low'
    elif confidence in range(50,75):
        return 'medium'
    elif confidence > 74:
        return 'high'
    else:
        syslog.syslog(syslog.LOG_ERR,'something got messed up in trying to gauge the confidence.')
        return 'low'

def read_configs(config_file):
    """ read configurations from the config file. if the section exists, then create the config module
    As of right now, it is still in doubt whether to error out on bad configuration, or to just exclude module"""
    config = ConfigParser.SafeConfigParser()
    cfg_success = config.read(config_file)
    if not cfg_success:
        syslog.syslog(syslog.LOG_ERR,'Could not read nyx.conf')
        exit(-1)
    
    configs={}
    source=False
    
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
    source='crits'
    
    if config.has_section('soltra'):
        #getting the CRITs configurations
        configs['soltra']={}
        if config.has_option('soltra','username'):
            configs['soltra']['username']=config.get('soltra','username')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Please make sure that the [soltra] section of the nyx.conf file has a username section')
            exit(-1)
            
        if config.has_option('soltra','password'):
            # i know, I know, it's not actual password encryption, but it should be better than cleartext
            configs['soltra']['password']=config.get('soltra', 'password').decode('base64').decode('rot13')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Please make sure that the [soltra] section of the nyx.conf file has a password section')
            exit(-1)
            
        if config.has_option('soltra','server'):
            configs['soltra']['server']=config.get('soltra','server')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Please make sure that the [soltra] section of the nyx.conf file has a server section')
            exit(-1)
            
        if config.has_option('soltra','subscriptions'):
            configs['soltra']['subscriptions']=json.loads(config.get('soltra','subscriptions'))
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Soltra subscriptions from the configuation file.')
            exit(-1)
        
        if config.has_option('soltra','supported_objects'):
            configs['soltra']['supported_objects']=json.loads(config.get('soltra','supported_objects'))
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Soltra supported_objects from the configuation file.')
            exit(-1)
        
        source='soltra'    
    if not source:
        syslog.syslog(syslog.LOG_ERR,'nyx: minimum sections required for nyx to run: a threat intel source - please populate either the soltra or the CRITs sections')
        exit(-1)
    
    if config.has_section('qradar'):
        # getting the QRadar Settings
        configs['qradar']={'map':{'ip':{'medium':'nyx_default_IP_medium','high':'nyx_default_IP_high'},'sample':{'medium':'nyx_default_sample_medium','high':'nyx_default_sample_high'},'email':{'medium':'nyx_default_email_medium','high':'nyx_default_email_high'},'domain':{'medium':'nyx_default_domain_medium','high':'nyx_default_domain_high'}}}
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
            configs['qradar']['map']['ip']['high']=configs['qradar']['high_reference_sets']["Address - ipv4-addr"]
            configs['qradar']['map']['domain']['high']=configs['qradar']['high_reference_sets']["A"]
            configs['qradar']['map']['sample']['high']=configs['qradar']['high_reference_sets']["md5"]
            configs['qradar']['map']['email']['high']=configs['qradar']['high_reference_sets']["email"]  
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the QRadar intel reference sets from the configuation file.')
            exit(-1)
        
        if config.has_option('qradar','medium_reference_sets'):
            configs['qradar']['medium_reference_sets']=json.loads(config.get('qradar','medium_reference_sets'))
            set_test+=configs['qradar']['medium_reference_sets'].values()
            configs['qradar']['map']['ip']['medium']=configs['qradar']['medium_reference_sets']["Address - ipv4-addr"]
            configs['qradar']['map']['domain']['medium']=configs['qradar']['medium_reference_sets']["A"]
            configs['qradar']['map']['sample']['medium']=configs['qradar']['medium_reference_sets']["md5"]
            configs['qradar']['map']['email']['medium']=configs['qradar']['medium_reference_sets']["email"]  
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the QRadar intel reference sets from the configuation file.')
            exit(-1)        
        for qset in set_test:
            if not qset in configs['qradar']['sets_to_validate'].keys():
                configs['qradar']['sets_to_validate'][qset]="ALNIC"
                syslog.syslog(syslog.LOG_ERR,"nyx: Unable to find metadata about the (%s) set in the configuation file. Defaulting to ALNIC" % qset)
        
    if config.has_section('bro'):
        #reading BRO settings
        configs['bro']={}
        if config.has_option('bro','filename'):
            configs['bro']['filename']=config.get('bro','filename')
            # truncating the filename to ensure no stale indicators
            for ftype in ['_file.txt','_addr.txt','_dom.txt','_mail.txt']:
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
        configs['palo_alto']={'map':{'ip':{'medium':'nyx_default_IP_medium','high':'nyx_default_IP_high'},'domain':{'medium':'nyx_default_domain_medium','high':'nyx_default_domain_high'}}}
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
        # this needs fixing to be more map-like: 
        if config.has_option('palo_alto','url_alert_list'):
            configs['palo_alto']['map']['domain']['medium']=config.get('palo_alto','url_alert_list')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto BlockList from the configuation file.')
            exit(-1)
            
        if config.has_option('palo_alto','url_block_list'):
            configs['palo_alto']['map']['domain']['high']=config.get('palo_alto','url_block_list')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto Alert List from the configuation file.')
            exit(-1)
            
        if config.has_option('palo_alto','ip_alert_list'):
            configs['palo_alto']['map']['ip']['medium']=config.get('palo_alto','ip_alert_list')
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to get the Palo Alto BlockList from the configuation file.')
            exit(-1)
            
        if config.has_option('palo_alto','ip_block_list'):
            configs['palo_alto']['map']['ip']['high']=config.get('palo_alto','ip_block_list')
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
    
    if config.has_section('wise'):
        #reading wise settings
        configs['wise']={}
        if config.has_option('wise','filename'):
            configs['wise']['filename']=config.get('wise','filename')
        else:
            syslog.syslog(syslog.LOG_ERR,'Unable to get the wise intel file location from the configuation file.')
            exit(-1)
        if config.has_option('wise','indicator_map'):
            configs['wise']['indicator_map']=json.loads(config.get('wise','indicator_map'))
            set_test+=configs['wise']['indicator_map'].keys()
        else:
            syslog.syslog(syslog.LOG_ERR,'nyx: Unable to load the wise indicator map from the configuation file.')
            exit(-1)
        # truncating the filename to ensure no stale indicators
        for ftype in config['wise']['indicator_map'].values():
            with open(configs['wise']['filename']+ftype,'w') as wise_file:
                wise_file.write()
    
    return configs

def address_in_index(address,ip_index):
    """checks to see if an address is in the index of IPs.
    The index should be a key-value pair address|CIDR:address group|reference set"""
    if address+"/32" in ip_index.keys():
        return ip_index[address+"/32"]
    elif address in ip_index.keys():
        return ip_index[address]
    else:
        return False
    
def url_in_index(url,url_index):
    """ checking url in url index
    The index should be a key-value pair url:address group|reference set"""

    if url in url_index.keys():
        return url_index[url]
    elif '*'+url in url_index.keys():
        return url_index['*'+url]
    else:
        return False