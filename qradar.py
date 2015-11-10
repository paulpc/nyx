from common_methods import *
import requests
import json
import syslog

def qradar(indicator,settings, reference_sets):
    """ places the indicator in a reference set"""
    reference_set_map=settings[reference_sets]
    if 'type' in indicator.keys() and indicator['type']=='Address - ipv4-addr':
        # adding an ip
        add_to_reference_set(reference_set_map[indicator['type']], indicator['ip'], get_sources(indicator), settings)
        return True
    elif 'type' in indicator.keys() and indicator['type']=='A':
        # adding the domain
        add_to_reference_set(reference_set_map[indicator['type']], indicator['domain'], get_sources(indicator), settings)
        return True
    elif 'md5' in indicator.keys():
        # adding the md5 hash
        if indicator['md5']:
            add_to_reference_set(reference_set_map['md5'], indicator['md5'], get_sources(indicator), settings)
        return True
    elif 'x_mailer' in indicator.keys():
        # adding the email address - for now, assuming spearphish, therefore focusing on the <<from>> field
        add_to_reference_set(reference_set_map['email'], indicator['from'], get_sources(indicator), settings)
        return True
    elif 'organization_id' in indicator.keys() and 'email_address' in indicator.keys():
        # adding a target email
        if indicator['email_address']:
            add_to_reference_set(reference_set_map['email'], indicator['email_address'], get_sources(indicator), settings)
        # adding the userid
        if indicator['organization_id']:
            add_to_reference_set(reference_set_map['userid'], indicator['organization_id'], get_sources(indicator), settings)
        return True
    else:
        syslog.syslog('nyx->QRadar: I do not know how to handle the following observable: %s' % str(indicator))
        return False

def add_to_reference_set(qset, value, source, settings):
    """ Adding the indicator (value) to the qset Reference Set, while maintaining the source"""
    headers = {'Version': '2.0', 'Accept': 'application/json','SEC':settings['SEC']}
    parameters={'value':value, 'source':source}
    resp=requests.post(settings['base_url']+'reference_data/sets/'+qset,headers=headers,params=parameters,verify=False)
    # print parameters, resp.text
    if resp.status_code==200 or resp.status_code==201:
        syslog.syslog(syslog.LOG_INFO,'nyx->QRadar: Added to %s to reference set: %s' % (value,qset))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,str(resp.status_code)+'nyx->QRadar: Unable to add %s to reference set: %s' % (value,qset))
        return False

def remove_from_reference_set(qset,value,settings):
    """ removes an indicator from the qset reference set """
    headers = {'Version': '2.0', 'Accept': 'application/json','SEC':settings['SEC']}
    resp=requests.delete(settings['base_url']+'reference_data/sets/'+qset+'/'+value,headers=headers,verify=False)
    if resp.status_code==200 or resp.status_code==201:
        syslog.syslog(syslog.LOG_INFO,'nyx->QRadar: deleted %s from reference set: %s' % (value,qset))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,str(resp.status_code)+'nyx->QRadar: Unable to  delete %s from reference set: %s' % (value,qset))
        return False
    
def list_reference_set(qset,settings):
    """ retrieves the elements of a reference set """
    headers = {'Version': '2.0', 'Accept': 'application/json','SEC':settings['SEC']}
    params={'limit':0}
    # getting basic metadata
    res=requests.get(settings['base_url']+'reference_data/sets/'+qset,headers=headers,params=params,verify=False)
    if res.status_code == 200:
        metadata=json.loads(res.text)
        # trying to get the whole thing:
        if metadata['number_of_elements'] > 0:
            params['limit']=metadata["number_of_elements"]
            resp=requests.get(settings['base_url']+'reference_data/sets/'+qset,headers=headers,params=params,verify=False)
            if resp.status_code == 200:
                result=json.loads(resp.text)['data']
                return result
            else:
                syslog.syslog(syslog.LOG_ERR,str(resp.status_code)+'nyx->QRadar: Unable to read reference set: %s' % qset)
                return []
        else:
            return []
    else:
        syslog.syslog(syslog.LOG_ERR,str(resp.status_code)+'nyx->QRadar: Unable to read reference set: %s' % qset)
        return []
    
    
def qradar_sets_cleanup(obs_index, settings):
    """ removes the outdated indicators from various sets """
    reference_sets={}
    # Checking IP addresses
    #high confidence first:
    qset=settings['high_reference_sets']['Address - ipv4-addr']
    for ipaddr in list_reference_set(qset,settings):
        if not ipaddr['value'] in obs_index['Address - ipv4-addr']['high']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,ipaddr['value'],settings)
    
    # checking medium confidence IPs
    qset=settings['medium_reference_sets']['Address - ipv4-addr']
    for ipaddr in list_reference_set(qset,settings):
        if not ipaddr['value'] in obs_index['Address - ipv4-addr']['medium']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,ipaddr['value'],settings)
    
    # checking Domains / URLS
    # high confidence domains
    qset=settings['high_reference_sets']['A']
    for domain in list_reference_set(qset,settings):
        if not domain['value'] in obs_index['A']['high']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,domain['value'],settings)
    
    # medium confidence domains
    qset=settings['medium_reference_sets']['A']
    for domain in list_reference_set(qset,settings):
        if not domain['value'] in obs_index['A']['medium']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,domain['value'],settings)
            
    # Checking Hashes
    # high confidence hashes
    qset=settings['high_reference_sets']['md5']
    for hash in list_reference_set(qset,settings):
        if not hash['value'] in obs_index['md5']['high']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,hash['value'],settings)
    
    # medium confidence hashes
    qset=settings['medium_reference_sets']['md5']
    for hash in list_reference_set(qset,settings):
        if not hash['value'] in obs_index['md5']['medium']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,hash['value'],settings)
    
    # checking emails
    # high confidence emails
    qset=settings['high_reference_sets']['email']
    for email in list_reference_set(qset,settings):
        if not email['value'] in obs_index['email']['high']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,email['value'],settings)
    
    # medium confidence emails
    qset=settings['medium_reference_sets']['email']
    for email in list_reference_set(qset,settings):
        if not email['value'] in obs_index['email']['medium']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,email['value'],settings)
            
    # checking userid
    # high confidence user_ids
    qset=settings['high_reference_sets']['userid']
    for userid in list_reference_set(qset,settings):
        if not userid['value'] in obs_index['userid']['high']:
            # this is an orphan value, needs to be removed
            remove_from_reference_set(qset,userid['value'],settings)
    
def validate_qradar(settings):
    """Adding indicators to QRadar reference sets. Keep in mind the categorization matrix,
    and use the indicators in the apropriate buckets. For this example here, we are using the
    following indicator buckets:
        -> Intel.High.Hashes, Intel.Medium.Hashes for MD5s
        -> Intel.High.IPs, Intel.Medium.IPs for IP addresses (ipv4)
        -> Intel.High.Domains, Intel.Medium.Domains for FQDNs"""
    headers = {'Version': '2.0', 'Accept': 'application/json','SEC':settings['SEC']}

    resp=requests.get(settings['base_url']+'reference_data/sets',headers=headers, verify=False)
    qradar_sets=json.loads(resp.text)
    for vset in settings['sets_to_validate'].keys():
        validated=False
        for qset in qradar_sets:
            if qset['name']==vset:
                validated=True
        if not validated:
            # creating reference sets not already in QRadar
            parameters={'name':vset,'element_type':settings['sets_to_validate'][vset]}
            resp=requests.post(settings['base_url']+'reference_data/sets',headers=headers,params=parameters,verify=False)
            if resp.status_code==201:
                syslog.syslog(syslog.LOG_INFO,'nyx->QRadar: Created reference set: %s' % vset)
                return True
            else:
                syslog.syslog(syslog.LOG_ERR,'nyx->QRadar: Unable to create additional reference set: %s' % vset)
                exit(-1)