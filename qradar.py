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
            add_to_reference_set(reference_set_map['userid'], indicator['organizational_id'], get_sources(indicator), settings)
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