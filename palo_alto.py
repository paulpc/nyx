import requests
import syslog
from common_methods import get_sources

def palo_alto(indicator, settings, plist):
    """ adds indicator in the medium-confidence watch list in Palo Alto """
    if 'type' in indicator.keys() and indicator['type']=='Address - ipv4-addr':
        # adding an ip
        res=add_ip_to_pan(indicator['ip'],get_sources(indicator),settings,settings[plist])
        bad_url=indicator['ip']
    elif 'type' in indicator.keys() and indicator['type']=='A':
        # adding the domain
        res=add_site_to_pan(indicator['domain'],settings,settings[plist])
        bad_url=indicator['domain']
    else:
        syslog.syslog('nyx->PAN: I do not know how to handle the following type of observable: %s' % indicator['type'])
    
    if res and res.status_code == 200 and 'code="20"' in res.text:
        syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully added %s to %s '% (bad_url, settings[plist]))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->PAN: Palo Alto potential issues: %s' % res.text)
        return False

def add_ip_to_pan(ip,source,settings,pan_list):
    """ adds an ip in the address group. Will have to create the object first then the address group"""
    # adding the adress object
    
    url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address/entry[@name='"+ip+"']&element=<ip-netmask>"+ip+"/32</ip-netmask>"
    r_actor=requests.get(url,verify=False)
    if r_actor.status_code==200 and 'code="20"' in r_actor.text:
        # if we successfully added the addressobject, adding it to the apropriate address group
        url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address-group/entry[@name='"+pan_list+"']&element=<static><member>"+ip+"</member></static>"
        r=requests.get(url,verify=False)
        return r
    else:
        return r_actor

def add_site_to_pan(site,settings,pan_list):
    """ adds a url to Palo Alto custom URL list"""
    url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name=%27"+pan_list+'%27]/list&element=<member>'+site+'</member>'
    r=requests.get(url,verify=False)
    return r

def pan_commit(settings):
    """Once we are happy with the settings, we will commit them to PAN
    partial commits are not as effective as hoped
    """
    url=settings['url']+'?type=commit&cmd=<commit></commit>&key='+settings['api_key']
    r=requests.get(url,verify=False)
    return r
