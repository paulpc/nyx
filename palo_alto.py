import requests
import syslog
import xmltodict
import re
from common_methods import get_sources

def add(indicator, settings, plist):
    """ adds indicator in the medium-confidence watch list in Palo Alto """
    if 'type' in indicator.keys() and indicator['type']=='Address - ipv4-addr':
        # adding an ip
        res=add_ip_to_panorama(indicator['ip'],get_sources(indicator),settings,settings[plist])
        bad_indicator=indicator['ip']
    elif 'type' in indicator.keys() and indicator['type']=='A':
        # adding the domain
        res=add_site_to_panorama(indicator['domain'],settings,settings[plist])
        bad_indicator=indicator['domain']
    else:
        syslog.syslog('nyx->PAN: I do not know how to handle the following type of observable: %s' % indicator['type'])
    
    if res and res.status_code == 200 and 'code="20"' in res.text:
        syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully added %s to %s '% (bad_indicator, settings[plist]))
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
    
def add_ip(ip,settings,pan_list,tags):
    """ adds an ip in the address group. Will have to create the object first then the address group"""
    # adding the adress object
    tag_str="<member>"+pan_list+"</member>"
    for tag in tags:
        clean_tag='dvn_intel_'+tag.replace(" ","_")
        tag_str+="<member>"+clean_tag+"</member>"
    url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/shared/address/entry[@name='"+ip+"']&element=<ip-netmask>"+ip+"/32</ip-netmask><tag>"+tag_str+"</tag>"
    r_actor=requests.get(url,verify=False)
    if r_actor and r_actor.status_code == 200 and 'code="20"' in r_actor.text:
        syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully added %s to %s '% (ip, pan_list))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->PAN: problems adding %s to %s '% (ip, pan_list))
        print r_actor.text
        return False

def remove_ip_from_panorama(ip,settings):
    """ removes an IP address from panorama """
    url=settings['url']+'?type=config&action=delete&key='+settings['api_key']+"&xpath=/config/shared/address/entry[@name='"+ip+"']"
    r_actor=requests.get(url,verify=False)
    if r_actor and r_actor.status_code == 200 and 'code="20"' in r_actor.text:
        syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully removed %s'% (ip))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->PAN: problems removing %s'% (ip))
        print r_actor.text
        return False
    
def add_site_to_pan(site,settings,pan_list):
    """ adds a url to Palo Alto custom URL list"""
    url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name=%27"+pan_list+'%27]/list&element=<member>'+site+'</member>'
    r=requests.get(url,verify=False)
    return r

def add_domain(site,settings,pan_list):
    """ adds a url to Palo Alto custom URL list"""
    url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/shared/profiles/custom-url-category/entry[@name=%27"+pan_list+'%27]/list&element=<member>'+site+'</member>'
    r=requests.get(url,verify=False)
    # if this is a domain, adding the * subdomains
    if len(site.split('.'))<3:
        url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/shared/profiles/custom-url-category/entry[@name=%27"+pan_list+'%27]/list&element=<member>'+"*."+site+'</member>'
        r=requests.get(url,verify=False)
    if r and r.status_code == 200 and 'code="20"' in r.text:
        syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully added %s to %s '% (site, pan_list))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->PAN: problems adding %s to %s '% (site, pan_list))
        print r.text
        return False

def remove_site_from_panorama():
    """ removes a fqdn from panorama """
    
def check_url(site,settings):
    # key may vary depending on the system you're connecting to (see note above)
    url = settings['url']+'?type=op&key='+settings['api_key']+'&cmd=<test><url>'+site+'</url></test>'
    r = requests.get(url, verify=False)
    return r.text


def pan_commit(settings):
    """Once we are happy with the settings, we will commit them to PAN
    partial commits are not as effective as hoped
    """
    url=settings['url']+'?type=commit&cmd=<commit></commit>&key='+settings['api_key']
    r=requests.get(url,verify=False)
    if r.status_code == 200 and 'code="19"'in r.text:
        syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully sent commit command')
        

def list_ips(settings):
    """ returns a list of all the addresses in the palo alto config - doing a diff in memory of this process to speed up the process"""
    palo_ip_index={}
    url=settings['url']+'/?type=config&action=get&key='+settings['api_key']+'&xpath=/config/shared/address'
    result = xmltodict.parse(requests.get(url, verify=False).text)
    if result['response']['@status']=='success':
        for address in result['response']['result']['address']['entry']:
            if 'tag' in address.keys():
                if 'ip-netmask' in address.keys():
                    # i know i am making an assumption that we're only dealing with /32 netmasks here
                    if isinstance(address['ip-netmask'],dict):
                        clean_address == address['ip-netmask']['#text'].split('/')[0]
                    elif isinstance(address['ip-netmask'],unicode):
                        clean_address=address['ip-netmask'].split('/')[0]
                    palo_ip_index[clean_address]=address['tag']['member']
                elif 'ip-rage' in address.keys():
                    syslog.syslog(syslog.LOG_INFO,"nyx->PAN: range probably means it's an internal object [%s]" % address['@name'])
                elif 'fqdn' in address.keys():
                    syslog.syslog(syslog.LOG_INFO,"nyx->PAN: fqdn means probably an internal object [%s]"% address['@name'])
            else:
                syslog.syslog(syslog.LOG_INFO,"nyx->PAN: address object does not have any tags associated with it [%s]"% address['@name'])    
    return palo_ip_index

def list_domains(settings):
    """ returns a list of all the urls in the two inteligence-based custom url lists in the config file """
    palo_url_index={}
    for url_cat in settings['map']['domain'].values():
        url=settings['url']+"/?type=config&action=get&key="+settings['api_key']+"&xpath=/config/shared/profiles/custom-url-category/entry[@name='"+url_cat+"']/list"
        result = xmltodict.parse(requests.get(url, verify=False).text)
        if result['response']['@status']=='success':
            for member in result['response']['result']['list']['member']:
                if isinstance(member,dict):
                    if member['#text'][0]=="*":
                        palo_domain=member['#text'][2:]
                    else:
                        palo_domain=member['#text']
                    palo_url_index[palo_domain]=url_cat
                elif isinstance(member,unicode):
                    if member[0]=="*":
                        palo_domain=member[2:]
                    else:
                        palo_domain=member
                    palo_url_index[palo_domain]=url_cat
    return palo_url_index

def list_tags(settings):
    """ lists the tags in panorama"""
    palo_tag_index=[]
    url=settings['url']+"/?type=config&action=get&key="+settings['api_key']+"&xpath=/config/shared/tag"
    result = xmltodict.parse(requests.get(url, verify=False).text)
    if result['response']['@status']=='success':
        for tag in result['response']['result']['tag']['entry']:
            palo_tag_index.append(tag['@name'])
    return palo_tag_index

def add_tag(tag,settings):
    """ adds an ip in the address group. Will have to create the object first then the address group"""
    # adding the adress object
    url=settings['url']+'?type=config&action=set&key='+settings['api_key']+"&xpath=/config/shared/tag/entry[@name='"+tag+"']&element=<color>color1</color>"
    r_actor=requests.get(url,verify=False)
    if r_actor and r_actor.status_code == 200 and 'code="20"' in r_actor.text:
        syslog.syslog(syslog.LOG_INFO,'nyx->PAN: successfully added tag: %s '% (tag))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->PAN: problems adding tag: %s '% (tag))
        return False
