from common_methods import *
import requests

def list_indicators(settings):
    """exports a list of the indocators in CRITs"""
    params={'username':settings['username'],'api_key':settings['api_key'],'limit':settings['offset'],'offset':0}
    url=settings['url']+'indicators/'
    total=settings['offset']
    indicators=[]
    while params['offset'] <= total:
        #print total,params['offset']
        r = requests.get(url, params=params, verify=False)
        if r.status_code == 200:
            res=r.json()
            for potential_result in res['objects']:
                # only getting indicators meaning something
                if potential_result['campaign'] and get_intel_confidence(potential_result) in ['medium','high']:
                    indicators.append(potential_result) 
            params['offset']+=settings['offset']
            total=res['meta']['total_count']
    return indicators

def list_ips(settings, limit=0):
    """exports a list of the IPs in CRITs, basing the confidence on the campaign confidence"""
    ips=[]
    params={'username':settings['username'],'api_key':settings['api_key'],'limit':settings['offset'],'offset':0}
    url=settings['url']+'ips/'
    #total=settings['offset']
    total=limit
    while params['offset'] <= total:
        #print total,params['offset']
        r = requests.get(url, params=params, verify=False)
        if r.status_code == 200:
            res=r.json()
            for potential_result in res['objects']:                
                # only getting indicators meaning something - don't care about low and unknowns
                if potential_result['campaign'] and get_intel_confidence(potential_result) in ['medium','high']:
                    #print potential_result
                    ips.append(potential_result) 
            params['offset']+=settings['offset']
            if not limit:
                total=res['meta']['total_count']            
    return ips

def normalize_ip(indicator,indicators):
    """ normalizes the ip and adds it to the indicator if it doesn't already exist"""
    if indicator['type']=='Address - ipv4-addr':
        ip=indicator['ip']
        tags=get_sources(indicator)
        if ip in indicators['incoming']['ip'].keys():
            for tag in tags:
                if not tag in indicators['incoming']['ip'][ip]['tags']:
                    indicators['incoming']['ip'][ip]['tags'].append(tag)
        else:
            indicators['incoming']['ip'][ip]={'confidence':get_intel_confidence(indicator),'tags':tags}
    return indicators

            
def list_fqdns(settings,limit=0):
    """exports a list of the FQDNs in CRITs, basing the confidence on the campaign confidence"""
    fqdns=[]
    params={'username':settings['username'],'api_key':settings['api_key'],'limit':settings['offset'],'offset':0}
    url=settings['url']+'domains/'
    if limit:
        total=limit
    else:
        total=settings['offset']+1
    while params['offset'] <= total:
        r = requests.get(url, params=params, verify=False)
        if r.status_code == 200:
            res=r.json()
            for potential_result in res['objects']:                
                if potential_result['campaign'] and get_intel_confidence(potential_result) in ['medium','high']:
                    fqdns.append(potential_result) 
            params['offset']+=settings['offset']
            if not limit:
                total=res['meta']['total_count']
    return fqdns

def normalize_fqdn(indicator,indicators):
    """ normalizes the domain and adds it to the indicator if it doesn't already exist"""
    if indicator['type']=='A':
        fqdn=indicator['domain']
        tags=get_sources(indicator)
        if fqdn in indicators['incoming']['domain'].keys():
            for tag in tags:
                if not tag in indicators['incoming']['domain'][fqdn]['tags']:
                    indicators['incoming']['domain'][fqdn]['tags'].append(tag)
        else:
            indicators['incoming']['domain'][fqdn]={'confidence':get_intel_confidence(indicator),'tags':tags}
    return indicators

def list_samples(settings,limit=0):
    """exports a list of the samples in CRITs, basing the confidence on the campaign confidence"""
    samples=[]
    params={'username':settings['username'],'api_key':settings['api_key'],'limit':settings['offset'],'offset':0}
    url=settings['url']+'samples/'
    if limit:
        total=limit
    else:
        total=settings['offset']
    while params['offset'] <= total:
        #print total,params['offset']
        r = requests.get(url, params=params, verify=False)
        if r.status_code == 200:
            res=r.json()
            for potential_result in res['objects']:                
                # only getting indicators meaning something - don't care about lows and unknowns
                if potential_result['campaign'] and get_intel_confidence(potential_result) in ['medium','high'] and (potential_result['md5'] or potential_results['fiename']):
                    #print potential_result
                    samples.append(potential_result) 
            params['offset']+=settings['offset']
            if not limit:
                total=res['meta']['total_count']           
    return samples

def normalize_sample(indicator,indicators):
    """ normalizes the sample and adds it to the indicator if it doesn't already exist"""
    if 'md5' in indicator.keys():
        md5=indicator['md5']
        # I need to make sure to check for all the necessary properties here filename, sha, sha256z, et cetera
        tags=get_sources(indicator)
        if fqdn in indicators['incoming']['sample'].keys():
            for tag in tags:
                if not tag in indicators['incoming']['domain'][fqdn]['tags']:
                    indicators['incoming']['domain'][fqdn]['tags'].append(tag)
        else:
            indicators['incoming']['domain'][fqdn]={'confidence':get_intel_confidence(fqdn),'tags':tags}
    return indicators

def list_targets(settings):
    """exports a list of the targets in CRITs"""
    targets=[]
    params={'username':settings['username'],'api_key':settings['api_key'],'limit':settings['offset'],'offset':0}
    url=settings['url']+'targets/'
    total=settings['offset']
    while params['offset'] <= total:
        #print total,params['offset']
        r = requests.get(url, params=params, verify=False)
        if r.status_code == 200:
            res=r.json()
            for potential_result in res['objects']:                
                targets.append(potential_result) 
            params['offset']+=settings['offset']
            total=res['meta']['total_count']            
    return targets