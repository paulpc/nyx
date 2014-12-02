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

def list_fqdns(settings,limit=0):
    """exports a list of the FQDNs in CRITs, basing the confidence on the campaign confidence"""
    fqdns=[]
    params={'username':settings['username'],'api_key':settings['api_key'],'limit':settings['offset'],'offset':0}
    url=settings['url']+'domains/'
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
                if potential_result['campaign'] and get_intel_confidence(potential_result) in ['medium','high']:
                    #print potential_result
                    fqdns.append(potential_result) 
            params['offset']+=settings['offset']
            if not limit:
                total=res['meta']['total_count']            
    return fqdns

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