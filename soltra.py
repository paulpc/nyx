from common_methods import *
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_11 as tm11
from libtaxii.constants import *
from stix.core import STIXPackage
import requests
import json
import uuid


def poll_feed(settings,subscription):
    """ polls a TAXII feed"""
    client = tc.HttpClient()
    client.set_auth_type(tc.HttpClient.AUTH_BASIC)
    client.set_use_https(True)
    client.set_auth_credentials({'username': settings['username'], 'password': settings['password']})

    msg_id=uuid.uuid4().hex
    poll_request1 = tm11.PollRequest(message_id=msg_id,collection_name=settings['subscriptions'][subscription]['collection_name'],subscription_id=settings['subscriptions'][subscription]['subscription_id'])
    poll_xml=poll_request1.to_xml()
    http_resp = client.call_taxii_service2(settings['server'], '/taxii-data/', VID_TAXII_XML_11, poll_xml)
    taxii_message = t.get_message_from_http_response(http_resp, poll_request1.message_id)
    observables={}
    
    indicators = json.loads(taxii_message.to_json())
    if 'content_blocks' in indicators.keys():
        for indicator in indicators['content_blocks']:
            open('/tmp/indicator.xml','w').write(indicator['content'])
            indi=STIXPackage.from_xml('/tmp/indicator.xml').to_dict()
            if 'observables' in indi.keys():
                for obs in indi['observables']['observables']:
                    if 'object' in obs.keys():
                        ot=obs['object']['properties']['xsi:type']
                        if ot in settings['supported_objects'].keys() and not ot in observables.keys():
                            observables[ot]=[]
                        if ot in settings['supported_objects'].keys() and settings['supported_objects'][ot] in obs['object']['properties'].keys():
                            # note, you will only be able to process one property per object type, but you also know there's only one property you can process
                            try:
                                observables[ot].append(obs['object']['properties'][settings['supported_objects'][ot]])
                            except:
                                print "[-] you're dumb"
                                print supported_objects[ot], "not in:", obs['object']
    return observables
    
  
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