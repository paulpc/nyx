def get_sources(indicator):
    """ appends the sources of an indicator in a string"""
    source_arr=[]
    if 'source' in indicator.keys():
        for source in indicator['source']:
            if not source in source_arr:
                source_arr.append(source['name'])
    if source_arr:
        return ','.join(source_arr)
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
    processed_campaigns=[indicator['campaign'][0]['name']]
    confidence=initial_score[indicator['campaign'][0]['confidence']]
    for campaign in indicator['campaign']:
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