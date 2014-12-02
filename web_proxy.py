def add_to_proxy(indicator, settings):
    """adds the domain to the blacklist for the proxy (only able to add the domains"""
    with open(settings['filename'],'a+') as web_proxy_file:
        # making sure that the indicator is acceptable
        if 'type' in indicator.keys() and indicator['type']=='A':
            web_proxy_file.write(indicator['domain']+'\n')
            return True