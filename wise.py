from common_methods import *
def alert_wise(indicator, settings,csi):
    """ adds indicator to wise service file
    # To load local files, set a unique section title starting with file:
# Type should be ip, domain, md5, email
# Files are assumed to be CSV or use format=tagger
[file:blah]
file=/tmp/test.ips
type=ip
tags=TAG1,TAG2
#column=1
    """
    # for now, we're mapping really basic elements:

    indicator_map=settings['indicator_map']
    
    if 'type' in indicator.keys() and indicator['type']=='Address - ipv4-addr':
        # adding an ip
        with open(settings['filename']+indicator_map[indicator['type']]+csi+'.txt','a+') as wise_file:
            wise_file.write(indicator['ip']+'\n')
        return True
    elif 'type' in indicator.keys() and indicator['type']=='A':
        # adding the domain
        with open(settings['filename']+indicator_map[indicator['type']]+csi+'.txt','a+') as wise_file:
            wise_file.write(indicator['domain']+'\n')
        return True
    elif 'md5' in indicator.keys():
        # adding the md5 hash and the filename
        with open(settings['filename']+indicator_map[indicator['type']]+csi+'.txt','a+') as wise_file:
            if indicator['md5']:
                wise_file.write(indicator['md5']+'\n')
        return True
    elif 'x_mailer' in indicator.keys():
        # adding the email address - for now, assuming spearphish, therefore focusing on the <<from>> field
        with open(settings['filename']+indicator_map[indicator['type']]+csi+'.txt','a+') as wise_file:
            wise_file.write(indicator['from']+'\n')
        return True
    else:
        syslog.syslog('nyx->wise: I do not know how to handle the following type of observable: %s' % indicator['type'])
        return False