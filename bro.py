from common_methods import *
def alert_bro(indicator, settings):
    """ adds indicator to the bro intel framework based on the type of indicator
    #fields indicator       indicator_type  meta.source     meta.url        meta.do_notice  meta.if_in
    Intel::ADDR
    Intel::URL
    Intel::SOFTWARE
    Intel::EMAIL
    Intel::DOMAIN
    Intel::USER_NAME
    Intel::FILE_HASH
    Intel::FILE_NAME
    Intel::CERT_HASH
    """
    # for now, we're mapping really basic elements:
    indicator_map=settings['indicator_map']
    with open(settings['filename'],'a+') as bro_file:
        if 'type' in indicator.keys() and indicator['type']=='Address - ipv4-addr':
            # adding an ip
            bro_file.write('\t'.join([indicator['ip'],indicator_map[indicator['type']],get_sources(indicator),'T'])+'\n')
            return True
        elif 'type' in indicator.keys() and indicator['type']=='A':
            # adding the domain
            bro_file.write('\t'.join([indicator['domain'],indicator_map[indicator['type']],get_sources(indicator),'T'])+'\n')
            return True
        elif 'md5' in indicator.keys():
            # adding the md5 hash and the filename
            if indicator['md5']:
                bro_file.write('\t'.join([indicator['md5'],indicator_map['md5'],get_sources(indicator),'T'])+'\n')
            if indicator['filename']:
                bro_file.write('\t'.join([indicator['filename'],indicator_map['filename'],get_sources(indicator),'T'])+'\n')
            return True
        elif 'x_mailer' in indicator.keys():
            # adding the email address - for now, assuming spearphish, therefore focusing on the <<from>> field
            bro_file.write('\t'.join([indicator['from'],indicator_map['email'],get_sources(indicator),'T'])+'\n')
            return True
        else:
            syslog.syslog('nyx->BRO: I do not know how to handle the following type of observable: %s' % indicator['type'])
            return False