import syslog

def add_ip(ip,settings,intel_list,tags):
    """ adds an IP to the pre-established list. The tags might or might not be supported by the control"""
    
    # your code here
    
    if "[condition for confirming a successful addition":
        syslog.syslog(syslog.LOG_INFO,'nyx->[this_plugin]: successfully added %s to %s'% (ip,intel_list))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->[this_plugin]: problems adding %s to %s'% (ip,intel_list))
        return False

def add_domain(domain,settings,intel_list,tags):
    """ adds an domain to the pre-established list. The tags might or might not be supported by the control"""
    
    # your code here
    
    if "[condition for confirming a successful addition":
        syslog.syslog(syslog.LOG_INFO,'nyx->[this_plugin]: successfully added %s to %s'% (ip,intel_list))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->[this_plugin]: problems adding %s to %s'% (ip,intel_list))
        return False

def list_ips(settings):
    """ retrieves the IP addresses from the control's specific lists for comparison"""
    ip_index={}
    # your code here
    return ip_index

def list_domains(settings):
    """ retrieves the domains from the control's lists for comparison.
    The index should be structured as a dictionary of {domain:intel_list}"""
    domain_index={}
    # your code here
    return domain_index

def remove_ip(ip,settings):
    """ removes an IP from the control"""
    
    # your code here
    
    
    if "[conditions for successful removal]":
        syslog.syslog(syslog.LOG_INFO,'nyx->[this_plugin]:: successfully removed %s'% (ip))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->[this_plugin]: problems removing %s'% (ip))
        return False
    
def remove_domain(domain,settings):
    """ removes a domain from the control"""
    
    # your code here
    
    
    if "[conditions for successful removal]":
        syslog.syslog(syslog.LOG_INFO,'nyx->[this_plugin]:: successfully removed %s'% (ip))
        return True
    else:
        syslog.syslog(syslog.LOG_ERR,'nyx->[this_plugin]: problems removing %s'% (ip))
        return False