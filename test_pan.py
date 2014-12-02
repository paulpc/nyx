from palo_alto import *
from nyx import read_configs
settings=read_configs('nyx.conf')
print "adding domain"
rs=add_site_to_pan('bad_site.ro',settings['palo_alto'],settings['palo_alto']['url_block_list'])
print rs.text
print "adding IP"
rs=add_ip_to_pan('108.89.89.89','crits_test',settings['palo_alto'],settings['palo_alto']['ip_alert_list'])
print rs.text
