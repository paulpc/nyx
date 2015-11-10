#!/bin/bash

# add this to the crontbab:
# */5 * * * * /opt/bro/intel/intel_refresh.sh > /var/log/intel.log

cd /opt/bro/intel/
rm CRITs.intel*
wget -q http://192.168.11.38/CRITs.intel
