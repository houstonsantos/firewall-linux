#!/bin/bash

HOJE=$(date --date "0 day ago" +%d/%m/%Y)
/usr/bin/sarg -f /etc/sarg/sarg.conf -d $HOJE-$HOJE 
