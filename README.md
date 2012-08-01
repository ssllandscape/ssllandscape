ssllandscape
============

Source code for our paper: "The SSL Landscape - a thorough analysis of the X.509 PKI using active and passive measurements"

scan/
scan.py - a cleaned-up version of our scanner

sql/
checkExpiry+Interm.sql - script to find expired certificates. Returns TRUE for expired certs. Checks include intermediate certificates.

checkExpiry.sql - script to find expired certificates. Returns TRUE for expired certs. Check *do not* include intermediate certificates (only end-host cert)

