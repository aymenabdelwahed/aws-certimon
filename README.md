# CERTIFICATE MONITORING: 
  Usefull tool for TLS/SSL certificates' monitoring

## aws-certimon script ##
Keeping track of certificate expiration dates is very important. However, tracking services that use SSL certificates is mundane, tedious and we often forget about them. This developed python script will automatically check SSL/TLS certificates expiry dates.

This code will help identifying expired certificates and especially hosts on which certificates will expire and the remaining time period.
TLS is the successor to Secure Sockets Layer (SSL). Both of TLS and SSL allows a client to verify the identity of the server and, optionally, allows the server to verify the identity of the client. 

## HOW TO USE  ? ##
Check the expiration date for the FQDN expired.badssl.com over the HTTPS standard port
'''
aws-certimon --target expired.badssl.com --port 443
'''
