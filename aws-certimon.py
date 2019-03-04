#!/usr/bin/env python

import os, ssl, socket, json
import logging,logging.config
import OpenSSL
import datetime
import urllib2
import argparse
import textwrap
import pprint
from time import sleep

"""
    Prerequisites:
       - pip install pyOpenSSL
"""

# Initialize Logger
logging.basicConfig(level=logging.INFO,
    filename='/tmp/dvt-certimon.log', 
    datefmt='%d-%m-%Y %H:%M:%S',
    #filemode='w',
    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('CertiMonSSLVerify')

# Initialize ArgParser
parser = argparse.ArgumentParser(
        prog='PROG', 
        formatter_class = argparse.RawDescriptionHelpFormatter,
        description = textwrap.dedent('''\
            CERTIFICATION MONITORING TOOL
            -----------------------------
                Monitoring TLS/SSL Certifcates expiration.
                Version 1.0
            '''),
        epilog="#"
        )   


# Create Parser
def set_parser():
    # Adding arguments
    parser.add_argument('--target', '-t', required=True, help='Target host IP address')
    parser.add_argument('--port', '-p', help='Target host Port')

    args = parser.parse_args()

    return args
    
# Create Logger
def set_logger(verbose='false', enable='false'):
    if verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(format="[+] %(message)s",level=logging.INFO)

    logger.setLevel(logging.INFO)


def ssl_expiry_datetime(target_host):

    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    ssl._create_default_https_context = ssl._create_unverified_context

    context = ssl.create_default_context()
    context.options &= ~ssl.OP_NO_SSLv3
    #try:
    conn = context.wrap_socket(
            socket.socket(socket.AF_INET), 
            server_hostname=target_host,
            )
    """except ssl.SSLError as serr:
        conn.close()
        logger.info('SSL Error occured:')
        logger.info('SSL handshake failed.\nError: {}'.format(serr))
    """

    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    logger.info('Connect to {}'.format(target_host))
    conn.connect((target_host, 443))

    print("---------------------------")
    ssl_info = conn.getpeercert()
    logger.info('GetPeerCert:  {}'.format(ssl_info))
    #pprint.pprint(ssl_info)
    print("---------------------------")

    # parse the string from the certificate into a Python datetime object
    will_expire_in = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
    logger.info('Expiry return result: {}'.format(will_expire_in))
    return will_expire_in 
def get_SSL_Expiry_date(target_host, target_port=443):

    cert = ssl.get_server_certificate((target_host,target_port))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

    """
    if x509.has_expired():
        logger.info('Certificate for {} is expired'.format(target_host))
        print ("SSL Cert for " + target_host + " has expired)")
    """

    #return x509.get_notAfter()
    #Return the timestamp at which the certificate stops being valid in the appropriate format
    return datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'),'%Y%m%d%H%M%SZ')


def ssl_valid_time_remaning(target_host, target_port=443):
    """Get the number of days left in a cert's lifetime."""
    #expires = ssl_expiry_datetime(target_host)
    expires = get_SSL_Expiry_date(target_host, target_port)

    logger.info('Certificate for {} expires at {}'.format(target_host, expires.isoformat()))

    return expires - datetime.datetime.utcnow()


"""
"""
def main():
    set_logger('true')
    arg = set_parser()

    target_host = arg.target
    if arg.port is not None:
        target_port = arg.port
    else:
        target_port = 443


    print("Target: "+ target_host + " Port: " + str(target_port))

    logger.info('Certiticate Check process starts...')
    logger.info('Certificate Check target: {}:{}'.format(target_host,target_port))

    url = "https://" + target_host
    buffer_days = 30
    #xx = get_SSL_Expiry_date(target_host)
    #print("decode2: " + str(datetime.datetime.strptime(xx.decode('utf-8'),'%Y%m%d%H%M%SZ').isoformat()))
    #print("Now: " + str( datetime.datetime.utcnow().isoformat() ))
    #print("SUB: " + str(datetime.datetime.strptime(xx.decode('utf-8'),'%Y%m%d%H%M%SZ') - datetime.datetime.utcnow()))

    #logger.info('Certiticate Check using get_SSL_Expiry_date is more reliable: {}'.format(get_SSL_Expiry_date(target_host)))

    """
    will_expire_in = ssl_valid_time_remaning(target_host)
    print(">>>>>>" + str(will_expire_in))
    exit()
    #raise Exception(will_expire_in.isoformat())
    """
    try:
        print("Target Host: " + target_host)
        will_expire_in = ssl_valid_time_remaning(target_host, target_port)
    except ssl.CertificateError as err:
        logger.info('SSL Certificate Error for {} is : {}'.format(target_host, err))
        print("ERROR: Certificate Error")
        print("\t" + err)
    except ssl.SSLError as err:
        logger.info('SSL Error for {} is : {}'.format(target_host, err))
        print("ERROR: SSL Error")
        print("\t" + err)
    except socket.timeout as err:
        print("ERROR: Socket Timeout")
        print("\t" + err)
        logger.info('Socket Timeout for {} is : {}'.format(target_host, err))
    else:
        if will_expire_in < datetime.timedelta(days=0):
            print("\tCert will expire")
            logger.info('Cert for {} is expired ({})'.format(target_host, will_expire_in))
        elif will_expire_in < datetime.timedelta(days=buffer_days):
            print("\tCert is expired " + will_expire_in)
            logger.info('Cert for {} expired: {}'.format(target_host, will_expire_in))
        else:
            print("\tCert is fine")
            logger.info('Cert for target "{}" is Okey, will expire in {}'.format(target_host, will_expire_in))
        print("\tExpire in " + str(will_expire_in))
    finally:
        logger.info('Certificate Check process finished.')

        print("EXIT")
        exit()
        print("CURL URL " + url)
        sleep(0.1)
        try:
            response = urllib2.urlopen(url)
            print (response.info())
        except:
            logger.info('Error occured during URL curl..')
        finally:
            response.close()
        #data = json.loads(response.read())
        #Best practice: Closing the file

if __name__ == '__main__':
    main()
