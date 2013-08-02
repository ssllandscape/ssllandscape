#!/usr/bin/python -u

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Explanatory note: This code is based on what johnath posted on 
# his blog in 2009:
# http://blog.johnath.com/2009/01/21/ssl-information-wants-to-be-free/
# It's been extended a good deal, but some things, like the
# implementation of the process queue, are still there. Thanks jonath!
# Since jonath wrote the original code during his time at Mozilla,
# we'll keep our scanner under the MPL, too.


# scan and update hosts to get their certificates

# TODO: replace string concatenation with interpolation

import sys
import string
import fileinput
import psycopg2
import time
import socket
import subprocess
import re
import os
import logging
from ConfigParser import SafeConfigParser

def printUsage():
  print """
Usage: scan.py <date> <SNI>
   - date is a date string like 09Feb2009
   - SNI is "sni" or "nosni"
"""
  sys.exit(1)

if (len(sys.argv) != 3):
  printUsage()

date = sys.argv[1]
sni = sys.argv[2]

if (sni != "sni" and sni != "nosni"):
  printUsage()

datesni = date + "_" + sni

home = os.environ["HOME"]

##############################################################
# BEGIN DEFINITION OF GLOBAL VARIABLES
TIMEOUT = 60 # seconds
MAX_PROCESSES = 128 # Make sure you have enough available file handles!
LOG_FILENAME = home + "/scan_" + datesni + ".log"
logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG, filemode='w')

# process queue
processQueue = []

# Database
conn = None
cursor = None
# table for hosts
tablenameHosts = "alexa_hosts_processed_" + datesni
# table for certs
tablenameCerts = "certificates_" + datesni
#table for intermediate certs
tablenameICerts = "icertificates_" + datesni

# Counters
successCount = 0

# Regexes
re_connRefused = re.compile("Connection refused")
re_handshakeFail = re.compile("(ssl handshake failure|alert unexpected message)")
re_unknownProto = re.compile("unknown protocol")
re_lookupfail = re.compile("gethostbyname")
re_certificate = re.compile("(-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----)", re.MULTILINE | re.DOTALL)

# Problems
re_selfSigned = re.compile("verify error:num=18:self signed certificate")
re_selfSigned19 = re.compile("verify error:num=19:self signed certificate")
re_noLocalIssuer = re.compile("verify error:num=20:unable to get local issuer certificate")
re_no1stcert = re.compile("verify error:num=21:unable to verify the first certificate")
re_expired = re.compile("verify error:num=10:certificate has expired")

re_verifyCode = re.compile("Verify return code: (.*)$", re.MULTILINE)
re_subject = re.compile("^subject=(.*)$", re.MULTILINE)
re_issuer = re.compile("^issuer=(.*)$", re.MULTILINE)
re_protocol = re.compile("    Protocol  : (.*)$", re.MULTILINE)
re_cipher = re.compile("    Cipher    : (.*)$", re.MULTILINE)
re_keylength = re.compile("Server public key is (\d+) bit", re.MULTILINE)
# END DEFINITION OF GLOBAL VARIABLES
##############################################################


def main():
    global conn, cursor, processQueue
  
    confparser = SafeConfigParser()
    confparser.read('general-db.conf')
    dbname = confparser.get('database', 'dbname')
    username = confparser.get('database', 'username')
    dbhost = confparser.get('database', 'host')
    password = confparser.get('database', 'password')

    # Open and init the DB
    connectString = "dbname='" + dbname + "' user='" + username + "' host='" + dbhost + "' password='" + password + "'"
    conn = psycopg2.connect(connectString)
    cursor = conn.cursor()

      
    print ""
    print ""
    print "For each host with port 443 open, get the certificate."

    try:
        sqlString = "SELECT host,rank FROM " + tablenameHosts + " WHERE verified IS TRUE ORDER BY rank"
        logging.info(sqlString)
        cursor.execute(sqlString)
    except Exception, e:
        print "Caught an exception while retrieving hosts. Aborting."
        print e
        sys.exit(1)
    conn.commit()
        
    rows = cursor.fetchall()
    print "Retrieved hosts from DB."
    print "Now retrieving certificates."
    print "..."

    total = len(rows)
    for i in range (len(rows)):    
        host = rows[i][0]
        rank = rows[i][1]
   
        checkHost(host, rank)

        # sleep statements to give it a break
        time.sleep(0.2)
        if ((i % 100) == 0):
            time.sleep(1)
        if ((i % 1000) == 0):
            time.sleep(1)
        if ( (i != 0) and (i % 5000) == 0):
            time.sleep(58) 
            
        # If the queue is still full, clear it before continuing
        while (len(processQueue) > MAX_PROCESSES):
            pollQueue()

    # Clear the queue
    while(len(processQueue) > 0):
        pollQueue()

    print "Closing connection."
    cursor.close()
    print ""
    print ""
    print "Done."
    print "Probed a total of " + str(total) + " hosts."
    print "Success on " + str(successCount) + " hosts." 
    print "Done at " + time.ctime()



def checkHost(host, rank) :
    global processQueue
    print "Retrieving certificate from " + host + "."
    host = host.rstrip()
    if (sni == "nosni"):
      parmarray = ["openssl", "s_client", "-connect", host + ":443", "-CAfile" , "ca-bundle.crt", "-showcerts"]
    else:
      parmarray = ["openssl", "s_client", "-connect", host + ":443", "-CAfile" , "ca-bundle.crt", "-showcerts",  "-servername", host]

    p = subprocess.Popen(parmarray, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, close_fds=True)
    p.stdin.close()
    processQueue.append((p, host, rank, time.time()))



def pollQueue() :
    global processQueue
    now = time.time()
    for (p, host, rank, starttime) in processQueue :
        p.poll()
        if(p.returncode != None) :
            processOutput(p.stdout.read(), host, rank)
            p.stdout.close()
            processQueue.remove((p, host, rank, starttime))
        elif now - starttime > TIMEOUT :
            # Taking too long, kill it.
            p.kill()
            processOutput("TIMEOUT", host, rank)
            logging.info("TIMEOUT: " + host)
            processQueue.remove((p, host, rank, starttime))




def processOutput(s, host, rank):

    global re_connRefused, re_handshakeFail, re_unknownProto
    global re_lookupfail, re_certificate, re_verifyCode
    global re_subject, re_issuer, re_protocol
    global re_cipher, re_keylength
    global conn, cursor, tablenameHosts, tablenameCerts
    global successCount
    
    # time at which we tried to grab the certificate
    visitdate = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())    
    
    crawlresult = None
    
    logging.info("Result for host " + host + " at rank " + str(rank) + ":")
    
    # search for a certificate
    res = re_certificate.search(s)

    if (res == None) :
    # No certificate suggests an error, try to log usefully
        if s == "TIMEOUT" :
            crawlresult = "TIMEOUT"
        elif re_connRefused.search(s) :
            crawlresult = "CONNECTION REFUSED"
        elif re_handshakeFail.search(s) :
            crawlresult = "SSL HANDSHAKE FAILURE"
        elif re_unknownProto.search(s) :
            crawlresult = "UNKNOWN PROTOCOL"
        elif re_lookupfail.search(s):
            crawlresult = "LOOKUP FAILURE"
        else :
            crawlresult = "OTHER FAILURE"
  
        host = host.rstrip()
        s = s.rstrip()
        logging.info("Failed to grab certificate! Reason: " + crawlresult + ". Updating host DB...")
        
        sqlString = "UPDATE " + tablenameHosts + " \
SET result=%s, errordata=%s, \
certgrabtime = '" + visitdate + "' WHERE host='" + host + "'"
        try:
            logging.info(sqlString, crawlresult, s)
            cursor.execute(sqlString, (crawlresult, s))
            logging.info("")
        except Exception, e:
            logging.error("UPDATE ERROR: UPDATE operation failed on host table on first update.")
            logging.error(e)
            logging.info("")
            
        conn.commit()
        logging.info("")
        logging.info("#######################################################")
        return
    
    
    # else, we had success
    crawlresult = "SUCCESS"
    successCount = successCount + 1
  
    # Now start extracting data. If no certs are found,
    # this is a reason tp PANIC as it means the extraction
    # is not working at all
    certs = re_certificate.findall(s)
    if (certs == None) :
        logging.error("PANIC: for " + host + " because of reason " + s)
        return
    
    # OK, we're good, continue...
    chainlength = len(certs)
    serverCert = certs[0]
    
    # store values for this certificate grab
    verifyCode = re_verifyCode.search(s).group(1)
    verifyCode = verifyCode.lstrip().rstrip()
    
    # self signed 18: first cert self signed
    selfSigned18Group = re_selfSigned.search(s)
    selfSigned18 = "False"
    if (selfSigned18Group != None):
        selfSigned18 = "True"

    # self signed 19: self signed cert in cert chain here
    selfSigned19Group = re_selfSigned19.search(s)
    selfSigned19 = "False"
    if (selfSigned19Group != None):
        selfSigned19 = "True"
        
    noLocalIssuerGroup = re_noLocalIssuer.search(s)
    noLocalIssuer20 = "False"
    if (noLocalIssuerGroup != None):
        noLocalIssuer20 = "True"
        
    no1stCertGroup = re_no1stcert.search(s)
    no1stCert21 = "False"
    if (no1stCertGroup != None):
        no1stCert21 = "True"
        
    expiredGroup = re_expired.search(s)
    expired10 = "False"
    if (expiredGroup != None):
        expired10 = "True"

    # It is possible to make openssl hiccup with unusual
    # setups (e.g. using GOST crypto). 
    # www.cryptopro.ru is an example -  we get "no peer
    # certificate sent" - then no subject or issuer is
    # extractable
    subject = ""
    try:
      subject = re_subject.search(s).group(1)
      subject = subject.lstrip().rstrip()
    except Exception, e:
      logging.error("ERROR for " + host + ": could not extract subject. Defaulting.")
      subject = "DEFAULTED"

    issuer = ""
    try:
      issuer = re_issuer.search(s).group(1)
      issuer = issuer.lstrip().rstrip()
    except Exception, e:
      logging.error("ERROR for " + host + ": could not extract issuer. Defaulting.")
      issuer = "DEFAULTED"

    protocol = re_protocol.search(s).group(1)
    cipher = re_cipher.search(s).group(1)
    
    keylength = ""
    try:
      keylength = re_keylength.search(s).group(1)
    except Exception, e:
      logging.error("ERROR for " + host + ": could not extract keylength. Defaulting.")
      keylength = "-1"
    
    logging.info("SUCCESS! Retrieved certificate. Updating certificate DB...")
    
    certShort = serverCert[:30]
    
    sqlStringHosts = "UPDATE " + tablenameHosts + " \
SET result= '" + crawlresult + "', \
certgrabtime = '" + visitdate + "', \
protocol='" + protocol + "', \
" + "cipher='" + cipher + "', \
keylength=" + keylength + " \
WHERE host='" + host + "'"
 
    # update host table
    try:
        logging.info(sqlStringHosts)
        cursor.execute(sqlStringHosts)
        logging.info("")
    except Exception, e:
        logging.error("ERROR: UPDATE operation failed on host table on second update.")
        logging.error(e)
        logging.info("")
    conn.commit() 
 
 
 
    # update certificate table   
    sqlStringCerts = "INSERT INTO " + tablenameCerts + " \
(host, cert, verifycode, subject, issuer, interm, hashcert, \
selfSigned18, selfSigned19, expired10, nolocalissuer20, no1stcert21) \
VALUES ('" + host + "', %s, %s, %s, %s, %s, md5(%s), %s, %s, %s, %s, %s)"

    intermNo = chainlength -1
    
    logSqlStringCerts = "INSERT INTO " + tablenameCerts + " \
(host, cert, verifycode, subject, issuer, interm, hashcert, \
selfSigned18, expired10, nolocalissuer20, no1stcert21) VALUES \
('" + host + "', '" + certShort + "', '" + verifyCode + "', \
'" + subject + "', '" + issuer + "', " + str(intermNo) + ", \
md5(cert)," + selfSigned18 + ", " + selfSigned19 + ", " + expired10 + ", \
" + noLocalIssuer20 + ", " + no1stCert21 + ")"
 

 
    try:
        logging.info(logSqlStringCerts)
        cursor.execute(sqlStringCerts, (serverCert, verifyCode, subject, issuer, intermNo, serverCert, selfSigned18, selfSigned19, expired10, noLocalIssuer20, no1stCert21))
        logging.info("")
    except Exception, e:
        logging.error("ERROR: INSERT operation failed on cert table.")
        logging.error(e)
    conn.commit()

    
    # now store intermediate certs, if any (chainlength > 1)
    if (chainlength > 1):
        logging.info("Cert for host " + host + " has " + str(chainlength-1) + " intermediate certs, inserting them...")
        # find out which position server cert has been stored at
        sqlSelectNoString = "SELECT last_value FROM " + tablenameCerts + "_no_seq"
    
        try:
            logging.info(sqlSelectNoString)
            cursor.execute(sqlSelectNoString)
        except Exception, e:
            logging.error("ERROR: Could not select no. of cert that I just inserted. \
Aborting insertion of intermediate certs.")
            logging.error(e)
            conn.commit()
            return
    
        conn.commit()
        certPositionRow = cursor.fetchone()
    
        if (certPositionRow == None):
            logging.error("ERROR: Could not retrieve no. of cert to which this intermediate cert is referring. \
Aborting insertion of intermediate certs.")
            return
        else:
            certPosition = certPositionRow[0]
            logging.info("Position is " + str(certPosition) + ", going to update there.")
        
        logging.info("Chainlength: " + str(chainlength))

        for level in range(chainlength):
            logging.info("Level: " + str(level))
            # this will take care that the end host cert is not stored as an intermediate
            if (level > 0):
                logging.info("Inserting intermediate cert no. " + str(level))
            
                currentCert = certs[level]
                chainpos = level
                shortCert = currentCert[:30]
            
                # store intermediate cert, position of cert it refers to, position in chain
                sqlInsertICertString = "INSERT INTO " + tablenameICerts + " \
(cert, certrefer, chainpos, hashcert) VALUES (%s,%s,%s, md5(%s))"
                logSqlInsertICertString = "INSERT INTO " + tablenameICerts + " \
(cert, certrefer, chainpos, hashcert) VALUES ('" + shortCert + "', \
" + str(certPosition) + ", " + str(chainpos) + ", md5(cert))"

                try:
                    logging.info(logSqlInsertICertString)
                    cursor.execute(sqlInsertICertString, (currentCert, certPosition, chainpos, currentCert))
                except Exception, e:
                    logging.error("ERROR: Could not insert intermediate cert.")
                    logging.error(e)
            
                conn.commit()
        logging.info("Done inserting intermediate certs.")
    logging.info("#######################################################")


main()
