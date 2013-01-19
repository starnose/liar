###################################################################################
# dnsliar.py, main file for Liar proxy
###################################################################################
#
# Copyright 2013 David Hicks (Starnose Ltd)
#
# This file is part of Liar
#
#    Liar is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3
#    as published by the Free Software Foundation, 
#
#    Liar is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Liar.  If not, see <http://www.gnu.org/licenses/>.
#
###################################################################################
#
# This is Liar
# Liar lies about its identity and will pretend to be *everyone* you've ever loved
#
###################################################################################
#
# This is the main file for liar and contains the argument parsing code and a 
# minimal DNS server implementation. When a request for a new server is encountered
# it starts a new network interface and fires off a liarServer thread from
# liarserver.py
#
###################################################################################

import socket
import threading
import time
import string
import os
import liarserver
import getopt
import sys
import logging 

from liarutils import *

class dodgyDNSServer(threading.Thread):

   def __init__(self, rootcert, rootkey, template, cafile, outputdir = '.', ports = (("443","tcp")), interface="eth0", ipstart="192.168.1.101", loglvl = logging.DEBUG):
      self.interface = interface
      self.nextip = ipstart
      self.rootcert = rootcert
      self.rootkey = rootkey
      self.template = template
      self.cafile = cafile
      self.outputdir = outputdir
      self.ports = ports
      self.interface = interface
      self.ipstart = ipstart
      self.database = dict()
      self.log = logging.getLogger('mainlog')
      self.loglvl = loglvl
      self.log.setLevel(loglvl)
      threading.Thread.__init__ ( self )

   def run(self):
     self.log.debug("Entering dns server run")
     udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     udps.bind(('',53))

     counter = 0  
     try:
        while 1:
           self.log.debug("Entering receive loop")
           data, addr = udps.recvfrom(1024)
           server = self.getServer(data)

           print "DNS Request from %s %s - " % addr
           ftd, plain = hexdump(data, len(data))
           print ftd
           self.log.debug(ftd)
           self.log.debug(plain)

           if server in self.database:
              self.log.debug("Got a hit on %s, no new IF needed" % (server))
              respIP = self.database[server]
           else:
              self.log.debug("Now be setting up interface %s:%d with address %s" % (self.interface, counter, self.nextip))
              createServerCert(server, self.rootcert, self.rootkey, self.template, os.path.join(self.outputdir, "certs"))
              os.system("/sbin/ifconfig %s:%d %s netmask 255.255.255.0 up" % (self.interface, counter, self.nextip))
              liarserver.liarServer(server, self.ports, self.nextip, os.path.join(outputdir, "logs"), os.path.join(self.outputdir, "certs"), self.cafile, self.loglvl).start()
              self.log.debug("Server set up for %s on %s" % (server, self.nextip))
              self.database.update( {server : self.nextip} )
              respIP = self.nextip
              counter =  counter + 1
              self.ipincr()

           respmesg = self.makeResponse(respIP, data)

           print "DNS Response to %s %s - " % addr
           ftd, plain = hexdump(respmesg, len(respmesg))
           print ftd

           udps.sendto(respmesg, addr)
           self.log.debug("Responding: %s -> %s" % (server, self.nextip))

     except KeyboardInterrupt:
        os._exit(1)
     except Exception, e:
        print "Something died: ", e 
        udps.close()

   def ipincr(self):
      a,b,c,d = self.nextip.split('.')
      self.log.debug("" + a + " " + b + " " + c + " " + d)
      if int(d) < 255:
         d = int(d) + 1
         self.nextip = ".".join((a,b,c,str(d)))
      else:
         self.log.debug("MAJOR DNS error, run out of IP space")


   def getServer(self, data):
      server=''
      tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
      if tipo == 0:                     # Standard query
         ini=12
         lon=ord(data[ini])
         while lon != 0:
            server+=data[ini+1:ini+lon+1]+'.'
            ini+=lon+1
            lon=ord(data[ini])
      return server[:-1]

   def makeResponse(self, ip, data):
      packet=''
      packet+=data[:2] + "\x81\x80"
      packet+=data[4:6] + data[4:6] + '\x00\x00\x00\x00'             # Questions and Answers Counts
      packet+=data[12:]                                              # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
      return packet


def usage ():
   print "Command usage -"
   print str(sys.argv[0]) + " -p <port> -u <port> -s <sslport> -r <rootcert> -k <rootkey> -t <templatefile> -c <cafile> -i <interface> -a <startaddress> -d <tmpdir> -n -h -?"
   print "-p\ttcp port to listen on. Multiple -p arguments allowed."
   print "-u\tudp port to listen on. Multiple -u arguments allowed."
   print "-s\tSSL tcp port to listen on. Multiple -s arguments allowed. 443 used if none given"
   print "-r\troot CA certificate file, containing the public portion of the fake root in use"
   print "-k\troot CA key file, containing the private portion of the fake root in use"
   print "-t\ttemplate file to use during certificate generation"
   print "-c\tfile containing third party CA certificates"
   print "-i\tnetwork interface to be used for interface cloning"
   print "-a\tstarting ipaddress for multi-ip use."
   print "-d\tdata/output directory. Liar is probably going to make a bit of a mess"
   print "-n\tswitch off logging"
   print "-h/-?\t show this help text and exit"



if __name__=='__main__': 
   portlist = []
   outputdir="."
   cafile = ""
   loglvl = logging.DEBUG

   # set up arg processor
   try:
      opts, args = getopt.getopt(sys.argv[1:], "p:u:s:r:k:t:c:i:a:d:nh?")
   except getopt.GetoptError, err:
      print err
      usage()
      sys.exit(1)

   # process args
   for opt, val in opts:
      if opt == "-p":
         if int(val, 10) < 1 :
            print "Invalid port value %s" % val
            usage()
            sys.exit(1)
         elif int(val, 10) > 65535 :
            print "Invalid port value %s" % val
            usage()
            sys.exit(1)
         else:
            portlist.append((int(val,10), "tcp"))
      if opt == "-u":
         if int(val, 10) < 1 :
            print "Invalid port value %s" % val
            usage()
            sys.exit(1)
         elif int(val, 10) > 65535 :
            print "Invalid port value %s" % val
            usage()
            sys.exit(1)
         else:
            portlist.append((int(val,10), "udp"))
      if opt == "-s":
         if int(val, 10) < 1 :
            print "Invalid port value %s" % val
            usage()
            sys.exit(1)
         elif int(val, 10) > 65535 :
            print "Invalid port value %s" % val
            usage()
            sys.exit(1)
         else:
            portlist.append((int(val,10), "stcp"))
      elif opt == "-r":
         rootcertfile = val
      elif opt == "-k":
         rootkeyfile = val
      elif opt == "-t":
         templatefile = val
      elif opt == "-c":
         cafile = val
      elif opt == "-i":
         interface = val
      elif opt == "-a":
         startaddress = val
      elif opt == "-d":
         outputdir = val
      elif opt == "-n":
         loglvl = logging.INFO
      elif opt in ("-h", "-?"):
         usage()
         sys.exit(0)
   
   # validate and set up
   if portlist == []:
      print "no listening port given, defaulting to 443"
      portlist.append((443,"stcp"))

   if not rootcertfile:
      print "please give a valid filename for root certificate"
      usage()
      sys.exit(1)
   if not rootkeyfile:
      print "please give a valid filename for root private key"
      usage()
      sys.exit(1)
   if not templatefile:
      print "please give a valid filename for root template"
      usage()
      sys.exit(1)
   if not os.path.isfile(rootcertfile):
      print "please give a valid filename for root certificate, cannot find %s" % rootcertfile
      usage()
      sys.exit(1)
   if not os.path.isfile(rootkeyfile):
      print "please give a valid filename for root private key, cannot find %s" % rootkeyfile
      usage()
      sys.exit(1)
   if not os.path.isfile(templatefile):
      print "please give a valid filename for root template, cannot find %s" % rootkeyfile
      usage()
      sys.exit(1)
   if not os.path.isfile(cafile):
      print "please give a valid filename the CA certs file, or omit this argument to run with remote servers unvalidated - %s" % rootcertfile
      usage()
      sys.exit(1)
   if not interface:
      print "no interface name given - trying eth0"
      interface = "eth0"
   if not startaddress:
      print "no starting ip address given. Using 192.168.1.101 as default"
      startaddress = "192.168.1.101"

   if not os.path.isdir(outputdir):
      print "Output directory not valid - %s" % outputdir
      usage()
      sys.exit(1)

   mainlog = logging.getLogger('mainlog')
   mainlog.setLevel(logging.DEBUG)
   mainlog.addHandler(logging.FileHandler(os.path.join(outputdir,'liarlog.log')))

   print "ARG Dump -"
   print "Ports - %s" % str(portlist)
   print "Root Cert - %s" % rootcertfile
   print "Root Key - %s" % rootkeyfile
   print "Cert Template - %s" % templatefile
   print "CA file - %s" % cafile
   print "Interface name - %s" % interface
   print "Starting IP address - %s" % startaddress
   print "Output directory - %s" % outputdir

   mainlog.debug("ARG Dump -")
   mainlog.debug("Ports - %s" % str(portlist))
   mainlog.debug("Root Cert - %s" % rootcertfile)
   mainlog.debug("Root Key - %s" % rootkeyfile)
   mainlog.debug("Cert Template - %s" % templatefile)
   mainlog.debug("CA file - %s" % cafile)
   mainlog.debug("Interface name - %s" % interface)
   mainlog.debug("Starting IP address - %s" % startaddress)
   mainlog.debug("Output directory - %s" % outputdir)

   if not os.path.isdir(os.path.join(outputdir,"certs")):
      os.mkdir(os.path.join(outputdir,"certs"))
   if not os.path.isdir(os.path.join(outputdir,"logs")):
      os.mkdir(os.path.join(outputdir,"logs"))

   dnsserv = dodgyDNSServer(rootcertfile, rootkeyfile, templatefile, cafile, outputdir, portlist, interface, startaddress, loglvl)
   dnsserv.run()



