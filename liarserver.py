###################################################################################
# liarserver.py, listening server code for Liar
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
#    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#
###################################################################################
#
# Implementation of a MITM server, listens on a selection of ports for UDP and TCP
# traffic, and will attempt to MITM any ports it has been told are secure
#
###################################################################################


import os
import threading
import socket
import ssl
import select
import logging
import time
from liarutils import *

class liarHandler( threading.Thread ):
   def __init__(self, srvsocket, servername, logdir, port, cafile, seqnum, loglvl = logging.DEBUG):
      self.srvsocket = srvsocket
      self.servername = servername
      self.cafile = cafile
      self.port = port
      self.logdir = logdir
      self.num=seqnum
      self.loglvl = loglvl
      threading.Thread.__init__(self)

   def setupCliSocket(self):
      cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      return cli_sock

   def fromClientMessageEdit(self, data):
      return data

   def fromServerMessageEdit(self, data):
      return data

   def run(self):

      logname = os.path.join(self.logdir,"%s-%d.log" % ( self.servername, self.num ) )
      self.log = logging.getLogger(logname)
      self.log.setLevel(self.loglvl)
      self.log.addHandler(logging.FileHandler(logname))

      self.log.debug("Starting %d handler" % self.port)

      cli_sock = self.setupCliSocket()

      if not cli_sock:
         self.srvsocket.close()
         return

      try:
         cli_sock.connect((self.servername, self.port))
      except Exception, e:
         print "Exception connecting to remote server %s:%d - " % (self.servername, self.port), e
         self.log.debug("Exception connecting to remote server %s:%d !" % (self.servername, self.port) )
         self.log.debug(e)
         self.srvsocket.close()
         return

      poller = select.poll()
      poller.register(cli_sock, select.POLLIN)
      poller.register(self.srvsocket, select.POLLIN)

      err = False
      while err == False:
#        rlist, wlist, xlist = select.select([cli_sock, self.srvsocket],[], [])
         pollres = poller.poll()

         if not pollres:
            err = True
            break

         if pollres == ():
            err = True
            break

         for fdesc, flag in pollres:

            if fdesc == cli_sock.fileno():
               try:
                  data = cli_sock.recv(16384)
                  if not data:
                     err = True
                     break

                  self.log.debug("Data, remote server -> local client. Port %d" % self.port)
                  ftd, plain = hexdump(data, len(data))
                  self.log.debug(ftd)
                  self.log.debug(plain)
                  print "Message received for client from %s on %d" % (self.servername, self.port)

                  realdata = self.fromServerMessageEdit(data)
                  self.log.debug("Data edited to")
                  ftd, plain = hexdump(realdata, len(realdata))
                  self.log.debug(ftd)
                  self.log.debug(plain)

                  self.srvsocket.sendall(realdata)

               except Exception, e:
                  print "Failed trying to send data to client", e
                  self.log.debug("Failed trying to send data to client")
                  self.log.debug(e)
                  err = True
                  break
            else:
               try:
                  data = self.srvsocket.recv(16384)
                  if not data:
                     err = True
                     break
                  
                  self.log.debug("Data, local client -> remote server, Port %d" % self.port)
                  ftd, plain = hexdump(data, len(data))
                  self.log.debug(ftd)
                  self.log.debug(plain)
                  print "Message received for %s on %d from client" % (self.servername, self.port)

                  realdata = self.fromClientMessageEdit(data)
                  self.log.debug("Data edited to")
                  ftd, plain = hexdump(realdata, len(realdata))
                  self.log.debug(ftd)
                  self.log.debug(plain)

                  cli_sock.sendall(realdata)

               except Exception, e:
                  print "Failed trying to send data to server", e
                  self.log.debug("Failed trying to send data to server")
                  self.log.debug(e)
                  err = True
                  break

      print "Exiting %d handler for server %s" % (self.port, self.servername)
      self.log.debug( "Exiting %d handler for server %s" % (self.port, self.servername))
      cli_sock.shutdown(socket.SHUT_RDWR)
      self.srvsocket.shutdown(socket.SHUT_RDWR)
      cli_sock.close()
      self.srvsocket.close()

class liarHTTPHandler(liarHandler):
   # When we see stuff of interest in the messages, edit it out
   # So far this is unintelligent and totally stateless

   def fromClientMessageEdit(self, data):
      if(self.servername == "server.im.interested.in.com"):
         newstr1 = data.replace("Something the client said","Something I want the server to think")
         newstr2 = newstr2.replace("Something else the client said","Something else I want the server to think")
         return newstr2
      else:
         return data

   def fromServerMessageEdit(self, data):
      newstr1 = data.replace("Something the server said","Something I want the client to think")
      newstr2 = newstr1.replace("Something else the server said","Something else I want the client to think")
      return newstr2


class liarHTTPSHandler(liarHTTPHandler):

   def setupCliSocket(self):
      cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

      if self.cafile:
         ssl_sock = ssl.wrap_socket(cli_sock, ca_certs=self.cafile, cert_reqs=ssl.CERT_OPTIONAL)
      else:
         ssl_sock = ssl.wrap_socket(cli_sock)

      if not ssl_sock:
         print "ERROR, could not make SSL Sock"
         self.log.debug("ERROR, could not make SSL Socket")
         self.srvsocket.close()

      return ssl_sock


class liarServer( threading.Thread ):

   def __init__(self, servername, ports, localIP, logdir, certdir, cafile, loglvl = logging.DEBUG ):
      print "Init new server %s" % (servername)
      self.servername = servername
      self.portlist = ports
      self.localIP = localIP
      self.logdir = logdir
      self.certdir = certdir
      self.cafile = cafile
      self.log = logging.getLogger('mainlog')
      self.loglvl = loglvl
      self.log.setLevel(loglvl)
      threading.Thread.__init__(self)

   def run(self):
      sockets = []
      portdict={}
      poller = select.poll()
      err = False
      seqnum = 0
      for port, mode in self.portlist:
         if mode == "tcp" or mode == "stcp":
            self.log.debug("Server %s opening up port %s" % (self.servername, port))
            listenaddr = (self.localIP, port)
            serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            serversock.setblocking(0)
            serversock.bind(listenaddr)

            if mode == "stcp":
                  print "Setting up TLS port"
                  phandler = liarHTTPSHandler
                  real_sock = ssl.wrap_socket(serversock, os.path.join(self.certdir, "%s%s" % (self.servername, ".key")),  os.path.join(self.certdir, "%s%s" % (self.servername, ".cert")), True)
            else:
               print "Setting up plain port on %s" % port
               phandler = liarHTTPHandler
               real_sock = serversock

            real_sock.listen(5)
            sockets.append(real_sock)
            poller.register(real_sock, select.POLLIN)

            portdict[real_sock.fileno()]=(port, real_sock, "tcp", phandler)
         else:
            udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udps.bind((self.localIP,port))
            portdict[udps.fileno()]=(port, udps, "udp", None)

      while err == False:

#         rlist, wlist, xlist = select.select(sockets,[],[])
         pollres = poller.poll()

         for result, flag in pollres:
            self.log.debug("Server %s starting new connhandler" % (self.servername))
            srvport, srvsock, mode, handlerclass = portdict[result]
            if mode == "tcp":
               try:
                  clientsock, cliaddr = srvsock.accept()
                  if clientsock:
                     handlerclass(clientsock, self.servername, self.logdir, srvport, self.cafile,seqnum, self.loglvl).start()
                     seqnum+=1
                  else:
                     err = True
                     break
               except Exception, e:
                  print "Failed trying to accept server %s " % (self.servername), e
                  self.log.debug("Failed trying to send data to server %s" % self.servername)
                  self.log.debug(e)
            else:
               sndprt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
               data, addr = srvsock.recvfrom(2048)
               ftd, plain = hexdump(data, len(data))
               self.log.debug(ftd)
               self.log.debug(plain)
               sndprt.sendto(data, address=(self.servername,srvport))
               sndprt.close()

      for sock in sockets:
         sock.close()


# test func for this unit
if __name__=='__main__': 
   liarServer("www.example.com", (443), '', '.', '.', '').run()

