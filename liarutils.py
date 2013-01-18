###################################################################################
# liarutils.py, utility calls for liar
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
# A couple of utility functions, both of which could be done a lot better.
# hexdump is used for output formatting and is a hacky translation of a C function
# createServerCert is a mess of os.system stuff for generating certificates from
# templates
#
###################################################################################

import string
import os
import random

def hexdump(data="", length=0):
   output=""
   p = 0
   major = 0
   minor = 0
   printbuf = ""
   plaintext=""
   output+= "    |  0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\n----+--------------------------------------------------"
   while p < length:
      if (minor % 16) == 0:
         output+= "    %s\n %3x|" % (printbuf,major)
         plaintext = plaintext + printbuf
         printbuf = ""
         major += 1;
      if (minor % 8) == 0:
         if (minor % 16) != 0:
            output+= " "
      output+= " %2.2x" % ( ord(data[p]) )
      if data[p] in string.letters or data[p] in string.digits or data[p] in string.punctuation:
         if data[p] == '\x0a':
            printbuf += '.'
         else:
            printbuf += data[p]
      else:
         printbuf +='.'
      minor += 1
      p += 1

   plaintext = plaintext + printbuf

   major = minor % 16
   if major != 0:
      major = (16 - major) * 3
      if major > 24:
         major += 1
      while major != 0:
         printbuf = " " + printbuf
         major -= 1

   output+= "    %s\n\n" % (printbuf)
   return output, plaintext

def createServerCert(servername, rootcert, rootkey, templatefile, outputdir):
   random.seed()
   if not (os.path.isfile(os.path.join(outputdir,"%s.key" % servername)) and os.path.isfile(os.path.join(outputdir,"%s.cert" % servername))):
      #DIRTY, VERY VERY DIRTY INDEED - this should probably done with real, actual python.
      os.system("sed s/SERVERNAME/%s/ %s > %s/%s.tmpl" % (servername, templatefile, outputdir, servername) )
      os.system("sed s/SERVERSERIAL/%d/ %s/%s.tmpl > %s/%s.tmp" % (random.randint(0,32767), outputdir, servername, outputdir, servername) )
      os.system("certtool --generate-privkey --bits 512 --outfile %s/%s.key" % (outputdir, servername) )
      os.system("certtool --generate-request --load-privkey %s/%s.key --outfile %s/%s.req --template %s/%s.tmp" %
                (outputdir, servername, outputdir, servername, outputdir, servername) )
      os.system("certtool --generate-certificate --load-request %s/%s.req --outfile %s/%s.cert --load-ca-certificate %s --load-ca-privkey %s --template %s/%s.tmp" %
                (outputdir, servername, outputdir, servername, rootcert, rootkey, outputdir, servername) )

