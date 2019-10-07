#
# $Header: /cvsroot/aolserver/nsldap/Makefile,v 1.1.1.1 2002/02/26 15:36:52 kriston Exp $
#
# nsexample --
#
#      Example AOLserver module Makefile.
#

#
# AOLserver's location
#
#  Since your module probably doesn't live inside the "aolserver"
#  directory, you can tell make where to find aolserver.
#
#NSHOME   =  /home/user/cvs/aolserver
#NSHOME   =  ../aolserver

NAVISERVER = /usr/local/ns
#
# Module name
#
MOD      =  nsldap.so

#
# Objects to build
#
OBJS     =  nsldap.o

#
# Header files in THIS directory (included with your module)
#
HDRS     =  

#
# Extra libraries required by your module (-L and -l go here)
#
MODLIBS  =  -L/usr/local/lib -lldap -llber

#
# Compiler flags required by your module (-I for external headers goes here)
#
# On macOS, you might use
#CFLAGS += -Wno-deprecated-declarations

include  $(NAVISERVER)/include/Makefile.module

