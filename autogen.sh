#!/bin/sh

# $Id: autogen.sh,v 1.1.1.1 2007/11/16 01:53:31 kewlio Exp $

# Regenerate auto-tools configuration

aclocal --force
autoconf --force
autoheader --force
automake -f -a -c

