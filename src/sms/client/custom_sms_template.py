#!/usr/bin/env python
import random
from src.core import setcore as core

try:
    print ("\n         [****]  Custom Template Generator [****]\n") 
    author=raw_input(core.setprompt(["7"], "Name of the author"))
    filename=randomgen=random.randrange(1,99999999999999999999)
    filename=str(filename)+(".template")
    origin=raw_input(core.setprompt(["7"], "Source phone # of the template"))
    subject=raw_input(core.setprompt(["7"], "Subject of the template"))
    body=raw_input(core.setprompt(["7"], "Body of the message"))
    filewrite=file("src/templates/sms/%s" % (filename), "w")
    filewrite.write("# Author: "+author+"\n#\n#\n#\n")
    filewrite.write('ORIGIN='+'"'+origin+'"\n\n')
    filewrite.write('SUBJECT='+'"'+subject+'"\n\n')
    filewrite.write('BODY='+'"'+body+'"\n')
    print "\n"
    filewrite.close()
except Exception, e:
    core.print_error("An error occured:")
    core.print_error("ERROR:" + str(e))
