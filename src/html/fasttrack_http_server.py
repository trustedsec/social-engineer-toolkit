#!/usr/bin/python
import os
import sys
definepath=os.getcwd()
sys.path.append(definepath)
from src.core import setcore
setcore.start_web_server_unthreaded("%s/src/program_junk/web_clone/" % (definepath))
#setcore.start_web_server("%s/src/program_junk/web_clone/" % (definepath))
