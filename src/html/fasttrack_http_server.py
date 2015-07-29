#!/usr/bin/env python
import os
import sys
definepath=os.getcwd()
sys.path.append(definepath)
from src.core.setcore import *
start_web_server_unthreaded(setdir + "/web_clone/")
