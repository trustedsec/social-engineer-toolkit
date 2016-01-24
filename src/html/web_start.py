#!/usr/bin/env python
# This is just a simple import for web_start
import sys
from src.core.setcore import *
me = mod_name()
debug_msg(me, "importing 'src.html.spawn'", 1)
sys.path.append("src/html")
try:
    module_reload(spawn)
except:
    pass
