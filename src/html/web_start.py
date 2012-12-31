#!/usr/bin/env python
# This is just a simple import for web_start
import sys
import setcore
me = setcore.mod_name()
setcore.debug_msg(me,"importing 'src.html.spawn'",1)
sys.path.append("src/html")
try: reload(spawn)
except: pass
