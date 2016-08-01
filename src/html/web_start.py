#!/usr/bin/env python
# coding=utf-8
# This is just a simple import for web_start
import sys

import src.core.setcore as core

core.debug_msg(core.mod_name(), "importing 'src.html.spawn'", 1)
sys.path.append("src/html")
try:
    import src.html.spawn
except:
    pass
