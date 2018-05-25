#!/usr/bin/env python
# coding=utf-8
import os
import sys

definepath = os.getcwd()
sys.path.append(definepath)
import src.core.setcore as core

core.start_web_server_unthreaded(os.path.join(core.userconfigpath, "web_clone"))
