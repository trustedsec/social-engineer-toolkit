#!/usr/bin/python
from src.core.setcore import debug_msg, mod_name
import subprocess
import re
import sys

me = mod_name()

sys.path.append("src/core")
debug_msg(me,"re-importing 'src.core.setcore'",1)
try: reload(setcore)
except: import setcore
print "[---] Updating the Social Engineer Toolkit FileFormat Exploit List [---]"
generate_list=subprocess.Popen("%s/msfcli | grep fileformat > src/core/msf_attacks/database/msf.database" % (meta_path), shell=True).wait()
print "[---] Database is now up-to-date [---]"
