#!/usr/bin/env python
import re
import subprocess
import sys
import src
from src.core import module_reload
from src.core.setcore import debug_msg, meta_path, mod_name

me = mod_name()

sys.path.append("src/core")
debug_msg(me, "re-importing 'src.core.setcore'", 1)
try:
    module_reload(src.core.setcore)
except:
    import src.core.setcore
print("[---] Updating the Social Engineer Toolkit FileFormat Exploit List [---]")
generate_list = subprocess.Popen(
    "%s/msfcli | grep fileformat > src/core/msf_attacks/database/msf.database" % (meta_path), shell=True).wait()
print("[---] Database is now up-to-date [---]")
