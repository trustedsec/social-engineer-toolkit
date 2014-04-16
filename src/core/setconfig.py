#!/usr/bin/env python

import os
import struct


# class to provide easy access to configurations in set_config (or any other config file that uses = as a delimeter)
# 
class SetConfig():

    def __init__(self, configfile):
         self.configfile = configfile
         # read config file into dictionary
         self.configvalues = self.readConfiguration()
         return

    def readConfiguration(self):
        configfromfile = {}
        trues = ["YES","ON","TRUE"]
        falses = ["NO","OFF","FALSE"]
        configfilecontent = file(self.configfile,"r")
        for line in configfilecontent:
            line = line.rstrip()
            if not line.startswith("#") and not line.replace(" ","") == "" and "=" in line:
                lineparts = line.split("=")
                parametername = lineparts[0].replace(" ","").upper()
                parametervalue = ""
                if len(lineparts) > 1:
                    parametervalue = lineparts[1].strip()
                    parametervalue_check = parametervalue.upper().replace(" ","")
                    if (parametervalue_check in trues):
                        parametervalue = "ON"
                    elif (parametervalue_check in falses):
                        parametervalue = "OFF"
                    configfromfile[parametername] = parametervalue
        return configfromfile

    def get(self, configparameter, defaultvalue):
        # sanitize parameter, just in case
        configparameter = configparameter.upper().strip()
        if configparameter in self.configvalues:
            return str(self.configvalues[configparameter])
        return str(defaultvalue)

    def set(self, configparameter, configvalue):
        self.configvalues[configparameter] = configvalue
        # To DO: write new config to file
        return
