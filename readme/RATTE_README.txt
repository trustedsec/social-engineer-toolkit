RATTE (Remote Administration Tool Tommy Edition) is a payload and third party module added/created to SET by 
Thomas Werth.

A couple of things to note about RATTE is that it's main purpose and design is to completely evade egress and firewall based restrictions by leveraging purely HTTP communications for the commands back and forth. 
RATTE has been extend to be very customizeable.
For now you can set:
- Connect Back IP
- Connect Back Port
- Wheater RATTE is persistent or not (example: For network Firewall testing, there is no need for beeing persistent. In a penetration test things may look different)
- a custom filename which RATTE uses for running so local firewalls and user may be fooled using names like iexplore.exe or 		firefox.exe and on ...

If RATTE is persistent, it tries on NTFS Systems to inject itself into Default Browser file binary and replaces
the executables with a portion of its own code in it as well. If this fails RATTE will save itself as autorun app using custom filename specified. If this one is missing it will go as iexplore.exe.

RATTE relies on communications to microsoft.com to identify the path out of the network.
