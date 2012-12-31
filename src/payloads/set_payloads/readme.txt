download.c is the inital stager payload that downloads the shell.exe payload.

listener.py is the SET listener.

shell.py is the shell, it uses pyinstaller for byte compilation then upx for packing of size.

persistence.py is the python based service

Edit each file if you want to see how to byte compile, what modules are required and what each one is doing.
