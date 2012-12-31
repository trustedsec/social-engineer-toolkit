#!/usr/bin/env python

#
# Notes from rel1k here... Had to downgrade to 0.1, the latest (0.3 currently) uses a different way for checksums of the peheader.
# This dies and fails in 64 bit operating systems, since this is the older version, shouldn't be a big deal, still works as expected.
#

"""V0.1 2007/12/18 - 2008/01/09

tool to manipulate digital signatures in PE files
commands:
- delete signed-file unsigned-file
- copy signed-source-file unsigned-file signed-file
- extract signed-file signature
- add signature unsigned-file signed-file

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
 2007/12/21: added arguments
 2008/01/09: code review

requires pefile:
 http://code.google.com/p/pefile/
 to install: setup.py install
"""

import pefile
import sys
from struct import *

def Usage():
    """Displays the usage of this tool
    """
    
    print "Usage: disitool command [options] file ..."
    print "  disitool V0.1, tool to manipulate digital signatures in PE files"
    print "  commands:"
    print "  - delete signed-file unsigned-file"
    print "  - copy signed-source-file unsigned-file signed-file"
    print "  - extract signed-file signature"
    print "  - add signature unsigned-file signed-file"
    print "  Source code put in the public domain by Didier Stevens, no Copyright"
    print "  Use at your own risk"
    print "  https://DidierStevens.com"

def DeleteDigitalSignature(SignedFile, UnsignedFile=None):
    """Deletes the digital signature from file SignedFile
       When UnsignedFile is not None, writes the modified file to UnsignedFile
       Returns the modified file as a PE file
    """
    pe =  pefile.PE(SignedFile)

    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0

    if address != 0:
        new_file_data = pe.write()[0:address]
    else:
        new_file_data = pe.write()
    
    if UnsignedFile:
        f = file(UnsignedFile, 'wb+')
        f.write(new_file_data)
        f.close()

    return new_file_data

def CopyDigitalSignature(SignedSourceFile, UnsignedFile, SignedFile=None):
    """Extracts the digital signature from file SignedSourceFile and adds it to file UnsignedFile
       When SignedFile is not None, writes the modified file to SignedFile
       Returns the modified file as a PE file
    """

    peSignedSource =  pefile.PE(SignedSourceFile)

    address = peSignedSource.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = peSignedSource.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print "Error: source file not signed"
        return

    signature = peSignedSource.write()[address:]

    peUnsigned = DeleteDigitalSignature(UnsignedFile)
    
    peSignedFile = pefile.PE(data=''.join(list(peUnsigned) + list(signature)))

    peSignedFile.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = len(peUnsigned)
    peSignedFile.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = size

    new_file_data = peSignedFile.write()

    if SignedFile:
        f = file(SignedFile, 'wb+')
        f.write(new_file_data)
        f.close()

    return new_file_data

def ExtractDigitalSignature(SignedFile, SignatureFile=None):
    """Extracts the digital signature from file SignedFile
       When SignatureFile is not None, writes the signature to SignatureFile
       Returns the signature
    """

    pe =  pefile.PE(SignedFile)

    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print "Error: source file not signed"
        return

    signature = pe.write()[address+8:]

    if SignatureFile:
        f = file(SignatureFile, 'wb+')
        f.write(signature)
        f.close()

    return signature

def AddDigitalSignature(SignatureFile, UnsignedFile, SignedFile=None):
    """Adds the digital signature from file SignatureFile to file UnsignedFile
       When SignedFile is not None, writes the modified file to SignedFile
       Returns the modified file as a PE file
    """

    f = file(SignatureFile, 'rb')
    signature = f.read()
    f.close()

    size = len(signature) + 8
    
    peUnsigned = DeleteDigitalSignature(UnsignedFile)
    
    peSignedFile = pefile.PE(data=''.join(list(peUnsigned) + list(unpack("4c", pack("i", size))) + ['\x00', '\x02', '\x02', '\x00'] + list(signature)))

    peSignedFile.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = len(peUnsigned)
    peSignedFile.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = size

    new_file_data = peSignedFile.write()

    if SignedFile:
        f = file(SignedFile, 'wb+')
        f.write(new_file_data)
        f.close()

    return new_file_data
