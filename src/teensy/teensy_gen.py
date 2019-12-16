from __future__ import print_function
# teensy_gen Functions

def check_input(orig_value, user_value):
    if ( user_value == '' ):
        print('Keeping orginal value')
        return (orig_value)
    else:
        print('Value changed from - '+orig_value+' to '+user_value)
        return (user_value)

def ino_print_gen(text_to_include):                                         # Define ino_print_gen function taking the text to be formatted for the ino file.
    return('  Keyboard.println(\"'+text_to_include+'\");')                  # Return the formatted text for the ino file.

def cmd_at_run_gen(cmd_for_run, env_varib, file_to_run):                    # Define cmd_at_run_gen function taking the text to be formatted into the CommandAtRunBar command for the ino file.
    return('  CommandAtRunBar(\"'+cmd_for_run+' '+env_varib+'\\'+file_to_run+'\");')    # Return the formatted text for the ino file.
