#!/usr/bin/env python
""" Python lists used for quick conversion of user input
    to strings used by the toolkit

    """


def encoder_type(encode):
    """
    Takes the value sent from the user encoding menu and returns
    the actual value to be used.

    """

    return {
        '0': "",
        '1': "shikata_ga_nai",
        '2': "",
        '3': "MULTIENCODE",
        '4': "BACKDOOR",
    }.get(encode, "ERROR")


def ms_module(exploit):
    """ Receives the input given by the user from gen_payload.py """

    return {
        '1': "exploit/multi/browser/adobe_flash_hacking_team_uaf",
        '2': "exploit/multi/browser/adobe_flash_nellymoser_bof",
        '3': "exploit/multi/browser/adobe_flash_shader_drawing_fill",
        '4': "exploit/windows/browser/ms14_012_textrange",
        '5': "exploit/windows/browser/ms14_012_cmarkup_uaf",
        '6': "exploit/windows/browser/ms13_080_cdisplaypointer",
        '7': "exploit/windows/browser/ie_setmousecapture_uaf",
        '8': "exploit/multi/browser/java_jre17_jmxbean_2",
        '9': "exploit/multi/browser/java_jre17_jmxbean",
        '10': "exploit/windows/browser/ms13_009_ie_slayoutrun_uaf",
        '11': "exploit/windows/browser/ie_cbutton_uaf",
        '12': "exploit/multi/browser/java_jre17_exec",
        '13': "exploit/windows/browser/ie_execcommand_uaf",
        '14': "exploit/multi/browser/java_atomicreferencearray",
        '15': "exploit/multi/browser/java_verifier_field_access",
        '16': "exploit/windows/browser/ms12_037_same_id",
        '17': "exploit/windows/browser/msxml_get_definition_code_exec",
        '18': "exploit/windows/browser/adobe_flash_rtmp",
        '19': "exploit/windows/browser/adobe_flash_mp4_cprt",
        '20': "exploit/windows/browser/ms12_004_midi",
        '21': "multi/browser/java_rhino\nset target 1",
        '22': "windows/browser/ms11_050_mshtml_cobjectelement",
        '23': "windows/browser/adobe_flashplayer_flash10o",
        '24': "windows/browser/cisco_anyconnect_exec",
        '25': "windows/browser/ms11_003_ie_css_import",
        '26': "windows/browser/wmi_admintools",
        '27': "windows/browser/ms10_090_ie_css_clip",
        '28': "windows/browser/java_codebase_trust",
        '29': "windows/browser/java_docbase_bof",
        '30': "windows/browser/webdav_dll_hijacker",
        '31': "windows/browser/adobe_flashplayer_avm",
        '32': "windows/browser/adobe_shockwave_rcsl_corruption",
        '33': "windows/browser/adobe_cooltype_sing",
        '34': "windows/browser/apple_quicktime_marshaled_punk",
        '35': "windows/browser/ms10_042_helpctr_xss_cmd_exec",
        '36': "windows/browser/ms10_018_ie_behaviors",
        '37': "windows/browser/ms10_002_aurora",
        '38': "windows/browser/ms10_018_ie_tabular_activex",
        '39': "windows/browser/ms09_002_memory_corruption",
        '40': "windows/browser/ms09_072_style_object",
        '41': "windows/browser/ie_iscomponentinstalled",
        '42': "windows/browser/ms08_078_xml_corruption",
        '43': "windows/browser/ie_unsafe_scripting",
        '44': "multi/browser/firefox_escape_retval",
        '45': "windows/browser/mozilla_mchannel",
        '46': "auxiliary/server/browser_autopwn",
    }.get(exploit, "ERROR")


# called from gen_payload.py
# uses payload_menu_2
def ms_payload(payload):
    """
    Receives the input given by the user from create_payload.py
    and create_payloads.py

    """

    return {
        '1': "windows/shell_reverse_tcp",
        '2': "windows/meterpreter/reverse_tcp",
        '3': "windows/vncinject/reverse_tcp",
        '4': "windows/x64/shell_reverse_tcp",
        '5': "windows/x64/meterpreter/reverse_tcp",
        '6': "windows/meterpreter/reverse_tcp_allports",
        '7': "windows/meterpreter/reverse_https",
        '8': "windows/meterpreter/reverse_tcp_dns",
        '9': "windows/download_exec",
    }.get(payload, "ERROR")

# called from create_payloads.py


def ms_payload_2(payload):
    """ Receives the input given by the user from create_payloadS.py """

    return {
        '1': "shellcode/pyinject",
        '2': "shellcode/multipyinject",
        '3': "set/reverse_shell",
        '4': "set/reverse_shell",
        '5': "set/reverse_shell",
        '6': "shellcode/alphanum",
#        '7': "7",
        '8': "cmd/multi",
    }.get(payload, "ERROR")


def ms_payload_3(payload):
    """ Receives the input given by the user from create_payloadS.py """

    return {
        '1': "windows/shell_reverse_tcp",
        '2': "windows/meterpreter/reverse_tcp",
        '3': "windows/vncinject/reverse_tcp",
        '4': "windows/x64/shell_reverse_tcp",
        '5': "windows/x64/meterpreter/reverse_tcp",
        '6': "windows/x64/shell_bind_tcp",
        '7': "windows/meterpreter/reverse_https",
    }.get(payload, "ERROR")


# uses create_payloads_menu
def ms_attacks(exploit):
    """ Receives the input given by the user from create_payload.py """

    return {
        '1': "dll_hijacking",
        '2': "unc_embed",
        '3': "exploit/windows/fileformat/ms15_100_mcl_exe",
        '4': "exploit/windows/fileformat/ms14_017_rtf",
        '5': "exploit/windows/fileformat/ms11_006_createsizeddibsection",
        '6': "exploit/windows/fileformat/ms10_087_rtf_pfragments_bof",
        '7': "exploit/windows/fileformat/adobe_flashplayer_button",
        '8': "exploit/windows/fileformat/adobe_cooltype_sing",
        '9': "exploit/windows/fileformat/adobe_flashplayer_newfunction",
        '10': "exploit/windows/fileformat/adobe_collectemailinfo",
        '11': "exploit/windows/fileformat/adobe_geticon",
        '12': "exploit/windows/fileformat/adobe_jbig2decode",
        '13': "exploit/windows/fileformat/adobe_pdf_embedded_exe",
        '14': "exploit/windows/fileformat/adobe_utilprintf",
        '15': "custom/exe/to/vba/payload",
        '16': "exploit/windows/fileformat/adobe_u3d_meshdecl",
        '17': 'exploit/windows/fileformat/adobe_pdf_embedded_exe_nojs',
        '18': "exploit/windows/fileformat/foxit_title_bof",
        '19': "exploit/windows/fileformat/apple_quicktime_pnsize",
        '20': "exploit/windows/fileformat/nuance_pdf_launch_overflow",
        '21': "exploit/windows/fileformat/adobe_reader_u3d",
        '22': "exploit/windows/fileformat/ms12_027_mscomctl_bof",
    }.get(exploit, "INVALID")


def teensy_config(choice):
    """ Receives the input given by the user from set.py """

    return {
        '1': "powershell_down.ino",
        '2': "wscript.ino",
        '3': "powershell_reverse.ino",
        '4': "beef.ino",
        '5': "java_applet.ino",
        '6': "gnome_wget.ino"
    }.get(choice, "ERROR")


def webattack_vector(attack_vector):
    """ Receives the input given by the user from set.py """

    return {
        '1': "java",
        '2': "browser",
        '3': "harvester",
        '4': "tabnapping",
        '5': "webjacking",
        '6': "multiattack",
    }.get(attack_vector, "ERROR")


def category(category):
    """
    Takes the value sent from the user encoding menu and returns
    the actual value to be used.

    """

    return {
        '0': "0",
        '1': "phishing",
        '2': "webattack",
        '3': "infectious",
        '4': "payloads",
        '5': "mailer",
        '6': "arduino",
        '7': "sms",
        '8': "wireless",
        '9': "modules",
        '10': "cloner",
        '11': "harvester",
        '12': "tabnapping",
        '13': "teensy",
        '14': "binary2teensy",
        '15': "dll_hijacking",
        '16': "multiattack",
        '17': "java_applet",
        '18': "encoding",
        '19': "fasttrack",
        '20': "autopwn",
        '21': "mssql",
        '22': "scan",
        '23': "direct",
        '24': "exploits",
        '25': "active_target",
        '26': "shell",
        '27': "set",
        '28': "teensy2powershell",
        '29': "powershell",
        '30': "delldrac",
        '31': "ridenum",
        '32': "psexec",
    }.get(category, "ERROR")
