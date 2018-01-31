# coding=utf-8
import os
import time

import src.core.setcore as core
import qrcode

# generate the qrcode and save it definition


def gen_qrcode(url):
    # generate the qrcode
    qr = qrcode.QRCode(5, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(url)
    qr.make()
    im = qr.make_image()
    time.sleep(1)

    qr_img_path = os.path.join(core.userconfigpath, "reports/qrcode_attack.png")

    if os.path.isfile(qr_img_path):
        os.remove(qr_img_path)
    # save the image out
    im.save(qr_img_path, format='png')
    # print that its been successful
    core.print_status("QRCode has been generated under {0}".format(qr_img_path))