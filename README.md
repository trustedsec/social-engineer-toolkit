# :briefcase: <code> </code> The Social-Engineer Toolkit (SET) <code>   </code> :briefcase:

Copyright 2018 The Social-Engineer Toolkit (SET)

Written by: David Kennedy (ReL1K)

Company: [TrustedSec](https://www.trustedsec.com)

DISCLAIMER: This is only for testing purposes and can only be used where strict consent has been given. Do not use this for illegal purposes, period.

Please read the LICENSE under readme/LICENSE for the licensing of SET. 


# :book: SET Tutorial :book:

For a full document on how to use SET, [visit the SET user manual](https://github.com/trustedsec/social-engineer-toolkit/raw/master/readme/User_Manual.pdf).


# :computer: Features :computer:


The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec, LLC – an information security consulting firm located in Cleveland, Ohio.


## Bugs and enhancements

For bug reports or enhancements, please open an [issue](https://github.com/trustedsec/social-engineer-toolkit/issues) here.


## Supported platforms

* Linux :penguin:
* Mac OS X :apple:

# :inbox_tray: Installation :inbox_tray:
## Resolve dependencies
*Ubuntu/Debian System*

```
$ apt-get -y install git apache2 python-requests libapache2-mod-php \
  python-pymssql build-essential python-pexpect python-pefile python-crypto python-openssl
```

*Arch System*

```bash
$ pacman -S --noconfirm --needed git python2 python2-beautifulsoup4 python2-pexpect python2-crypto
$ wget https://github.com/erocarrera/pefile/archive/master.zip && unzip master.zip
$ chmod a+x pefile-master/setup.py && rm -rf pefile-master*
```

*Fedora System*

```bash
$ dnf -y install git python-pexpect python-pefile python-crypto pyOpenSSL
```

*CentOS System*

```bash
$ yum update -y && yum install python-pexpect python-crypto python-openssl python-pefile
```

*Mac OS X dependent*

```bash
$ pip install pexpect pycrypto pyopenssl pefile
```

## Install SET

*All OSs*

```bash
$ git clone https://github.com/trustedsec/social-engineer-toolkit/ set/
$ cd set
$ python setup.py install
```
