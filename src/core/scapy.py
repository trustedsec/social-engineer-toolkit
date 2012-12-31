#! /usr/bin/env python

#############################################################################
##                                                                         ##
## scapy.py --- Interactive packet manipulation tool                       ##
##              see http://www.secdev.org/projects/scapy/                  ##
##              for more informations                                      ##
##                                                                         ##
## Copyright (C) 2003  Philippe Biondi <phil@secdev.org>                   ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################


from __future__ import generators
import os

VERSION = "1.2.0.2"

DEFAULT_CONFIG_FILE = os.path.join(os.environ["HOME"], ".scapy_startup.py")

try:
    os.stat(DEFAULT_CONFIG_FILE)
except OSError:
    DEFAULT_CONFIG_FILE = None

def usage():
    print """Usage: scapy.py [-s sessionfile] [-c new_startup_file] [-C]
    -C: do not read startup file"""
    sys.exit(0)


#############################
##### Logging subsystem #####
#############################

class Scapy_Exception(Exception):
    pass

import logging,traceback,time

class ScapyFreqFilter(logging.Filter):
    def __init__(self):
        logging.Filter.__init__(self)
        self.warning_table = {}
    def filter(self, record):        
        wt = conf.warning_threshold
        if wt > 0:
            stk = traceback.extract_stack()
            caller=None
            for f,l,n,c in stk:
                if n == 'warning':
                    break
                caller = l
            tm,nb = self.warning_table.get(caller, (0,0))
            ltm = time.time()
            if ltm-tm > wt:
                tm = ltm
                nb = 0
            else:
                if nb < 2:
                    nb += 1
                    if nb == 2:
                        record.msg = "more "+record.msg
                else:
                    return 0
            self.warning_table[caller] = (tm,nb)
        return 1    

log_scapy = logging.getLogger("scapy")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
log_scapy.addHandler(console_handler)
log_runtime = logging.getLogger("scapy.runtime")          # logs at runtime
log_runtime.addFilter(ScapyFreqFilter())
log_interactive = logging.getLogger("scapy.interactive")  # logs in interactive functions
log_loading = logging.getLogger("scapy.loading")          # logs when loading scapy

if __name__ == "__main__":
    log_scapy.setLevel(1)


##################
##### Module #####
##################

import socket, sys, getopt, string, struct, random, code
import cPickle, copy, types, gzip, base64, re, zlib, array
#from sets import Set
from select import select
from glob import glob
from fcntl import ioctl
import itertools
import fcntl
import warnings
warnings.filterwarnings("ignore","tempnam",RuntimeWarning, __name__)


try:
    import Gnuplot
    GNUPLOT=1
except ImportError:
    log_loading.info("did not find python gnuplot wrapper . Won't be able to plot")
    GNUPLOT=0

try:
    import pyx
    PYX=1
except ImportError:
    log_loading.info("Can't import PyX. Won't be able to use psdump() or pdfdump()")
    PYX=0


LINUX=sys.platform.startswith("linux")
OPENBSD=sys.platform.startswith("openbsd")
FREEBSD=sys.platform.startswith("freebsd")
DARWIN=sys.platform.startswith("darwin")
BIG_ENDIAN= struct.pack("H",1) == "\x00\x01"
X86_64 = (os.uname()[4] == 'x86_64')
SOLARIS=sys.platform.startswith("sunos")


if LINUX:
    DNET=PCAP=0
else:
    DNET=PCAP=1
    

if PCAP:
    try:
        import pcap
        PCAP = 1
    except ImportError:
        if LINUX:
            log_loading.warning("did not find pcap module. Fallback to linux primitives")
            PCAP = 0
        else:
            if __name__ == "__main__":
                log_loading.error("did not find pcap module")
                raise SystemExit
            else:
                raise

if DNET:
    try:
        import dnet
        DNET = 1
    except ImportError:
        if LINUX:
            log_loading.warning("did not find dnet module. Fallback to linux primitives")
            DNET = 0
        else:
            if __name__ == "__main__":
                log_loading.error("did not find dnet module")
                raise SystemExit
            else:
                raise

if not PCAP:
    f = os.popen("tcpdump -V 2> /dev/null")
    if f.close() >> 8 == 0x7f:
        log_loading.warning("Failed to execute tcpdump. Check it is installed and in the PATH")
        TCPDUMP=0
    else:
        TCPDUMP=1
    del(f)
        
    

try:
    from Crypto.Cipher import ARC4
except ImportError:
    log_loading.info("Can't find Crypto python lib. Won't be able to decrypt WEP")


# Workarround bug 643005 : https://sourceforge.net/tracker/?func=detail&atid=105470&aid=643005&group_id=5470
try:
    socket.inet_aton("255.255.255.255")
except socket.error:
    def inet_aton(x):
        if x == "255.255.255.255":
            return "\xff"*4
        else:
            return socket.inet_aton(x)
else:
    inet_aton = socket.inet_aton

inet_ntoa = socket.inet_ntoa
try:
    inet_ntop = socket.inet_ntop
    inet_pton = socket.inet_pton
except AttributeError:
    log_loading.info("inet_ntop/pton functions not found. Python IPv6 support not present")


if SOLARIS:
    # GRE is missing on Solaris
    socket.IPPROTO_GRE = 47

###############################
## Direct Access dictionnary ##
###############################

def fixname(x):
    if x and x[0] in "0123456789":
        x = "n_"+x
    return x.translate("________________________________________________0123456789_______ABCDEFGHIJKLMNOPQRSTUVWXYZ______abcdefghijklmnopqrstuvwxyz_____________________________________________________________________________________________________________________________________")


class DADict_Exception(Scapy_Exception):
    pass

class DADict:
    def __init__(self, _name="DADict", **kargs):
        self._name=_name
        self.__dict__.update(kargs)
    def fixname(self,val):
        return fixname(val)
    def __contains__(self, val):
        return val in self.__dict__
    def __getitem__(self, attr):
        return getattr(self, attr)
    def __setitem__(self, attr, val):        
        return setattr(self, self.fixname(attr), val)
    def __iter__(self):
        return iter(map(lambda (x,y):y,filter(lambda (x,y):x and x[0]!="_", self.__dict__.items())))
    def _show(self):
        for k in self.__dict__.keys():
            if k and k[0] != "_":
                print "%10s = %r" % (k,getattr(self,k))
    def __repr__(self):
        return "<%s/ %s>" % (self._name," ".join(filter(lambda x:x and x[0]!="_",self.__dict__.keys())))

    def _branch(self, br, uniq=0):
        if uniq and br._name in self:
            raise DADict_Exception("DADict: [%s] already branched in [%s]" % (br._name, self._name))
        self[br._name] = br

    def _my_find(self, *args, **kargs):
        if args and self._name not in args:
            return False
        for k in kargs:
            if k not in self or self[k] != kargs[k]:
                return False
        return True
    
    def _find(self, *args, **kargs):
         return self._recurs_find((), *args, **kargs)
    def _recurs_find(self, path, *args, **kargs):
        if self in path:
            return None
        if self._my_find(*args, **kargs):
            return self
        for o in self:
            if isinstance(o, DADict):
                p = o._recurs_find(path+(self,), *args, **kargs)
                if p is not None:
                    return p
        return None
    def _find_all(self, *args, **kargs):
        return self._recurs_find_all((), *args, **kargs)
    def _recurs_find_all(self, path, *args, **kargs):
        r = []
        if self in path:
            return r
        if self._my_find(*args, **kargs):
            r.append(self)
        for o in self:
            if isinstance(o, DADict):
                p = o._recurs_find_all(path+(self,), *args, **kargs)
                r += p
        return r
    def keys(self):
        return filter(lambda x:x and x[0]!="_", self.__dict__.keys())
        


############
## Consts ##
############

ETHER_ANY = "\x00"*6
ETHER_BROADCAST = "\xff"*6

ETH_P_ALL = 3
ETH_P_IP = 0x800
ETH_P_ARP = 0x806

# From net/if_arp.h
ARPHDR_ETHER = 1
ARPHDR_METRICOM = 23
ARPHDR_PPP = 512
ARPHDR_LOOPBACK = 772
ARPHDR_TUN = 65534

# From bits/ioctls.h
SIOCGIFHWADDR  = 0x8927          # Get hardware address    
SIOCGIFADDR    = 0x8915          # get PA address          
SIOCGIFNETMASK = 0x891b          # get network PA mask     
SIOCGIFNAME    = 0x8910          # get iface name          
SIOCSIFLINK    = 0x8911          # set iface channel       
SIOCGIFCONF    = 0x8912          # get iface list          
SIOCGIFFLAGS   = 0x8913          # get flags               
SIOCSIFFLAGS   = 0x8914          # set flags               
SIOCGIFINDEX   = 0x8933          # name -> if_index mapping
SIOCGIFCOUNT   = 0x8938          # get number of devices
SIOCGSTAMP     = 0x8906          # get packet timestamp (as a timeval)


# From if.h
IFF_UP = 0x1               # Interface is up.
IFF_BROADCAST = 0x2        # Broadcast address valid.
IFF_DEBUG = 0x4            # Turn on debugging.
IFF_LOOPBACK = 0x8         # Is a loopback net.
IFF_POINTOPOINT = 0x10     # Interface is point-to-point link.
IFF_NOTRAILERS = 0x20      # Avoid use of trailers.
IFF_RUNNING = 0x40         # Resources allocated.
IFF_NOARP = 0x80           # No address resolution protocol.
IFF_PROMISC = 0x100        # Receive all packets.



# From netpacket/packet.h
PACKET_ADD_MEMBERSHIP  = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_RECV_OUTPUT     = 3
PACKET_RX_RING         = 5
PACKET_STATISTICS      = 6
PACKET_MR_MULTICAST    = 0
PACKET_MR_PROMISC      = 1
PACKET_MR_ALLMULTI     = 2


# From bits/socket.h
SOL_PACKET = 263
# From asm/socket.h
SO_ATTACH_FILTER = 26
SOL_SOCKET = 1

# From net/route.h
RTF_UP = 0x0001  # Route usable
RTF_REJECT = 0x0200

# From BSD net/bpf.h
#BIOCIMMEDIATE=0x80044270
BIOCIMMEDIATE=-2147204496

MTU = 1600

 
# file parsing to get some values :

def load_protocols(filename):
    spaces = re.compile("[ \t]+|\n")
    dct = DADict(_name=filename)
    try:
        for l in open(filename):
            try:
                shrp = l.find("#")
                if  shrp >= 0:
                    l = l[:shrp]
                l = l.strip()
                if not l:
                    continue
                lt = tuple(re.split(spaces, l))
                if len(lt) < 2 or not lt[0]:
                    continue
                dct[lt[0]] = int(lt[1])
            except Exception,e:
                log_loading.info("Couldn't parse file [%s]: line [%r] (%s)" % (filename,l,e))
    except IOError:
        log_loading.info("Can't open /etc/protocols file")
    return dct

IP_PROTOS=load_protocols("/etc/protocols")

def load_ethertypes(filename):
    spaces = re.compile("[ \t]+|\n")
    dct = DADict(_name=filename)
    try:
        f=open(filename)
        for l in f:
            try:
                shrp = l.find("#")
                if  shrp >= 0:
                    l = l[:shrp]
                l = l.strip()
                if not l:
                    continue
                lt = tuple(re.split(spaces, l))
                if len(lt) < 2 or not lt[0]:
                    continue
                dct[lt[0]] = int(lt[1], 16)
            except Exception,e:
                log_loading.info("Couldn't parse file [%s]: line [%r] (%s)" % (filename,l,e))
        f.close()
    except IOError,msg:
        pass
    return dct

ETHER_TYPES=load_ethertypes("/etc/ethertypes")

def load_services(filename):
    spaces = re.compile("[ \t]+|\n")
    tdct=DADict(_name="%s-tcp"%filename)
    udct=DADict(_name="%s-udp"%filename)
    try:
        f=open(filename)
        for l in f:
            try:
                shrp = l.find("#")
                if  shrp >= 0:
                    l = l[:shrp]
                l = l.strip()
                if not l:
                    continue
                lt = tuple(re.split(spaces, l))
                if len(lt) < 2 or not lt[0]:
                    continue
                if lt[1].endswith("/tcp"):
                    tdct[lt[0]] = int(lt[1].split('/')[0])
                elif lt[1].endswith("/udp"):
                    udct[lt[0]] = int(lt[1].split('/')[0])
            except Exception,e:
                log_loading.warning("Couldn't file [%s]: line [%r] (%s)" % (filename,l,e))
        f.close()
    except IOError:
        log_loading.info("Can't open /etc/services file")
    return tdct,udct

TCP_SERVICES,UDP_SERVICES=load_services("/etc/services")

class ManufDA(DADict):
    def fixname(self, val):
        return val
    def _get_manuf_couple(self, mac):
        oui = ":".join(mac.split(":")[:3]).upper()
        return self.__dict__.get(oui,(mac,mac))
    def _get_manuf(self, mac):
        return self._get_manuf_couple(mac)[1]
    def _get_short_manuf(self, mac):
        return self._get_manuf_couple(mac)[0]
    def _resolve_MAC(self, mac):
        oui = ":".join(mac.split(":")[:3]).upper()
        if oui in self:
            return ":".join([self[oui][0]]+ mac.split(":")[3:])
        return mac
        
        
        

def load_manuf(filename):
    try:
        manufdb=ManufDA(_name=filename)
        for l in open(filename):
            try:
                l = l.strip()
                if not l or l.startswith("#"):
                    continue
                oui,shrt=l.split()[:2]
                i = l.find("#")
                if i < 0:
                    lng=shrt
                else:
                    lng = l[i+2:]
                manufdb[oui] = shrt,lng
            except Exception,e:
                log_loading.warning("Couldn't parse one line from [%s] [%r] (%s)" % (filename, l, e))
    except IOError:
        #log_loading.warning("Couldn't open [%s] file" % filename)
        pass
    return manufdb
    
MANUFDB = load_manuf("/usr/share/wireshark/wireshark/manuf")




###########
## Tools ##
###########

def sane_color(x):
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+conf.color_theme.not_printable(".")
        else:
            r=r+i
    return r

def sane(x):
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+"."
        else:
            r=r+i
    return r

def lhex(x):
    if type(x) in (int,long):
        return hex(x)
    elif type(x) is tuple:
        return "(%s)" % ", ".join(map(lhex, x))
    elif type(x) is list:
        return "[%s]" % ", ".join(map(lhex, x))
    else:
        return x

def hexdump(x):
    x=str(x)
    l = len(x)
    i = 0
    while i < l:
        print "%04x  " % i,
        for j in range(16):
            if i+j < l:
                print "%02X" % ord(x[i+j]),
            else:
                print "  ",
            if j%16 == 7:
                print "",
        print " ",
        print sane_color(x[i:i+16])
        i += 16

def linehexdump(x, onlyasc=0, onlyhex=0):
    x = str(x)
    l = len(x)
    if not onlyasc:
        for i in range(l):
            print "%02X" % ord(x[i]),
        print "",
    if not onlyhex:
        print sane_color(x)

def chexdump(x):
    x=str(x)
    print ", ".join(map(lambda x: "%#04x"%ord(x), x))
    
def hexstr(x, onlyasc=0, onlyhex=0):
    s = []
    if not onlyasc:
        s.append(" ".join(map(lambda x:"%02x"%ord(x), x)))
    if not onlyhex:
        s.append(sane(x)) 
    return "  ".join(s)


def hexdiff(x,y):
    x=str(x)[::-1]
    y=str(y)[::-1]
    SUBST=1
    INSERT=1
    d={}
    d[-1,-1] = 0,(-1,-1)
    for j in range(len(y)):
        d[-1,j] = d[-1,j-1][0]+INSERT, (-1,j-1)
    for i in range(len(x)):
        d[i,-1] = d[i-1,-1][0]+INSERT, (i-1,-1)

    for j in range(len(y)):
        for i in range(len(x)):
            d[i,j] = min( ( d[i-1,j-1][0]+SUBST*(x[i] != y[j]), (i-1,j-1) ),
                          ( d[i-1,j][0]+INSERT, (i-1,j) ),
                          ( d[i,j-1][0]+INSERT, (i,j-1) ) )
                          

    backtrackx = []
    backtracky = []
    i=len(x)-1
    j=len(y)-1
    while not (i == j == -1):
        i2,j2 = d[i,j][1]
        backtrackx.append(x[i2+1:i+1])
        backtracky.append(y[j2+1:j+1])
        i,j = i2,j2

        

    x = y = i = 0
    colorize = { 0: lambda x:x,
                -1: conf.color_theme.left,
                 1: conf.color_theme.right }
    
    dox=1
    doy=0
    l = len(backtrackx)
    while i < l:
        separate=0
        linex = backtrackx[i:i+16]
        liney = backtracky[i:i+16]
        xx = sum(len(k) for k in linex)
        yy = sum(len(k) for k in liney)
        if dox and not xx:
            dox = 0
            doy = 1
        if dox and linex == liney:
            doy=1
            
        if dox:
            xd = y
            j = 0
            while not linex[j]:
                j += 1
                xd -= 1
            print colorize[doy-dox]("%04x" % xd),
            x += xx
            line=linex
        else:
            print "    ",
        if doy:
            yd = y
            j = 0
            while not liney[j]:
                j += 1
                yd -= 1
            print colorize[doy-dox]("%04x" % yd),
            y += yy
            line=liney
        else:
            print "    ",
            
        print " ",
        
        cl = ""
        for j in range(16):
            if i+j < l:
                if line[j]:
                    col = colorize[(linex[j]!=liney[j])*(doy-dox)]
                    print col("%02X" % ord(line[j])),
                    if linex[j]==liney[j]:
                        cl += sane_color(line[j])
                    else:
                        cl += col(sane(line[j]))
                else:
                    print "  ",
                    cl += " "
            else:
                print "  ",
            if j == 7:
                print "",


        print " ",cl

        if doy or not yy:
            doy=0
            dox=1
            i += 16
        else:
            if yy:
                dox=0
                doy=1
            else:
                i += 16

    
crc32 = zlib.crc32

if BIG_ENDIAN:
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff
else:
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff

def warning(x):
    log_runtime.warning(x)

def mac2str(mac):
    return "".join(map(lambda x: chr(int(x,16)), mac.split(":")))

def str2mac(s):
    return ("%02x:"*6)[:-1] % tuple(map(ord, s)) 

def strxor(x,y):
    return "".join(map(lambda x,y:chr(ord(x)^ord(y)),x,y))

def atol(x):
    try:
        ip = inet_aton(x)
    except socket.error:
        ip = inet_aton(socket.gethostbyname(x))
    return struct.unpack("!I", ip)[0]
def ltoa(x):
    return inet_ntoa(struct.pack("!I", x))

def itom(x):
    return (0xffffffff00000000L>>x)&0xffffffffL

def do_graph(graph,prog=None,format="svg",target=None, type=None,string=None,options=None):
    """do_graph(graph, prog=conf.prog.dot, format="svg",
         target="| conf.prog.display", options=None, [string=1]):
    string: if not None, simply return the graph string
    graph: GraphViz graph description
    format: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
    target: filename or redirect. Defaults pipe to Imagemagick's display program
    prog: which graphviz program to use
    options: options to be passed to prog"""
        

    if string:
        return graph
    if type is not None:
        format=type
    if prog is None:
        prog = conf.prog.dot
    if target is None:
        target = "| %s" % conf.prog.display
    if format is not None:
        format = "-T %s" % format
    w,r = os.popen2("%s %s %s %s" % (prog,options or "", format or "", target))
    w.write(graph)
    w.close()

_TEX_TR = {
    "{":"{\\tt\\char123}",
    "}":"{\\tt\\char125}",
    "\\":"{\\tt\\char92}",
    "^":"\\^{}",
    "$":"\\$",
    "#":"\\#",
    "~":"\\~",
    "_":"\\_",
    "&":"\\&",
    "%":"\\%",
    "|":"{\\tt\\char124}",
    "~":"{\\tt\\char126}",
    "<":"{\\tt\\char60}",
    ">":"{\\tt\\char62}",
    }
    
def tex_escape(x):
    s = ""
    for c in x:
        s += _TEX_TR.get(c,c)
    return s

def colgen(*lstcol,**kargs):
    """Returns a generator that mixes provided quantities forever
    trans: a function to convert the three arguments into a color. lambda x,y,z:(x,y,z) by default"""
    if len(lstcol) < 2:
        lstcol *= 2
    trans = kargs.get("trans", lambda x,y,z: (x,y,z))
    while 1:
        for i in range(len(lstcol)):
            for j in range(len(lstcol)):
                for k in range(len(lstcol)):
                    if i != j or j != k or k != i:
                        yield trans(lstcol[(i+j)%len(lstcol)],lstcol[(j+k)%len(lstcol)],lstcol[(k+i)%len(lstcol)])

def incremental_label(label="tag%05i", start=0):
    while True:
        yield label % start
        start += 1

#########################
#### Enum management ####
#########################

class EnumElement:
    _value=None
    def __init__(self, key, value):
        self._key = key
        self._value = value
    def __repr__(self):
        return "<%s %s[%r]>" % (self.__dict__.get("_name", self.__class__.__name__), self._key, self._value)
    def __getattr__(self, attr):
        return getattr(self._value, attr)
    def __str__(self):
        return self._key
    def __eq__(self, other):
        return self._value == int(other)


class Enum_metaclass(type):
    element_class = EnumElement
    def __new__(cls, name, bases, dct):
        rdict={}
        for k,v in dct.iteritems():
            if type(v) is int:
                v = cls.element_class(k,v)
                dct[k] = v
                rdict[v] = k
        dct["__rdict__"] = rdict
        return super(Enum_metaclass, cls).__new__(cls, name, bases, dct)
    def __getitem__(self, attr):
        return self.__rdict__[attr]
    def __contains__(self, val):
        return val in self.__rdict__
    def get(self, attr, val=None):
        return self._rdict__.get(attr, val)
    def __repr__(self):
        return "<%s>" % self.__dict__.get("name", self.__name__)




##############################
## Session saving/restoring ##
##############################


def save_session(fname, session=None, pickleProto=-1):
    if session is None:
        session = scapy_session

    to_be_saved = session.copy()
        
    if to_be_saved.has_key("__builtins__"):
        del(to_be_saved["__builtins__"])

    for k in to_be_saved.keys():
        if type(to_be_saved[k]) in [types.TypeType, types.ClassType, types.ModuleType]:
             log_interactive.error("[%s] (%s) can't be saved." % (k, type(to_be_saved[k])))
             del(to_be_saved[k])

    try:
        os.rename(fname, fname+".bak")
    except OSError:
        pass
    f=gzip.open(fname,"wb")
    cPickle.dump(to_be_saved, f, pickleProto)
    f.close()

def load_session(fname):
    try:
        s = cPickle.load(gzip.open(fname,"rb"))
    except IOError:
        s = cPickle.load(open(fname,"rb"))
    scapy_session.clear()
    scapy_session.update(s)

def update_session(fname):
    try:
        s = cPickle.load(gzip.open(fname,"rb"))
    except IOError:
        s = cPickle.load(open(fname,"rb"))
    scapy_session.update(s)


def export_object(obj):
    print base64.encodestring(gzip.zlib.compress(cPickle.dumps(obj,2),9))

def import_object(obj=None):
    if obj is None:
        obj = sys.stdin.read()
    return cPickle.loads(gzip.zlib.decompress(base64.decodestring(obj.strip())))


def save_object(fname, obj):
    cPickle.dump(obj,gzip.open(fname,"wb"))

def load_object(fname):
    return cPickle.load(gzip.open(fname,"rb"))


#################
## Debug class ##
#################

class debug:
    recv=[]
    sent=[]
    match=[]


####################
## IP Tools class ##
####################

class IPTools:
    """Add more powers to a class that have a "src" attribute."""
    def whois(self):
        os.system("whois %s" % self.src)
    def ottl(self):
        t = [32,64,128,255]+[self.ttl]
        t.sort()
        return t[t.index(self.ttl)+1]
    def hops(self):
        return self.ottl()-self.ttl-1 


##############################
## Routing/Interfaces stuff ##
##############################

class Route:
    def __init__(self):
        self.resync()
        self.s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cache = {}

    def invalidate_cache(self):
        self.cache = {}

    def resync(self):
        self.invalidate_cache()
        self.routes = read_routes()

    def __repr__(self):
        rt = "Network         Netmask         Gateway         Iface           Output IP\n"
        for net,msk,gw,iface,addr in self.routes:
            rt += "%-15s %-15s %-15s %-15s %-15s\n" % (ltoa(net),
                                              ltoa(msk),
                                              gw,
                                              iface,
                                              addr)
        return rt

    def make_route(self, host=None, net=None, gw=None, dev=None):
        if host is not None:
            thenet,msk = host,32
        elif net is not None:
            thenet,msk = net.split("/")
            msk = int(msk)
        else:
            raise Scapy_Exception("make_route: Incorrect parameters. You should specify a host or a net")
        if gw is None:
            gw="0.0.0.0"
        if dev is None:
            if gw:
                nhop = gw
            else:
                nhop = thenet
            dev,ifaddr,x = self.route(nhop)
        else:
            ifaddr = get_if_addr(dev)
        return (atol(thenet), itom(msk), gw, dev, ifaddr)

    def add(self, *args, **kargs):
        """Ex:
        add(net="192.168.1.0/24",gw="1.2.3.4")
        """
        self.invalidate_cache()
        self.routes.append(self.make_route(*args,**kargs))

        
    def delt(self,  *args, **kargs):
        """delt(host|net, gw|dev)"""
        self.invalidate_cache()
        route = self.make_route(*args,**kargs)
        try:
            i=self.routes.index(route)
            del(self.routes[i])
        except ValueError:
            warning("no matching route found")
             
    def ifchange(self, iff, addr):
        self.invalidate_cache()
        the_addr,the_msk = (addr.split("/")+["32"])[:2]
        the_msk = itom(int(the_msk))
        the_rawaddr = atol(the_addr)
        the_net = the_rawaddr & the_msk
        
        
        for i in range(len(self.routes)):
            net,msk,gw,iface,addr = self.routes[i]
            if iface != iff:
                continue
            if gw == '0.0.0.0':
                self.routes[i] = (the_net,the_msk,gw,iface,the_addr)
            else:
                self.routes[i] = (net,msk,gw,iface,the_addr)
        for i in arp_cache.keys():
            del(arp_cache[i])
        
                

    def ifdel(self, iff):
        self.invalidate_cache()
        new_routes=[]
        for rt in self.routes:
            if rt[3] != iff:
                new_routes.append(rt)
        self.routes=new_routes
        
    def ifadd(self, iff, addr):
        self.invalidate_cache()
        the_addr,the_msk = (addr.split("/")+["32"])[:2]
        the_msk = itom(int(the_msk))
        the_rawaddr = atol(the_addr)
        the_net = the_rawaddr & the_msk
        self.routes.append((the_net,the_msk,'0.0.0.0',iff,the_addr))


    def route(self,dest,verbose=None):
        if dest in self.cache:
            return self.cache[dest]
        if verbose is None:
            verbose=conf.verb
        # Transform "192.168.*.1-5" to one IP of the set
        dst = dest.split("/")[0]
        dst = dst.replace("*","0") 
        while 1:
            l = dst.find("-")
            if l < 0:
                break
            m = (dst[l:]+".").find(".")
            dst = dst[:l]+dst[l+m:]

            
        dst = atol(dst)
        pathes=[]
        for d,m,gw,i,a in self.routes:
            aa = atol(a)
            if aa == dst:
                pathes.append((0xffffffffL,("lo",a,"0.0.0.0")))
            if (dst & m) == (d & m):
                pathes.append((m,(i,a,gw)))
        if not pathes:
            if verbose:
                warning("No route found (no default route?)")
            return "lo","0.0.0.0","0.0.0.0" #XXX linux specific!
        # Choose the more specific route (greatest netmask).
        # XXX: we don't care about metrics
        pathes.sort()
        ret = pathes[-1][1]
        self.cache[dest] = ret
        return ret
            
    def get_if_bcast(self, iff):
        for net, msk, gw, iface, addr in self.routes:
            if (iff == iface and net != 0L):
                bcast = atol(addr)|(~msk&0xffffffffL); # FIXME: check error in atol()
                return ltoa(bcast);
        warning("No broadcast address found for iface %s\n" % iff);

if DNET:
    def get_if_raw_hwaddr(iff):
        if iff[:2] == "lo":
            return (772, '\x00'*6)
        try:
            l = dnet.intf().get(iff)
            l = l["link_addr"]
        except:
            raise Scapy_Exception("Error in attempting to get hw address for interface [%s]" % iff)
        return l.type,l.data
    def get_if_raw_addr(ifname):
        i = dnet.intf()
        return i.get(ifname)["addr"].data
else:
    def get_if_raw_hwaddr(iff):
        return struct.unpack("16xh6s8x",get_if(iff,SIOCGIFHWADDR))

    def get_if_raw_addr(iff):
        try:
            return get_if(iff, SIOCGIFADDR)[20:24]
        except IOError:
            return "\0\0\0\0"


if PCAP:
    def get_if_list():
        # remove 'any' interface
        return map(lambda x:x[0],filter(lambda x:x[1] is None,pcap.findalldevs()))
    def get_working_if():
        try:
            return pcap.lookupdev()
        except pcap.pcapc.EXCEPTION:
            return 'lo'

    def attach_filter(s, filter):
        warning("attach_filter() should not be called in PCAP mode")
    def set_promisc(s,iff,val=1):
        warning("set_promisc() should not be called in DNET/PCAP mode")
    
else:
    def get_if_list():
        f=open("/proc/net/dev","r")
        lst = []
        f.readline()
        f.readline()
        for l in f:
            lst.append(l.split(":")[0].strip())
        return lst
    def get_working_if():
        for i in get_if_list():
            if i == 'lo':                
                continue
            ifflags = struct.unpack("16xH14x",get_if(i,SIOCGIFFLAGS))[0]
            if ifflags & IFF_UP:
                return i
        return "lo"
    def attach_filter(s, filter):
        # XXX We generate the filter on the interface conf.iface 
        # because tcpdump open the "any" interface and ppp interfaces
        # in cooked mode. As we use them in raw mode, the filter will not
        # work... one solution could be to use "any" interface and translate
        # the filter from cooked mode to raw mode
        # mode
        if not TCPDUMP:
            return
        try:
            f = os.popen("%s -i %s -ddd -s 1600 '%s'" % (conf.prog.tcpdump,conf.iface,filter))
        except OSError,msg:
            log_interactive.warning("Failed to execute tcpdump: (%s)")
            return
        lines = f.readlines()
        if f.close():
            raise Scapy_Exception("Filter parse error")
        nb = int(lines[0])
        bpf = ""
        for l in lines[1:]:
            bpf += struct.pack("HBBI",*map(long,l.split()))
    
        # XXX. Argl! We need to give the kernel a pointer on the BPF,
        # python object header seems to be 20 bytes. 36 bytes for x86 64bits arch.
        if X86_64:
            bpfh = struct.pack("HL", nb, id(bpf)+36)
        else:
            bpfh = struct.pack("HI", nb, id(bpf)+20)  
        s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, bpfh)

    def set_promisc(s,iff,val=1):
        mreq = struct.pack("IHH8s", get_if_index(iff), PACKET_MR_PROMISC, 0, "")
        if val:
            cmd = PACKET_ADD_MEMBERSHIP
        else:
            cmd = PACKET_DROP_MEMBERSHIP
        s.setsockopt(SOL_PACKET, cmd, mreq)


if not LINUX:

    def new_read_routes():

        rtlst = []
        def addrt(rt,lst):
            dst,gw = rt
            lst.append(rt)

        r = dnet.route()
        print r.loop(addrt, rtlst)
        return rtlst

    def read_routes():
        if SOLARIS:
            f=os.popen("netstat -rvn") # -f inet
        elif FREEBSD:
            f=os.popen("netstat -rnW") # -W to handle long interface names
        else:
            f=os.popen("netstat -rn") # -f inet
        ok = 0
        mtu_present = False
        routes = []
        for l in f.readlines():
            if not l:
                break
            l = l.strip()
            if l.find("----") >= 0: # a separation line
                continue
            if l.find("Destination") >= 0:
                ok = 1
                if l.find("Mtu") >= 0:
                    mtu_present = True
                continue
            if ok == 0:
                continue
            if not l:
                break
            if SOLARIS:
                dest,mask,gw,netif,mxfrg,rtt,ref,flg = l.split()[:8]
            else:
                if mtu_present:
                    dest,gw,flg,ref,use,mtu,netif = l.split()[:7]
                else:
                    dest,gw,flg,ref,use,netif = l.split()[:6]
            if flg.find("Lc") >= 0:
                continue                
            if dest == "default":
                dest = 0L
                netmask = 0L
            else:
                if SOLARIS:
                    netmask = atol(mask)
                elif "/" in dest:
                    dest,netmask = dest.split("/")
                    netmask = itom(int(netmask))
                else:
                    netmask = itom((dest.count(".") + 1) * 8)
                dest += ".0"*(3-dest.count("."))
                dest = atol(dest)
            if not "G" in flg:
                gw = '0.0.0.0'
            ifaddr = get_if_addr(netif)
            routes.append((dest,netmask,gw,netif,ifaddr))
        f.close()
        return routes

    def read_interfaces():
        i = dnet.intf()
        ifflist = {}
        def addif(iff,lst):
            if not iff.has_key("addr"):
                return
            if not iff.has_key("link_addr"):
                return
            rawip = iff["addr"].data
            ip = inet_ntoa(rawip)
            rawll = iff["link_addr"].data
            ll = str2mac(rawll)
            lst[iff["name"]] = (rawll,ll,rawip,ip)
        i.loop(addif, ifflist)
        return ifflist

            
else:

    def read_routes():
        f=open("/proc/net/route","r")
        routes = []
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x","lo"))
        addrfamily = struct.unpack("h",ifreq[16:18])[0]
        if addrfamily == socket.AF_INET:
            ifreq2 = ioctl(s, SIOCGIFNETMASK,struct.pack("16s16x","lo"))
            msk = socket.ntohl(struct.unpack("I",ifreq2[20:24])[0])
            dst = socket.ntohl(struct.unpack("I",ifreq[20:24])[0]) & msk
            ifaddr = inet_ntoa(ifreq[20:24])
            routes.append((dst, msk, "0.0.0.0", "lo", ifaddr))
        else:
            warning("Interface lo: unkown address family (%i)"% addrfamily)
    
        for l in f.readlines()[1:]:
            iff,dst,gw,flags,x,x,x,msk,x,x,x = l.split()
            flags = int(flags,16)
            if flags & RTF_UP == 0:
                continue
            if flags & RTF_REJECT:
                continue
            try:
                ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x",iff))
            except IOError: # interface is present in routing tables but does not have any assigned IP
                ifaddr="0.0.0.0"
            else:
                addrfamily = struct.unpack("h",ifreq[16:18])[0]
                if addrfamily == socket.AF_INET:
                    ifaddr = inet_ntoa(ifreq[20:24])
                else:
                    warning("Interface %s: unkown address family (%i)"%(iff, addrfamily))
                    continue
            routes.append((socket.htonl(long(dst,16))&0xffffffffL,
                           socket.htonl(long(msk,16))&0xffffffffL,
                           inet_ntoa(struct.pack("I",long(gw,16))),
                           iff, ifaddr))
        
        f.close()
        return routes

    def get_if(iff,cmd):
        s=socket.socket()
        ifreq = ioctl(s, cmd, struct.pack("16s16x",iff))
        s.close()
        return ifreq


    def get_if_index(iff):
        return int(struct.unpack("I",get_if(iff, SIOCGIFINDEX)[16:20])[0])

    def get_last_packet_timestamp(sock):
        ts = ioctl(sock, SIOCGSTAMP, "12345678")
        s,us = struct.unpack("II",ts)
        return s+us/1000000.0

    
def get_if_addr(iff):
    return inet_ntoa(get_if_raw_addr(iff))
    
def get_if_hwaddr(iff):
    addrfamily, mac = get_if_raw_hwaddr(iff)
    if addrfamily in [ARPHDR_ETHER,ARPHDR_LOOPBACK]:
        return str2mac(mac)
    else:
        raise Scapy_Exception("Unsupported address family (%i) for interface [%s]" % (addrfamily,iff))



#####################
## ARP cache stuff ##
#####################

ARPTIMEOUT=120

# XXX Fill arp_cache with /etc/ether and arp cache
arp_cache={}

if 0 and DNET: ## XXX Can't use this because it does not resolve IPs not in cache
    dnet_arp_object = dnet.arp()
    def getmacbyip(ip, chainCC=0):
        tmp = map(ord, inet_aton(ip))
        if (tmp[0] & 0xf0) == 0xe0: # mcast @
            return "01:00:5e:%.2x:%.2x:%.2x" % (tmp[1]&0x7f,tmp[2],tmp[3])
        iff,a,gw = conf.route.route(ip)
        if iff == "lo":
            return "ff:ff:ff:ff:ff:ff"
        if gw != "0.0.0.0":
            ip = gw
        res = dnet_arp_object.get(dnet.addr(ip))
        if res is None:
            return None
        else:
            return res.ntoa()
else:
    def getmacbyip(ip, chainCC=0):
        tmp = map(ord, inet_aton(ip))
        if (tmp[0] & 0xf0) == 0xe0: # mcast @
            return "01:00:5e:%.2x:%.2x:%.2x" % (tmp[1]&0x7f,tmp[2],tmp[3])
        iff,a,gw = conf.route.route(ip)
        if ( (iff == "lo") or (ip == conf.route.get_if_bcast(iff)) ):
            return "ff:ff:ff:ff:ff:ff"
        if gw != "0.0.0.0":
            ip = gw
    
        if arp_cache.has_key(ip):
            mac, timeout = arp_cache[ip]
            if not timeout or (time.time()-timeout < ARPTIMEOUT):
                return mac

        res = srp1(Ether(dst=ETHER_BROADCAST)/ARP(op="who-has", pdst=ip),
                   type=ETH_P_ARP,
                   iface = iff,
                   timeout=2,
                   verbose=0,
                   chainCC=chainCC,
                   nofilter=1)
        if res is not None:
            mac = res.payload.hwsrc
            arp_cache[ip] = (mac,time.time())
            return mac
        return None
    

####################
## Random numbers ##
####################

def randseq(inf, sup, seed=None, forever=1, renewkeys=0):
    """iterate through a sequence in random order.
       When all the values have been drawn, if forever=1, the drawing is done again.
       If renewkeys=0, the draw will be in the same order, guaranteeing that the same
       number will be drawn in not less than the number of integers of the sequence"""
    rnd = random.Random(seed)
    sbox_size = 256

    top = sup-inf+1
    
    n=0
    while (1<<n) < top:
        n += 1

    fs = min(3,(n+1)/2)
    fsmask = 2**fs-1
    rounds = max(n,3)
    turns = 0

    while 1:
        if turns == 0 or renewkeys:
            sbox = [rnd.randint(0,fsmask) for k in xrange(sbox_size)]
        turns += 1
        i = 0
        while i < 2**n:
            ct = i
            i += 1
            for k in range(rounds): # Unbalanced Feistel Network
                lsb = ct & fsmask
                ct >>= fs
                lsb ^= sbox[ct%sbox_size]
                ct |= lsb << (n-fs)
            
            if ct < top:
                yield inf+ct
        if not forever:
            break


class VolatileValue:
    def __repr__(self):
        return "<%s>" % self.__class__.__name__
    def __getattr__(self, attr):
        if attr == "__setstate__":
            raise AttributeError(attr)
        return getattr(self._fix(),attr)
    def _fix(self):
        return None


class RandField(VolatileValue):
    pass


class RandNum(RandField):
    min = 0
    max = 0
    def __init__(self, min, max):
        self.seq = randseq(min,max)
    def _fix(self):
        return self.seq.next()

class RandNumGamma(RandField):
    def __init__(self, alpha, beta):
        self.alpha = alpha
        self.beta = beta
    def _fix(self):
        return int(round(random.gammavariate(self.alpha, self.beta)))

class RandNumGauss(RandField):
    def __init__(self, mu, sigma):
        self.mu = mu
        self.sigma = sigma
    def _fix(self):
        return int(round(random.gauss(self.mu, self.sigma)))

class RandNumExpo(RandField):
    def __init__(self, lambd):
        self.lambd = lambd
    def _fix(self):
        return int(round(random.expovariate(self.lambd)))

class RandByte(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**8-1)

class RandShort(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**16-1)

class RandInt(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**32-1)

class RandSInt(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2L**31, 2L**31-1)

class RandLong(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**64-1)

class RandSLong(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2L**63, 2L**63-1)

class RandChoice(RandField):
    def __init__(self, *args):
        self._choice = args
    def _fix(self):
        return random.choice(self._choice)
    
class RandString(RandField):
    def __init__(self, size, chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
        self.chars = chars
        self.size = size
    def _fix(self):
        s = ""
        for i in range(self.size):
            s += random.choice(self.chars)
        return s

class RandBin(RandString):
    def __init__(self, size):
        RandString.__init__(self, size, "".join(map(chr,range(256))))


class RandTermString(RandString):
    def __init__(self, size, term):
        RandString.__init__(self, size, "".join(map(chr,range(1,256))))
        self.term = term
    def _fix(self):
        return RandString._fix(self)+self.term
    
    

class RandIP(RandString):
    def __init__(self, iptemplate="0.0.0.0/0"):
        self.ip = Net(iptemplate)
    def _fix(self):
        return self.ip.choice()

class RandMAC(RandString):
    def __init__(self, template="*"):
        template += ":*:*:*:*:*"
        template = template.split(":")
        self.mac = ()
        for i in range(6):
            if template[i] == "*":
                v = RandByte()
            elif "-" in template[i]:
                x,y = template[i].split("-")
                v = RandNum(int(x,16), int(y,16))
            else:
                v = int(template[i],16)
            self.mac += (v,)
    def _fix(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % self.mac
    

class RandOID(RandString):
    def __init__(self, fmt=None, depth=RandNumExpo(0.1), idnum=RandNumExpo(0.01)):
        self.ori_fmt = fmt
        if fmt is not None:
            fmt = fmt.split(".")
            for i in range(len(fmt)):
                if "-" in fmt[i]:
                    fmt[i] = tuple(map(int, fmt[i].split("-")))
        self.fmt = fmt
        self.depth = depth
        self.idnum = idnum
    def __repr__(self):
        if self.ori_fmt is None:
            return "<%s>" % self.__class__.__name__
        else:
            return "<%s [%s]>" % (self.__class__.__name__, self.ori_fmt)
    def _fix(self):
        if self.fmt is None:
            return ".".join(map(str, [self.idnum for i in xrange(1+self.depth)]))
        else:
            oid = []
            for i in self.fmt:
                if i == "*":
                    oid.append(str(self.idnum))
                elif i == "**":
                    oid += map(str, [self.idnum for i in xrange(1+self.depth)])
                elif type(i) is tuple:
                    oid.append(str(random.randrange(*i)))
                else:
                    oid.append(i)
            return ".".join(oid)
            


class RandASN1Object(RandField):
    def __init__(self, objlist=None):
        if objlist is None:
            objlist = map(lambda x:x._asn1_obj,
                          filter(lambda x:hasattr(x,"_asn1_obj"), ASN1_Class_UNIVERSAL.__rdict__.values()))
        self.objlist = objlist
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    def _fix(self, n=0):
        o = random.choice(self.objlist)
        if issubclass(o, ASN1_INTEGER):
            return o(int(random.gauss(0,1000)))
        elif issubclass(o, ASN1_STRING):
            z = int(random.expovariate(0.05)+1)
            return o("".join([random.choice(self.chars) for i in range(z)]))
        elif issubclass(o, ASN1_SEQUENCE) and (n < 10):
            z = int(random.expovariate(0.08)+1)
            return o(map(lambda x:x._fix(n+1), [self.__class__(objlist=self.objlist)]*z))
        return ASN1_INTEGER(int(random.gauss(0,1000)))


# Automatic timestamp

class AutoTime(VolatileValue):
    def __init__(self, base=None):
        if base == None:
            self.diff = 0
        else:
            self.diff = time.time()-base
    def _fix(self):
        return time.time()-self.diff
            
class IntAutoTime(AutoTime):
    def _fix(self):
        return int(time.time()-self.diff)



class DelayedEval(VolatileValue):
    """ Exemple of usage: DelayedEval("time.time()") """
    def __init__(self, expr):
        self.expr = expr
    def _fix(self):
        return eval(self.expr)


class IncrementalValue(VolatileValue):
    def __init__(self, start=0, step=1, restart=-1):
        self.start = self.val = start
        self.step = step
        self.restart = restart
    def _fix(self):
        v = self.val
        if self.val == self.restart :
            self.val = self.start
        else:
            self.val += self.step
        return v

def corrupt_bytes(s, p=0.01, n=None):
    s = array.array("B",str(s))
    l = len(s)
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i] = random.randint(0,255)
    return s.tostring()

def corrupt_bits(s, p=0.01, n=None):
    s = array.array("B",str(s))
    l = len(s)*8
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i/8] ^= 1 << (i%8)
    return s.tostring()

    
class CorruptedBytes(VolatileValue):
    def __init__(self, s, p=0.01, n=None):
        self.s = s
        self.p = p
        self.n = n
    def _fix(self):
        return corrupt_bytes(self.s, self.p, self.n)

class CorruptedBits(CorruptedBytes):
    def _fix(self):
        return corrupt_bits(self.s, self.p, self.n)

##############
#### ASN1 ####
##############

class ASN1_Error(Exception):
    pass

class ASN1_Encoding_Error(ASN1_Error):
    pass

class ASN1_Decoding_Error(ASN1_Error):
    pass

class ASN1_BadTag_Decoding_Error(ASN1_Decoding_Error):
    pass



class ASN1Codec(EnumElement):
    def register_stem(cls, stem):
        cls._stem = stem
    def dec(cls, s, context=None):
        return cls._stem.dec(s, context=context)
    def safedec(cls, s, context=None):
        return cls._stem.safedec(s, context=context)
    def get_stem(cls):
        return cls.stem
    

class ASN1_Codecs_metaclass(Enum_metaclass):
    element_class = ASN1Codec

class ASN1_Codecs:
    __metaclass__ = ASN1_Codecs_metaclass
    BER = 1
    DER = 2
    PER = 3
    CER = 4
    LWER = 5
    BACnet = 6
    OER = 7
    SER = 8
    XER = 9

class ASN1Tag(EnumElement):
    def __init__(self, key, value, context=None, codec=None):
        EnumElement.__init__(self, key, value)
        self._context = context
        if codec == None:
            codec = {}
        self._codec = codec
    def clone(self): # /!\ not a real deep copy. self.codec is shared
        return self.__class__(self._key, self._value, self._context, self._codec)
    def register_asn1_object(self, asn1obj):
        self._asn1_obj = asn1obj
    def asn1_object(self, val):
        if hasattr(self,"_asn1_obj"):
            return self._asn1_obj(val)
        raise ASN1_Error("%r does not have any assigned ASN1 object" % self)
    def register(self, codecnum, codec):
        self._codec[codecnum] = codec
    def get_codec(self, codec):
        try:
            c = self._codec[codec]
        except KeyError,msg:
            raise ASN1_Error("Codec %r not found for tag %r" % (codec, self))
        return c

class ASN1_Class_metaclass(Enum_metaclass):
    element_class = ASN1Tag
    def __new__(cls, name, bases, dct): # XXX factorise a bit with Enum_metaclass.__new__()
        for b in bases:
            for k,v in b.__dict__.iteritems():
                if k not in dct and isinstance(v,ASN1Tag):
                    dct[k] = v.clone()

        rdict = {}
        for k,v in dct.iteritems():
            if type(v) is int:
                v = ASN1Tag(k,v) 
                dct[k] = v
                rdict[v] = v
            elif isinstance(v, ASN1Tag):
                rdict[v] = v
        dct["__rdict__"] = rdict

        cls = type.__new__(cls, name, bases, dct)
        for v in cls.__dict__.values():
            if isinstance(v, ASN1Tag): 
                v.context = cls # overwrite ASN1Tag contexts, even cloned ones
        return cls
            

class ASN1_Class:
    __metaclass__ = ASN1_Class_metaclass

class ASN1_Class_UNIVERSAL(ASN1_Class):
    name = "UNIVERSAL"
    ERROR = -3
    RAW = -2
    NONE = -1
    ANY = 0
    BOOLEAN = 1
    INTEGER = 2
    BIT_STRING = 3
    STRING = 4
    NULL = 5
    OID = 6
    OBJECT_DESCRIPTOR = 7
    EXTERNAL = 8
    REAL = 9
    ENUMERATED = 10
    EMBEDDED_PDF = 11
    UTF8_STRING = 12
    RELATIVE_OID = 13
    SEQUENCE = 0x30#XXX 16 ??
    SET = 0x31 #XXX 17 ??
    NUMERIC_STRING = 18
    PRINTABLE_STRING = 19
    T61_STRING = 20
    VIDEOTEX_STRING = 21
    IA5_STRING = 22
    UTC_TIME = 23
    GENERALIZED_TIME = 24
    GRAPHIC_STRING = 25
    ISO646_STRING = 26
    GENERAL_STRING = 27
    UNIVERSAL_STRING = 28
    CHAR_STRING = 29
    BMP_STRING = 30
    COUNTER32 = 0x41
    TIME_TICKS = 0x43

class ASN1_Object_metaclass(type):
    def __new__(cls, name, bases, dct):
        c = super(ASN1_Object_metaclass, cls).__new__(cls, name, bases, dct)
        try:
            c.tag.register_asn1_object(c)
        except:
            warning("Error registering %r for %r" % (c.tag, c.codec))
        return c


class ASN1_Object:
    __metaclass__ = ASN1_Object_metaclass
    tag = ASN1_Class_UNIVERSAL.ANY
    def __init__(self, val):
        self.val = val
    def enc(self, codec):
        return self.tag.get_codec(codec).enc(self.val)
    def __repr__(self):
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), self.val)
    def __str__(self):
        return self.enc(conf.ASN1_default_codec)
    def strshow(self, lvl=0):
        return ("  "*lvl)+repr(self)+"\n"
    def show(self, lvl=0):
        print self.strshow(lvl)
    def __eq__(self, other):
        return self.val == other
    def __cmp__(self, other):
        return cmp(self.val, other)

class ASN1_DECODING_ERROR(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.ERROR
    def __init__(self, val, exc=None):
        ASN1_Object.__init__(self, val)
        self.exc = exc
    def __repr__(self):
        return "<%s[%r]{{%s}}>" % (self.__dict__.get("name", self.__class__.__name__),
                                   self.val, self.exc.args[0])
    def enc(self, codec):
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val

class ASN1_force(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.RAW
    def enc(self, codec):
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val

class ASN1_BADTAG(ASN1_force):
    pass

class ASN1_INTEGER(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.INTEGER

class ASN1_STRING(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.STRING

class ASN1_BIT_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

class ASN1_PRINTABLE_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class ASN1_T61_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING

class ASN1_IA5_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING

class ASN1_NUMERIC_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING

class ASN1_VIDEOTEX_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING

class ASN1_UTC_TIME(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME

class ASN1_TIME_TICKS(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS

class ASN1_BOOLEAN(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN
    
class ASN1_NULL(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.NULL

class ASN1_COUNTER32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32
    
class ASN1_SEQUENCE(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE
    def strshow(self, lvl=0):
        s = ("  "*lvl)+("# %s:" % self.__class__.__name__)+"\n"
        for o in self.val:
            s += o.strshow(lvl=lvl+1)
        return s
    
class ASN1_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET
    
class ASN1_OID(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.OID
    def __init__(self, val):
        val = conf.mib._oid(val)
        ASN1_Object.__init__(self, val)
    def __repr__(self):
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), conf.mib._oidname(self.val))
    


##################
## BER encoding ##
##################



#####[ BER tools ]#####


class BER_Exception(Exception):
    pass

class BER_Decoding_Error(ASN1_Decoding_Error):
    def __init__(self, msg, decoded=None, remaining=None):
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.decoded = decoded
    def __str__(self):
        s = Exception.__str__(self)
        if isinstance(self.decoded, BERcodec_Object):
            s+="\n### Already decoded ###\n%s" % self.decoded.strshow()
        else:
            s+="\n### Already decoded ###\n%r" % self.decoded
        s+="\n### Remaining ###\n%r" % self.remaining
        return s

class BER_BadTag_Decoding_Error(BER_Decoding_Error, ASN1_BadTag_Decoding_Error):
    pass

def BER_len_enc(l, size=0):
        if l <= 127 and size==0:
            return chr(l)
        s = ""
        while l or size>0:
            s = chr(l&0xff)+s
            l >>= 8L
            size -= 1
        if len(s) > 127:
            raise BER_Exception("BER_len_enc: Length too long (%i) to be encoded [%r]" % (len(s),s))
        return chr(len(s)|0x80)+s
def BER_len_dec(s):
        l = ord(s[0])
        if not l & 0x80:
            return l,s[1:]
        l &= 0x7f
        if len(s) <= l:
            raise BER_Decoding_Error("BER_len_dec: Got %i bytes while expecting %i" % (len(s)-1, l),remaining=s)
        ll = 0L
        for c in s[1:l+1]:
            ll <<= 8L
            ll |= ord(c)
        return ll,s[l+1:]
        
def BER_num_enc(l, size=1):
        x=[]
        while l or size>0:
            x.insert(0, l & 0x7f)
            if len(x) > 1:
                x[0] |= 0x80
            l >>= 7
            size -= 1
        return "".join([chr(k) for k in x])
def BER_num_dec(s):
        x = 0
        for i in range(len(s)):
            c = ord(s[i])
            x <<= 7
            x |= c&0x7f
            if not c&0x80:
                break
        if c&0x80:
            raise BER_Decoding_Error("BER_num_dec: unfinished number description", remaining=s)
        return x, s[i+1:]

#####[ BER classes ]#####

class BERcodec_metaclass(type):
    def __new__(cls, name, bases, dct):
        c = super(BERcodec_metaclass, cls).__new__(cls, name, bases, dct)
        try:
            c.tag.register(c.codec, c)
        except:
            warning("Error registering %r for %r" % (c.tag, c.codec))
        return c


class BERcodec_Object:
    __metaclass__ = BERcodec_metaclass
    codec = ASN1_Codecs.BER
    tag = ASN1_Class_UNIVERSAL.ANY

    @classmethod
    def asn1_object(cls, val):
        return cls.tag.asn1_object(val)

    @classmethod
    def check_string(cls, s):
        if not s:
            raise BER_Decoding_Error("%s: Got empty object while expecting tag %r" %
                                     (cls.__name__,cls.tag), remaining=s)        
    @classmethod
    def check_type(cls, s):
        cls.check_string(s)
        if cls.tag != ord(s[0]):
            raise BER_BadTag_Decoding_Error("%s: Got tag [%i/%#x] while expecting %r" %
                                            (cls.__name__, ord(s[0]), ord(s[0]),cls.tag), remaining=s)
        return s[1:]
    @classmethod
    def check_type_get_len(cls, s):
        s2 = cls.check_type(s)
        if not s2:
            raise BER_Decoding_Error("%s: No bytes while expecting a length" %
                                     cls.__name__, remaining=s)
        return BER_len_dec(s2)
    @classmethod
    def check_type_check_len(cls, s):
        l,s3 = cls.check_type_get_len(s)
        if len(s3) < l:
            raise BER_Decoding_Error("%s: Got %i bytes while expecting %i" %
                                     (cls.__name__, len(s3), l), remaining=s)
        return l,s3[:l],s3[l:]

    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        if context is None:
            context = cls.tag.context
        cls.check_string(s)
        p = ord(s[0])
        if p not in context:
            t = s
            if len(t) > 18:
                t = t[:15]+"..."
            raise BER_Decoding_Error("Unknown prefix [%02x] for [%r]" % (p,t), remaining=s)
        codec = context[p].get_codec(ASN1_Codecs.BER)
        return codec.dec(s,context,safe)

    @classmethod
    def dec(cls, s, context=None, safe=False):
        if not safe:
            return cls.do_dec(s, context, safe)
        try:
            return cls.do_dec(s, context, safe)
        except BER_BadTag_Decoding_Error,e:
            o,remain = BERcodec_Object.dec(e.remaining, context, safe)
            return ASN1_BADTAG(o),remain
        except BER_Decoding_Error, e:
            return ASN1_DECODING_ERROR(s, exc=e),""
        except ASN1_Error, e:
            return ASN1_DECODING_ERROR(s, exc=e),""

    @classmethod
    def safedec(cls, s, context=None):
        return cls.dec(s, context, safe=True)


    @classmethod
    def enc(cls, s):
        if type(s) is str:
            return BERcodec_STRING.enc(s)
        else:
            return BERcodec_INTEGER.enc(int(s))

            

ASN1_Codecs.BER.register_stem(BERcodec_Object)


class BERcodec_INTEGER(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.INTEGER
    @classmethod
    def enc(cls, i):
        s = []
        while 1:
            s.append(i&0xff)
            if -127 <= i < 0:
                break
            if 128 <= i <= 255:
                s.append(0)
            i >>= 8
            if not i:
                break
        s = map(chr, s)
        s.append(BER_len_enc(len(s)))
        s.append(chr(cls.tag))
        s.reverse()
        return "".join(s)
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        x = 0L
        if s:
            if ord(s[0])&0x80: # negative int
                x = -1L
            for c in s:
                x <<= 8
                x |= ord(c)
        return cls.asn1_object(x),t
    

class BERcodec_BOOLEAN(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN

class BERcodec_NULL(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.NULL
    @classmethod
    def enc(cls, i):
        if i == 0:
            return chr(cls.tag)+"\0"
        else:
            return super(cls,cls).enc(i)

class BERcodec_STRING(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.STRING
    @classmethod
    def enc(cls,s):
        return chr(cls.tag)+BER_len_enc(len(s))+s
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        return cls.tag.asn1_object(s),t

class BERcodec_BIT_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

class BERcodec_PRINTABLE_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class BERcodec_T61_STRING (BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING

class BERcodec_IA5_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING

class BERcodec_UTC_TIME(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME

class BERcodec_TIME_TICKS(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS

class BERcodec_COUNTER32(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32

class BERcodec_SEQUENCE(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE
    @classmethod
    def enc(cls, l):
        if type(l) is not str:
            l = "".join(map(lambda x: x.enc(cls.codec), l))
        return chr(cls.tag)+BER_len_enc(len(l))+l
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        if context is None:
            context = cls.tag.context
        l,st = cls.check_type_get_len(s) # we may have len(s) < l
        s,t = st[:l],st[l:]
        obj = []
        while s:
            try:
                o,s = BERcodec_Object.dec(s, context, safe)
            except BER_Decoding_Error, err:
                print "enrichi %r <- %r  %r" % (err.remaining,t,s), obj
                err.remaining += t
                if err.decoded is not None:
                    obj.append(err.decoded)
                err.decoded = obj
                raise 
            obj.append(o)
        if len(st) < l:
            raise BER_Decoding_Error("Not enough bytes to decode sequence", decoded=obj)
        return cls.asn1_object(obj),t

class BERcodec_SET(BERcodec_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class BERcodec_OID(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def enc(cls, oid):
        lst = [int(x) for x in oid.strip(".").split(".")]
        if len(lst) >= 2:
            lst[1] += 40*lst[0]
            del(lst[0])
        s = "".join([BER_num_enc(k) for k in lst])
        return chr(cls.tag)+BER_len_enc(len(s))+s
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        lst = []
        while s:
            l,s = BER_num_dec(s)
            lst.append(l)
        if (len(lst) > 0):
            lst.insert(0,lst[0]/40)
            lst[1] %= 40
        return cls.asn1_object(".".join([str(k) for k in lst])), t


#################
## MIB parsing ##
#################

_mib_re_integer = re.compile("^[0-9]+$")
_mib_re_both = re.compile("^([a-zA-Z_][a-zA-Z0-9_-]*)\(([0-9]+)\)$")
_mib_re_oiddecl = re.compile("$\s*([a-zA-Z0-9_-]+)\s+OBJECT[^:]+::=\s*\{([^\}]+)\}",re.M)
_mib_re_strings = re.compile('"[^"]*"')
_mib_re_comments = re.compile('--.*(\r|\n)')

class MIBDict(DADict):
    def _findroot(self, x):
        if x.startswith("."):
            x = x[1:]
        if not x.endswith("."):
            x += "."
        max=0
        root="."
        for k in self.keys():
            if x.startswith(self[k]+"."):
                if max < len(self[k]):
                    max = len(self[k])
                    root = k
        return root, x[max:-1]
    def _oidname(self, x):
        root,remainder = self._findroot(x)
        return root+remainder
    def _oid(self, x):
        xl = x.strip(".").split(".")
        p = len(xl)-1
        while p >= 0 and _mib_re_integer.match(xl[p]):
            p -= 1
        if p != 0 or xl[p] not in self:
            return x
        xl[p] = self[xl[p]] 
        return ".".join(xl[p:])
    def _make_graph(self, other_keys=[], **kargs):
        nodes = [(k,self[k]) for k in self.keys()]
        oids = [self[k] for k in self.keys()]
        for k in other_keys:
            if k not in oids:
                nodes.append(self.oidname(k),k)
        s = 'digraph "mib" {\n\trankdir=LR;\n\n'
        for k,o in nodes:
            s += '\t"%s" [ label="%s"  ];\n' % (o,k)
        s += "\n"
        for k,o in nodes:
            parent,remainder = self._findroot(o[:-1])
            remainder = remainder[1:]+o[-1]
            if parent != ".":
                parent = self[parent]
            s += '\t"%s" -> "%s" [label="%s"];\n' % (parent, o,remainder)
        s += "}\n"
        do_graph(s, **kargs)


def mib_register(ident, value, the_mib, unresolved):
    if ident in the_mib or ident in unresolved:
        return ident in the_mib
    resval = []
    not_resolved = 0
    for v in value:
        if _mib_re_integer.match(v):
            resval.append(v)
        else:
            v = fixname(v)
            if v not in the_mib:
                not_resolved = 1
            if v in the_mib:
                v = the_mib[v]
            elif v in unresolved:
                v = unresolved[v]
            if type(v) is list:
                resval += v
            else:
                resval.append(v)
    if not_resolved:
        unresolved[ident] = resval
        return False
    else:
        the_mib[ident] = resval
        keys = unresolved.keys()
        i = 0
        while i < len(keys):
            k = keys[i]
            if mib_register(k,unresolved[k], the_mib, {}):
                del(unresolved[k])
                del(keys[i])
                i = 0
            else:
                i += 1
                    
        return True


def load_mib(filenames):
    the_mib = {'iso': ['1']}
    unresolved = {}
    for k in conf.mib.keys():
        mib_register(k, conf.mib[k].split("."), the_mib, unresolved)

    if type(filenames) is str:
        filenames = [filenames]
    for fnames in filenames:
        for fname in glob(fnames):
            f = open(fname)
            text = f.read()
            cleantext = " ".join(_mib_re_strings.split(" ".join(_mib_re_comments.split(text))))
            for m in _mib_re_oiddecl.finditer(cleantext):
                ident,oid = m.groups()
                ident=fixname(ident)
                oid = oid.split()
                for i in range(len(oid)):
                    m = _mib_re_both.match(oid[i])
                    if m:
                        oid[i] = m.groups()[1]
                mib_register(ident, oid, the_mib, unresolved)

    newmib = MIBDict(_name="MIB")
    for k,o in the_mib.iteritems():
        newmib[k]=".".join(o)
    for k,o in unresolved.iteritems():
        newmib[k]=".".join(o)

    conf.mib=newmib



################
## Generators ##
################

class Gen(object):
    def __iter__(self):
        return iter([])
    
class SetGen(Gen):
    def __init__(self, set, _iterpacket=1):
        self._iterpacket=_iterpacket
        if type(set) is list:
            self.set = set
        elif isinstance(set, PacketList):
            self.set = list(set)
        else:
            self.set = [set]
    def transf(self, element):
        return element
    def __iter__(self):
        for i in self.set:
            if (type(i) is tuple) and (len(i) == 2) and type(i[0]) is int and type(i[1]) is int:
                if  (i[0] <= i[1]):
                    j=i[0]
                    while j <= i[1]:
                        yield j
                        j += 1
            elif isinstance(i, Gen) and (self._iterpacket or not isinstance(i,Packet)):
                for j in i:
                    yield j
            else:
                yield i
    def __repr__(self):
        return "<SetGen %s>" % self.set.__repr__()

class Net(Gen):
    """Generate a list of IPs from a network address or a name"""
    name = "ip"
    ipaddress = re.compile(r"^(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)(/[0-3]?[0-9])?$")
    def __init__(self, net):
        self.repr=net

        tmp=net.split('/')+["32"]
        if not self.ipaddress.match(net):
            tmp[0]=socket.gethostbyname(tmp[0])
        netmask = int(tmp[1])

        def parse_digit(a,netmask):
            netmask = min(8,max(netmask,0))
            if a == "*":
                a = (0,256)
            elif a.find("-") >= 0:
                x,y = map(int,a.split("-"))
                if x > y:
                    y = x
                a = (x &  (0xffL<<netmask) , max(y, (x | (0xffL>>(8-netmask))))+1)
            else:
                a = (int(a) & (0xffL<<netmask),(int(a) | (0xffL>>(8-netmask)))+1)
            return a

        self.parsed = map(lambda x,y: parse_digit(x,y), tmp[0].split("."), map(lambda x,nm=netmask: x-nm, (8,16,24,32)))
                                                                                               
    def __iter__(self):
        for d in xrange(*self.parsed[3]):
            for c in xrange(*self.parsed[2]):
                for b in xrange(*self.parsed[1]):
                    for a in xrange(*self.parsed[0]):
                        yield "%i.%i.%i.%i" % (a,b,c,d)
    def choice(self):
        ip = []
        for v in self.parsed:
            ip.append(str(random.randint(v[0],v[1]-1)))
        return ".".join(ip) 
                          
    def __repr__(self):
        return "Net(%r)" % self.repr

class OID(Gen):
    name = "OID"
    def __init__(self, oid):
        self.oid = oid        
        self.cmpt = []
        fmt = []        
        for i in oid.split("."):
            if "-" in i:
                fmt.append("%i")
                self.cmpt.append(tuple(map(int, i.split("-"))))
            else:
                fmt.append(i)
        self.fmt = ".".join(fmt)
    def __repr__(self):
        return "OID(%r)" % self.oid
    def __iter__(self):        
        ii = [k[0] for k in self.cmpt]
        while 1:
            yield self.fmt % tuple(ii)
            i = 0
            while 1:
                if i >= len(ii):
                    raise StopIteration
                if ii[i] < self.cmpt[i][1]:
                    ii[i]+=1
                    break
                else:
                    ii[i] = self.cmpt[i][0]
                i += 1
 

#############
## Results ##
#############

class PacketList:
    res = []
    def __init__(self, res=None, name="PacketList", stats=None):
        """create a packet list from a list of packets
           res: the list of packets
           stats: a list of classes that will appear in the stats (defaults to [TCP,UDP,ICMP])"""
        if stats is None:
            stats = [ TCP,UDP,ICMP ]
        self.stats = stats
        if res is None:
            res = []
        if isinstance(res, PacketList):
            res = res.res
        self.res = res
        self.listname = name
    def _elt2pkt(self, elt):
        return elt
    def _elt2sum(self, elt):
        return elt.summary()
    def _elt2show(self, elt):
        return self._elt2sum(elt)
    def __repr__(self):
#        stats=dict.fromkeys(self.stats,0) ## needs python >= 2.3  :(
        stats = dict(map(lambda x: (x,0), self.stats))
        other = 0
        for r in self.res:
            f = 0
            for p in stats:
                if self._elt2pkt(r).haslayer(p):
                    stats[p] += 1
                    f = 1
                    break
            if not f:
                other += 1
        s = ""
        ct = conf.color_theme
        for p in stats:
            s += " %s%s%s" % (ct.packetlist_proto(p.name),
                              ct.punct(":"),
                              ct.packetlist_value(stats[p]))
        s += " %s%s%s" % (ct.packetlist_proto("Other"),
                          ct.punct(":"),
                          ct.packetlist_value(other))
        return "%s%s%s%s%s" % (ct.punct("<"),
                               ct.packetlist_name(self.listname),
                               ct.punct(":"),
                               s,
                               ct.punct(">"))
    def __getattr__(self, attr):
        return getattr(self.res, attr)
    def __getitem__(self, item):
        if isinstance(item,type) and issubclass(item,Packet):
            return self.__class__(filter(lambda x: item in self._elt2pkt(x),self.res),
                                  name="%s from %s"%(item.__name__,self.listname))
        if type(item) is slice:
            return self.__class__(self.res.__getitem__(item),
                                  name = "mod %s" % self.listname)
        return self.res.__getitem__(item)
    def __getslice__(self, *args, **kargs):
        return self.__class__(self.res.__getslice__(*args, **kargs),
                              name="mod %s"%self.listname)
    def __add__(self, other):
        return self.__class__(self.res+other.res,
                              name="%s+%s"%(self.listname,other.listname))
    def summary(self, prn=None, lfilter=None):
        """prints a summary of each packet
prn:     function to apply to each packet instead of lambda x:x.summary()
lfilter: truth function to apply to each packet to decide whether it will be displayed"""
        for r in self.res:
            if lfilter is not None:
                if not lfilter(r):
                    continue
            if prn is None:
                print self._elt2sum(r)
            else:
                print prn(r)
    def nsummary(self,prn=None, lfilter=None):
        """prints a summary of each packet with the packet's number
prn:     function to apply to each packet instead of lambda x:x.summary()
lfilter: truth function to apply to each packet to decide whether it will be displayed"""
        for i in range(len(self.res)):
            if lfilter is not None:
                if not lfilter(self.res[i]):
                    continue
            print conf.color_theme.id(i,"%04i"),
            if prn is None:
                print self._elt2sum(self.res[i])
            else:
                print prn(self.res[i])
    def display(self): # Deprecated. Use show()
        """deprecated. is show()"""
        self.show()
    def show(self, *args, **kargs):
        """Best way to display the packet list. Defaults to nsummary() method"""
        return self.nsummary(*args, **kargs)
    
    def filter(self, func):
        """Returns a packet list filtered by a truth function"""
        return self.__class__(filter(func,self.res),
                              name="filtered %s"%self.listname)
    def make_table(self, *args, **kargs):
        """Prints a table using a function that returs for each packet its head column value, head row value and displayed value
        ex: p.make_table(lambda x:(x[IP].dst, x[TCP].dport, x[TCP].sprintf("%flags%")) """
        return make_table(self.res, *args, **kargs)
    def make_lined_table(self, *args, **kargs):
        """Same as make_table, but print a table with lines"""
        return make_lined_table(self.res, *args, **kargs)
    def make_tex_table(self, *args, **kargs):
        """Same as make_table, but print a table with LaTeX syntax"""
        return make_tex_table(self.res, *args, **kargs)

    def plot(self, f, lfilter=None,**kargs):
        """Applies a function to each packet to get a value that will be plotted with GnuPlot. A gnuplot object is returned
        lfilter: a truth function that decides whether a packet must be ploted"""
        g=Gnuplot.Gnuplot()
        l = self.res
        if lfilter is not None:
            l = filter(lfilter, l)
        l = map(f,l)
        g.plot(Gnuplot.Data(l, **kargs))
        return g

    def diffplot(self, f, delay=1, lfilter=None, **kargs):
        """diffplot(f, delay=1, lfilter=None)
        Applies a function to couples (l[i],l[i+delay])"""
        g = Gnuplot.Gnuplot()
        l = self.res
        if lfilter is not None:
            l = filter(lfilter, l)
        l = map(f,l[:-delay],l[delay:])
        g.plot(Gnuplot.Data(l, **kargs))
        return g

    def multiplot(self, f, lfilter=None, **kargs):
        """Uses a function that returns a label and a value for this label, then plots all the values label by label"""
        g=Gnuplot.Gnuplot()
        l = self.res
        if lfilter is not None:
            l = filter(lfilter, l)

        d={}
        for e in l:
            k,v = f(e)
            if k in d:
                d[k].append(v)
            else:
                d[k] = [v]
        data=[]
        for k in d:
            data.append(Gnuplot.Data(d[k], title=k, **kargs))

        g.plot(*data)
        return g
        

    def rawhexdump(self):
        """Prints an hexadecimal dump of each packet in the list"""
        for p in self:
            hexdump(self._elt2pkt(p))

    def hexraw(self, lfilter=None):
        """Same as nsummary(), except that if a packet has a Raw layer, it will be hexdumped
        lfilter: a truth function that decides whether a packet must be displayed"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if lfilter is not None and not lfilter(p):
                continue
            print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                p.sprintf("%.time%"),
                                self._elt2sum(self.res[i]))
            if p.haslayer(Raw):
                hexdump(p.getlayer(Raw).load)

    def hexdump(self, lfilter=None):
        """Same as nsummary(), except that packets are also hexdumped
        lfilter: a truth function that decides whether a packet must be displayed"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if lfilter is not None and not lfilter(p):
                continue
            print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                p.sprintf("%.time%"),
                                self._elt2sum(self.res[i]))
            hexdump(p)

    def padding(self, lfilter=None):
        """Same as hexraw(), for Padding layer"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if p.haslayer(Padding):
                if lfilter is None or lfilter(p):
                    print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                        p.sprintf("%.time%"),
                                        self._elt2sum(self.res[i]))
                    hexdump(p.getlayer(Padding).load)

    def nzpadding(self, lfilter=None):
        """Same as padding() but only non null padding"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if p.haslayer(Padding):
                pad = p.getlayer(Padding).load
                if pad == pad[0]*len(pad):
                    continue
                if lfilter is None or lfilter(p):
                    print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                        p.sprintf("%.time%"),
                                        self._elt2sum(self.res[i]))
                    hexdump(p.getlayer(Padding).load)
        

    def conversations(self, getsrcdst=None,**kargs):
        """Graphes a conversations between sources and destinations and display it
        (using graphviz and imagemagick)
        getsrcdst: a function that takes an element of the list and return the source and dest
                   by defaults, return source and destination IP
        type: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
        target: filename or redirect. Defaults pipe to Imagemagick's display program
        prog: which graphviz program to use"""
        if getsrcdst is None:
            getsrcdst = lambda x:(x[IP].src, x[IP].dst)
        conv = {}
        for p in self.res:
            p = self._elt2pkt(p)
            try:
                c = getsrcdst(p)
            except:
                #XXX warning()
                continue
            conv[c] = conv.get(c,0)+1
        gr = 'digraph "conv" {\n'
        for s,d in conv:
            gr += '\t "%s" -> "%s"\n' % (s,d)
        gr += "}\n"        
        return do_graph(gr, **kargs)

    def afterglow(self, src=None, event=None, dst=None, **kargs):
        """Experimental clone attempt of http://sourceforge.net/projects/afterglow
        each datum is reduced as src -> event -> dst and the data are graphed.
        by default we have IP.src -> IP.dport -> IP.dst"""
        if src is None:
            src = lambda x: x[IP].src
        if event is None:
            event = lambda x: x[IP].dport
        if dst is None:
            dst = lambda x: x[IP].dst
        sl = {}
        el = {}
        dl = {}
        for i in self.res:
            try:
                s,e,d = src(i),event(i),dst(i)
                if s in sl:
                    n,l = sl[s]
                    n += 1
                    if e not in l:
                        l.append(e)
                    sl[s] = (n,l)
                else:
                    sl[s] = (1,[e])
                if e in el:
                    n,l = el[e]
                    n+=1
                    if d not in l:
                        l.append(d)
                    el[e] = (n,l)
                else:
                    el[e] = (1,[d])
                dl[d] = dl.get(d,0)+1
            except:
                continue

        import math
        def normalize(n):
            return 2+math.log(n)/4.0

        def minmax(x):
            m,M = min(x),max(x)
            if m == M:
                m = 0
            if M == 0:
                M = 1
            return m,M

        mins,maxs = minmax(map(lambda (x,y): x, sl.values()))
        mine,maxe = minmax(map(lambda (x,y): x, el.values()))
        mind,maxd = minmax(dl.values())
    
        gr = 'digraph "afterglow" {\n\tedge [len=2.5];\n'

        gr += "# src nodes\n"
        for s in sl:
            n,l = sl[s]; n = 1+float(n-mins)/(maxs-mins)
            gr += '"src.%s" [label = "%s", shape=box, fillcolor="#FF0000", style=filled, fixedsize=1, height=%.2f,width=%.2f];\n' % (`s`,`s`,n,n)
        gr += "# event nodes\n"
        for e in el:
            n,l = el[e]; n = n = 1+float(n-mine)/(maxe-mine)
            gr += '"evt.%s" [label = "%s", shape=circle, fillcolor="#00FFFF", style=filled, fixedsize=1, height=%.2f, width=%.2f];\n' % (`e`,`e`,n,n)
        for d in dl:
            n = dl[d]; n = n = 1+float(n-mind)/(maxd-mind)
            gr += '"dst.%s" [label = "%s", shape=triangle, fillcolor="#0000ff", style=filled, fixedsize=1, height=%.2f, width=%.2f];\n' % (`d`,`d`,n,n)

        gr += "###\n"
        for s in sl:
            n,l = sl[s]
            for e in l:
                gr += ' "src.%s" -> "evt.%s";\n' % (`s`,`e`) 
        for e in el:
            n,l = el[e]
            for d in l:
                gr += ' "evt.%s" -> "dst.%s";\n' % (`e`,`d`) 
            
        gr += "}"
        open("/tmp/aze","w").write(gr)
        return do_graph(gr, **kargs)
        

        
    def timeskew_graph(self, ip, **kargs):
        """Tries to graph the timeskew between the timestamps and real time for a given ip"""
        res = map(lambda x: self._elt2pkt(x), self.res)
        b = filter(lambda x:x.haslayer(IP) and x.getlayer(IP).src == ip and x.haslayer(TCP), res)
        c = []
        for p in b:
            opts = p.getlayer(TCP).options
            for o in opts:
                if o[0] == "Timestamp":
                    c.append((p.time,o[1][0]))
        if not c:
            warning("No timestamps found in packet list")
            return
        d = map(lambda (x,y): (x%2000,((x-c[0][0])-((y-c[0][1])/1000.0))),c)
        g = Gnuplot.Gnuplot()
        g.plot(Gnuplot.Data(d,**kargs))
        return g
        
    def _dump_document(self, **kargs):
        d = pyx.document.document()
        l = len(self.res)
        for i in range(len(self.res)):
            elt = self.res[i]
            c = self._elt2pkt(elt).canvas_dump(**kargs)
            cbb = c.bbox()
            c.text(cbb.left(),cbb.top()+1,r"\font\cmssfont=cmss12\cmssfont{Frame %i/%i}" % (i,l),[pyx.text.size.LARGE])
            if conf.verb >= 2:
                os.write(1,".")
            d.append(pyx.document.page(c, paperformat=pyx.document.paperformat.A4,
                                       margin=1*pyx.unit.t_cm,
                                       fittosize=1))
        return d
                     
                 

    def psdump(self, filename = None, **kargs):
        """Creates a multipage poscript file with a psdump of every packet
        filename: name of the file to write to. If empty, a temporary file is used and
                  conf.prog.psreader is called"""
        d = self._dump_document(**kargs)
        if filename is None:
            filename = "/tmp/scapy.psd.%i" % os.getpid()
            d.writePSfile(filename)
            os.system("%s %s.ps &" % (conf.prog.psreader,filename))
        else:
            d.writePSfile(filename)
        print
        
    def pdfdump(self, filename = None, **kargs):
        """Creates a PDF file with a psdump of every packet
        filename: name of the file to write to. If empty, a temporary file is used and
                  conf.prog.pdfreader is called"""
        d = self._dump_document(**kargs)
        if filename is None:
            filename = "/tmp/scapy.psd.%i" % os.getpid()
            d.writePDFfile(filename)
            os.system("%s %s.pdf &" % (conf.prog.pdfreader,filename))
        else:
            d.writePDFfile(filename)
        print

    def sr(self,multi=0):
        """sr([multi=1]) -> (SndRcvList, PacketList)
        Matches packets in the list and return ( (matched couples), (unmatched packets) )"""
        remain = self.res[:]
        sr = []
        i = 0
        while i < len(remain):
            s = remain[i]
            j = i
            while j < len(remain)-1:
                j += 1
                r = remain[j]
                if r.answers(s):
                    sr.append((s,r))
                    if multi:
                        remain[i]._answered=1
                        remain[j]._answered=2
                        continue
                    del(remain[j])
                    del(remain[i])
                    i -= 1
                    break
            i += 1
        if multi:
            remain = filter(lambda x:not hasattr(x,"_answered"), remain)
        return SndRcvList(sr),PacketList(remain)
        


        


class Dot11PacketList(PacketList):
    def __init__(self, res=None, name="Dot11List", stats=None):
        if stats is None:
            stats = [Dot11WEP, Dot11Beacon, UDP, ICMP, TCP]

        PacketList.__init__(self, res, name, stats)
    def toEthernet(self):
        data = map(lambda x:x.getlayer(Dot11), filter(lambda x : x.haslayer(Dot11) and x.type == 2, self.res))
        r2 = []
        for p in data:
            q = p.copy()
            q.unwep()
            r2.append(Ether()/q.payload.payload.payload) #Dot11/LLC/SNAP/IP
        return PacketList(r2,name="Ether from %s"%self.listname)
        
        

class SndRcvList(PacketList):
    def __init__(self, res=None, name="Results", stats=None):
        PacketList.__init__(self, res, name, stats)
    def _elt2pkt(self, elt):
        return elt[1]
    def _elt2sum(self, elt):
        return "%s ==> %s" % (elt[0].summary(),elt[1].summary()) 


class ARPingResult(SndRcvList):
    def __init__(self, res=None, name="ARPing", stats=None):
        PacketList.__init__(self, res, name, stats)

    def show(self):
        for s,r in self.res:
            print r.sprintf("%Ether.src% %ARP.psrc%")


class AS_resolver:
    server = None
    options = "-k" 
    def __init__(self, server=None, port=43, options=None):
        if server is not None:
            self.server = server
        self.port = port
        if options is not None:
            self.options = options
        
    def _start(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server,self.port))
        if self.options:
            self.s.send(self.options+"\n")
            self.s.recv(8192)
    def _stop(self):
        self.s.close()
        
    def _parse_whois(self, txt):
        asn,desc = None,""
        for l in txt.splitlines():
            if not asn and l.startswith("origin:"):
                asn = l[7:].strip()
            if l.startswith("descr:"):
                if desc:
                    desc += r"\n"
                desc += l[6:].strip()
            if asn is not None and desc:
                break
        return asn,desc.strip()

    def _resolve_one(self, ip):
        self.s.send("%s\n" % ip)
        x = ""
        while not ("%" in x  or "source" in x):
            x += self.s.recv(8192)
        asn, desc = self._parse_whois(x)
        return ip,asn,desc
    def resolve(self, *ips):
        self._start()
        ret = []
        for ip in ips:
            ip,asn,desc = self._resolve_one(ip)
            if asn is not None:
                ret.append((ip,asn,desc))
        self._stop()
        return ret

class AS_resolver_riswhois(AS_resolver):
    server = "riswhois.ripe.net"
    options = "-k -M -1"


class AS_resolver_radb(AS_resolver):
    server = "whois.ra.net"
    options = "-k -M"
    

class AS_resolver_cymru(AS_resolver):
    server = "whois.cymru.com"
    options = None
    def resolve(self, *ips):
        ASNlist = []
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server,self.port))
        s.send("begin\r\n"+"\r\n".join(ips)+"\r\nend\r\n")
        r = ""
        while 1:
            l = s.recv(8192)
            if l == "":
                break
            r += l
        s.close()
        for l in r.splitlines()[1:]:
            if "|" not in l:
                continue
            asn,ip,desc = map(str.strip, l.split("|"))
            if asn == "NA":
                continue
            asn = int(asn)
            ASNlist.append((ip,asn,desc))
        return ASNlist

class AS_resolver_multi(AS_resolver):
    resolvers_list = ( AS_resolver_cymru(),AS_resolver_riswhois(),AS_resolver_radb() )
    def __init__(self, *reslist):
        if reslist:
            self.resolvers_list = reslist
    def resolve(self, *ips):
        todo = ips
        ret = []
        for ASres in self.resolvers_list:
            res = ASres.resolve(*todo)
            resolved = [ ip for ip,asn,desc in res ]
            todo = [ ip for ip in todo if ip not in resolved ]
            ret += res
        return ret
    
    

class TracerouteResult(SndRcvList):
    def __init__(self, res=None, name="Traceroute", stats=None):
        PacketList.__init__(self, res, name, stats)
        self.graphdef = None
        self.graphASres = 0
        self.padding = 0
        self.hloc = None
        self.nloc = None

    def show(self):
        return self.make_table(lambda (s,r): (s.sprintf("%IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
                                              s.ttl,
                                              r.sprintf("%-15s,IP.src% {TCP:%TCP.flags%}{ICMP:%ir,ICMP.type%}")))


    def get_trace(self):
        trace = {}
        for s,r in self.res:
            if IP not in s:
                continue
            d = s[IP].dst
            if d not in trace:
                trace[d] = {}
            trace[d][s[IP].ttl] = r[IP].src, ICMP not in r
        for k in trace.values():
            m = filter(lambda x:k[x][1], k.keys())
            if not m:
                continue
            m = min(m)
            for l in k.keys():
                if l > m:
                    del(k[l])
        return trace

    def trace3D(self):
        """Give a 3D representation of the traceroute.
        right button: rotate the scene
        middle button: zoom
        left button: move the scene
        left button on a ball: toggle IP displaying
        ctrl-left button on a ball: scan ports 21,22,23,25,80 and 443 and display the result"""
        trace = self.get_trace()
        import visual

        class IPsphere(visual.sphere):
            def __init__(self, ip, **kargs):
                visual.sphere.__init__(self, **kargs)
                self.ip=ip
                self.label=None
                self.setlabel(self.ip)
            def setlabel(self, txt,visible=None):
                if self.label is not None:
                    if visible is None:
                        visible = self.label.visible
                    self.label.visible = 0
                elif visible is None:
                    visible=0
                self.label=visual.label(text=txt, pos=self.pos, space=self.radius, xoffset=10, yoffset=20, visible=visible)
            def action(self):
                self.label.visible ^= 1

        visual.scene = visual.display()
        visual.scene.exit_on_close(0)
        start = visual.box()
        rings={}
        tr3d = {}
        for i in trace:
            tr = trace[i]
            tr3d[i] = []
            ttl = tr.keys()
            for t in range(1,max(ttl)+1):
                if t not in rings:
                    rings[t] = []
                if t in tr:
                    if tr[t] not in rings[t]:
                        rings[t].append(tr[t])
                    tr3d[i].append(rings[t].index(tr[t]))
                else:
                    rings[t].append(("unk",-1))
                    tr3d[i].append(len(rings[t])-1)
        for t in rings:
            r = rings[t]
            l = len(r)
            for i in range(l):
                if r[i][1] == -1:
                    col = (0.75,0.75,0.75)
                elif r[i][1]:
                    col = visual.color.green
                else:
                    col = visual.color.blue
                
                s = IPsphere(pos=((l-1)*visual.cos(2*i*visual.pi/l),(l-1)*visual.sin(2*i*visual.pi/l),2*t),
                             ip = r[i][0],
                             color = col)
                for trlst in tr3d.values():
                    if t <= len(trlst):
                        if trlst[t-1] == i:
                            trlst[t-1] = s
        forecol = colgen(0.625, 0.4375, 0.25, 0.125)
        for trlst in tr3d.values():
            col = forecol.next()
            start = (0,0,0)
            for ip in trlst:
                visual.cylinder(pos=start,axis=ip.pos-start,color=col,radius=0.2)
                start = ip.pos
        
        movcenter=None
        while 1:
            if visual.scene.kb.keys:
                k = visual.scene.kb.getkey()
                if k == "esc":
                    break
            if visual.scene.mouse.events:
                ev = visual.scene.mouse.getevent()
                if ev.press == "left":
                    o = ev.pick
                    if o:
                        if ev.ctrl:
                            if o.ip == "unk":
                                continue
                            savcolor = o.color
                            o.color = (1,0,0)
                            a,b=sr(IP(dst=o.ip)/TCP(dport=[21,22,23,25,80,443]),timeout=2)
                            o.color = savcolor
                            if len(a) == 0:
                                txt = "%s:\nno results" % o.ip
                            else:
                                txt = "%s:\n" % o.ip
                                for s,r in a:
                                    txt += r.sprintf("{TCP:%IP.src%:%TCP.sport% %TCP.flags%}{TCPerror:%IPerror.dst%:%TCPerror.dport% %IP.src% %ir,ICMP.type%}\n")
                            o.setlabel(txt, visible=1)
                        else:
                            if hasattr(o, "action"):
                                o.action()
                elif ev.drag == "left":
                    movcenter = ev.pos
                elif ev.drop == "left":
                    movcenter = None
            if movcenter:
                visual.scene.center -= visual.scene.mouse.pos-movcenter
                movcenter = visual.scene.mouse.pos
                
                
    def world_trace(self):
        ips = {}
        rt = {}
        ports_done = {}
        for s,r in self.res:
            ips[r.src] = None
            if s.haslayer(TCP) or s.haslayer(UDP):
                trace_id = (s.src,s.dst,s.proto,s.dport)
            elif s.haslayer(ICMP):
                trace_id = (s.src,s.dst,s.proto,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            if not r.haslayer(ICMP) or r.type != 11:
                if ports_done.has_key(trace_id):
                    continue
                ports_done[trace_id] = None
            trace[s.ttl] = r.src
            rt[trace_id] = trace

        trt = {}
        for trace_id in rt:
            trace = rt[trace_id]
            loctrace = []
            for i in range(max(trace.keys())):
                ip = trace.get(i,None)
                if ip is None:
                    continue
                loc = locate_ip(ip)
                if loc is None:
                    continue
#                loctrace.append((ip,loc)) # no labels yet
                loctrace.append(loc)
            if loctrace:
                trt[trace_id] = loctrace

        tr = map(lambda x: Gnuplot.Data(x,with_="lines"), trt.values())
        g = Gnuplot.Gnuplot()
        world = Gnuplot.File(conf.gnuplot_world,with_="lines")
        g.plot(world,*tr)
        return g

    def make_graph(self,ASres=None,padding=0):
        if ASres is None:
            ASres = conf.AS_resolver
        self.graphASres = ASres
        self.graphpadding = padding
        ips = {}
        rt = {}
        ports = {}
        ports_done = {}
        for s,r in self.res:
            r = r[IP] or r[IPv6] or r
            s = s[IP] or s[IPv6] or s
            ips[r.src] = None
            if TCP in s:
                trace_id = (s.src,s.dst,6,s.dport)
            elif UDP in s:
                trace_id = (s.src,s.dst,17,s.dport)
            elif ICMP in s:
                trace_id = (s.src,s.dst,1,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            ttl = IPv6 in s and s.hlim or s.ttl
            if not (ICMP in r and r[ICMP].type == 11) and not (IPv6 in r and ICMPv6TimeExceeded in r):
                if trace_id in ports_done:
                    continue
                ports_done[trace_id] = None
                p = ports.get(r.src,[])
                if TCP in r:
                    p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))
                    trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
                elif UDP in r:
                    p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
                    trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
                elif ICMP in r:
                    p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
                    trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                else:
                    p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))
                    trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')
                ports[r.src] = p
            else:
                trace[ttl] = r.sprintf('"%r,src%"')
            rt[trace_id] = trace
    
        # Fill holes with unk%i nodes
        unknown_label = incremental_label("unk%i")
        blackholes = []
        bhip = {}
        for rtk in rt:
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                if not trace.has_key(n):
                    trace[n] = unknown_label.next()
            if not ports_done.has_key(rtk):
                if rtk[2] == 1: #ICMP
                    bh = "%s %i/icmp" % (rtk[1],rtk[3])
                elif rtk[2] == 6: #TCP
                    bh = "%s %i/tcp" % (rtk[1],rtk[3])
                elif rtk[2] == 17: #UDP                    
                    bh = '%s %i/udp' % (rtk[1],rtk[3])
                else:
                    bh = '%s %i/proto' % (rtk[1],rtk[2]) 
                ips[bh] = None
                bhip[rtk[1]] = bh
                bh = '"%s"' % bh
                trace[max(k)+1] = bh
                blackholes.append(bh)
    
        # Find AS numbers
        ASN_query_list = dict.fromkeys(map(lambda x:x.rsplit(" ",1)[0],ips)).keys()
        if ASres is None:            
            ASNlist = []
        else:
            ASNlist = ASres.resolve(*ASN_query_list)            
    
        ASNs = {}
        ASDs = {}
        for ip,asn,desc, in ASNlist:
            if asn is None:
                continue
            iplist = ASNs.get(asn,[])
            if ip in bhip:
                if ip in ports:
                    iplist.append(ip)
                iplist.append(bhip[ip])
            else:
                iplist.append(ip)
            ASNs[asn] = iplist
            ASDs[asn] = desc
    
    
        backcolorlist=colgen("60","86","ba","ff")
        forecolorlist=colgen("a0","70","40","20")
    
        s = "digraph trace {\n"
    
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
        s += "\n#ASN clustering\n"
        for asn in ASNs:
            s += '\tsubgraph cluster_%s {\n' % asn
            col = backcolorlist.next()
            s += '\t\tcolor="#%s%s%s";' % col
            s += '\t\tnode [fillcolor="#%s%s%s",style=filled];' % col
            s += '\t\tfontsize = 10;'
            s += '\t\tlabel = "%s\\n[%s]"\n' % (asn,ASDs[asn])
            for ip in ASNs[asn]:
    
                s += '\t\t"%s";\n'%ip
            s += "\t}\n"
    
    
    
    
        s += "#endpoints\n"
        for p in ports:
            s += '\t"%s" [shape=record,color=black,fillcolor=green,style=filled,label="%s|%s"];\n' % (p,p,"|".join(ports[p]))
    
        s += "\n#Blackholes\n"
        for bh in blackholes:
            s += '\t%s [shape=octagon,color=black,fillcolor=red,style=filled];\n' % bh

        if padding:
            s += "\n#Padding\n"
            pad={}
            for snd,rcv in self.res:
                if rcv.src not in ports and rcv.haslayer(Padding):
                    p = rcv.getlayer(Padding).load
                    if p != "\x00"*len(p):
                        pad[rcv.src]=None
            for rcv in pad:
                s += '\t"%s" [shape=triangle,color=black,fillcolor=red,style=filled];\n' % rcv
    
    
            
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
    
        for rtk in rt:
            s += "#---[%s\n" % `rtk`
            s += '\t\tedge [color="#%s%s%s"];\n' % forecolorlist.next()
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                s += '\t%s ->\n' % trace[n]
            s += '\t%s;\n' % trace[max(k)]
    
        s += "}\n";
        self.graphdef = s
    
    def graph(self, ASres=None, padding=0, **kargs):
        """x.graph(ASres=conf.AS_resolver, other args):
        ASres=None          : no AS resolver => no clustering
        ASres=AS_resolver() : default whois AS resolver (riswhois.ripe.net)
        ASres=AS_resolver_cymru(): use whois.cymru.com whois database
        ASres=AS_resolver(server="whois.ra.net")
        type: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
        target: filename or redirect. Defaults pipe to Imagemagick's display program
        prog: which graphviz program to use"""
        if ASres is None:
            ASres = conf.AS_resolver
        if (self.graphdef is None or
            self.graphASres != ASres or
            self.graphpadding != padding):
            self.make_graph(ASres,padding)

        return do_graph(self.graphdef, **kargs)


        
    
############
## Fields ##
############

class Field:
    """For more informations on how this work, please refer to
       http://www.secdev.org/projects/scapy/files/scapydoc.pdf
       chapter ``Adding a New Field''"""
    islist=0
    holds_packets=0
    def __init__(self, name, default, fmt="H"):
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.default = self.any2i(None,default)
        self.sz = struct.calcsize(self.fmt)
        self.owners = []

    def register_owner(self, cls):
        self.owners.append(cls)

    def i2len(self, pkt, x):
        """Convert internal value to a length usable by a FieldLenField"""
        return self.sz
    def i2count(self, pkt, x):
        """Convert internal value to a number of elements usable by a FieldLenField.
        Always 1 except for list fields"""
        return 1
    def h2i(self, pkt, x):
        """Convert human value to internal value"""
        return x
    def i2h(self, pkt, x):
        """Convert internal value to human value"""
        return x
    def m2i(self, pkt, x):
        """Convert machine value to internal value"""
        return x
    def i2m(self, pkt, x):
        """Convert internal value to machine value"""
        if x is None:
            x = 0
        return x
    def any2i(self, pkt, x):
        """Try to understand the most input values possible and make an internal value from them"""
        return self.h2i(pkt, x)
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if x is None:
            x = 0
        return repr(self.i2h(pkt,x))
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        return s+struct.pack(self.fmt, self.i2m(pkt,val))
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:self.sz])[0])
    def do_copy(self, x):
        if hasattr(x, "copy"):
            return x.copy()
        if type(x) is list:
            x = x[:]
            for i in xrange(len(x)):
                if isinstance(x[i], Packet):
                    x[i] = x[i].copy()
        return x
    def __repr__(self):
        return "<Field (%s).%s>" % (",".join(x.__name__ for x in self.owners),self.name)
    def copy(self):
        return copy.deepcopy(self)
    def randval(self):
        """Return a volatile object whose value is both random and suitable for this field"""
        fmtt = self.fmt[-1]
        if fmtt in "BHIQ":
            return {"B":RandByte,"H":RandShort,"I":RandInt, "Q":RandLong}[fmtt]()
        elif fmtt == "s":
            if self.fmt[0] in "0123456789":
                l = int(self.fmt[:-1])
            else:
                l = int(self.fmt[1:-1])
            return RandBin(l)
        else:
            warning("no random class for [%s] (fmt=%s)." % (self.name, self.fmt))
            



class Emph:
    fld = ""
    def __init__(self, fld):
        self.fld = fld
    def __getattr__(self, attr):
        return getattr(self.fld,attr)
    def __hash__(self):
        return hash(self.fld)
    def __eq__(self, other):
        return self.fld == other
    

class ActionField:
    _fld = None
    def __init__(self, fld, action_method, **kargs):
        self._fld = fld
        self._action_method = action_method
        self._privdata = kargs
    def any2i(self, pkt, val):
        getattr(pkt, self._action_method)(val, self._fld, **self._privdata)
        return getattr(self._fld, "any2i")(pkt, val)
    def __getattr__(self, attr):
        return getattr(self._fld,attr)


class ConditionalField:
    fld = None
    def __init__(self, fld, cond):
        self.fld = fld
        self.cond = cond
    def _evalcond(self,pkt):
        return self.cond(pkt)
        
    def getfield(self, pkt, s):
        if self._evalcond(pkt):
            return self.fld.getfield(pkt,s)
        else:
            return s,None
        
    def addfield(self, pkt, s, val):
        if self._evalcond(pkt):
            return self.fld.addfield(pkt,s,val)
        else:
            return s
    def __getattr__(self, attr):
        return getattr(self.fld,attr)
        

class PadField:
    """Add bytes after the proxified field so that it ends at the specified
       alignment from its begining"""
    _fld = None
    def __init__(self, fld, align, padwith=None):
        self._fld = fld
        self._align = align
        self._padwith = padwith or ""

    def addfield(self, pkt, s, val):
        sval = self._fld.addfield(pkt, "", val)
        return s+sval+struct.pack("%is" % (-len(sval)%self._align), self._padwith)
    
    def __getattr__(self, attr):
        return getattr(self._fld,attr)
        

class MACField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")
    def i2m(self, pkt, x):
        if x is None:
            return "\0\0\0\0\0\0"
        return mac2str(x)
    def m2i(self, pkt, x):
        return str2mac(x)
    def any2i(self, pkt, x):
        if type(x) is str and len(x) is 6:
            x = self.m2i(pkt, x)
        return x
    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        if self in conf.resolve:
            x = conf.manufdb._resolve_MAC(x)
        return x
    def randval(self):
        return RandMAC()

class DestMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            dstip = None
            if isinstance(pkt.payload, IPv6):
                dstip = pkt.payload.dst            
            elif isinstance(pkt.payload, IP):
                dstip = pkt.payload.dst
            elif isinstance(pkt.payload, ARP):
                dstip = pkt.payload.pdst
            if isinstance(dstip, Gen):
                dstip = dstip.__iter__().next()
            if dstip is not None:
                if isinstance(pkt.payload, IPv6):
                    x = getmacbyip6(dstip, chainCC=1)
                else:    
                    x = getmacbyip(dstip, chainCC=1)
            if x is None:
                x = "ff:ff:ff:ff:ff:ff"
                warning("Mac address to reach %s not found\n"%dstip)
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))
        
class SourceMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            dstip = None
            if isinstance(pkt.payload, IPv6):
                dstip = pkt.payload.dst
            elif isinstance(pkt.payload, IP):
                dstip = pkt.payload.dst
            elif isinstance(pkt.payload, ARP):
                dstip = pkt.payload.pdst
            if isinstance(dstip, Gen):
                dstip = dstip.__iter__().next()
            if dstip is not None:
                if isinstance(pkt.payload, IPv6):
                    iff,a,nh = conf.route6.route(dstip)
                else:
                    iff,a,gw = conf.route.route(dstip)
                try:
                    x = get_if_hwaddr(iff)
                except:
                    pass
                if x is None:
                    x = "00:00:00:00:00:00"
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))
        
class ARPSourceMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            dstip = pkt.pdst
            if isinstance(dstip, Gen):
                dstip = dstip.__iter__().next()
            if dstip is not None:
                iff,a,gw = conf.route.route(dstip)
                try:
                    x = get_if_hwaddr(iff)
                except:
                    pass
                if x is None:
                    x = "00:00:00:00:00:00"
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))

class Dot11AddrMACField(MACField):
    def is_applicable(self, pkt):
        return 1
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return MACField.addfield(self, pkt, s, val)
        else:
            return s        
    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return MACField.getfield(self, pkt, s)
        else:
            return s,None

class Dot11Addr2MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type == 1:
            return pkt.subtype in [ 0xb, 0xa, 0xe, 0xf] # RTS, PS-Poll, CF-End, CF-End+CF-Ack
        return 1

class Dot11Addr3MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type in [0,2]:
            return 1
        return 0

class Dot11Addr4MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type == 2:
            if pkt.FCfield & 0x3 == 0x3: # To-DS and From-DS are set
                return 1
        return 0
    
class IPField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "4s")
    def h2i(self, pkt, x):
        if type(x) is str:
            try:
                inet_aton(x)
            except socket.error:
                x = Net(x)
        elif type(x) is list:
            x = [self.h2i(pkt, n) for n in x] 
        return x
    def resolve(self, x):
        if self in conf.resolve:
            try:
                ret = socket.gethostbyaddr(x)[0]
            except:
                pass
            else:
                if ret:
                    return ret
        return x
    def i2m(self, pkt, x):
        return inet_aton(x)
    def m2i(self, pkt, x):
        return inet_ntoa(x)
    def any2i(self, pkt, x):
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        return self.resolve(self.i2h(pkt, x))
    def randval(self):
        return RandIP()

class SourceIPField(IPField):
    def __init__(self, name, dstname):
        IPField.__init__(self, name, None)
        self.dstname = dstname
    def i2m(self, pkt, x):
        if x is None:
            iff,x,gw = conf.route.route(getattr(pkt,self.dstname))
        return IPField.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            dst=getattr(pkt,self.dstname)
            if isinstance(dst,Gen):
                r = map(conf.route.route, dst)
                r.sort()
                if r[0] == r[-1]:
                    x=r[0][1]
                else:
                    warning("More than one possible route for %s"%repr(dst))
                    return None
            else:
                iff,x,gw = conf.route.route(dst)
        return IPField.i2h(self, pkt, x)

    


class ByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")
        
class XByteField(ByteField):
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return lhex(self.i2h(pkt, x))

class X3BytesField(XByteField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "!I")
    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, self.i2m(pkt,val))[1:4]
    def getfield(self, pkt, s):
        return  s[3:], self.m2i(pkt, struct.unpack(self.fmt, "\x00"+s[:3])[0])


class ShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "H")

class LEShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<H")

class XShortField(ShortField):
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return lhex(self.i2h(pkt, x))


class IntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "I")

class SignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "i")
    def randval(self):
        return RandSInt()

class LEIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<I")

class LESignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<i")
    def randval(self):
        return RandSInt()

class XIntField(IntField):
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return lhex(self.i2h(pkt, x))


class LongField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "Q")

class XLongField(LongField):
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return lhex(self.i2h(pkt, x))

def FIELD_LENGTH_MANAGEMENT_DEPRECATION(x):
    try:
        for tb in traceback.extract_stack()+[("??",-1,None,"")]:
            f,l,_,line = tb
            if line.startswith("fields_desc"):
                break
    except:
        f,l="??",-1
    log_loading.warning("Deprecated use of %s (%s l. %i). See http://trac.secdev.org/scapy/wiki/LengthFields" % (x,f,l))

class StrField(Field):
    def __init__(self, name, default, fmt="H", remain=0, shift=0):
        Field.__init__(self,name,default,fmt)
        self.remain = remain        
        self.shift = shift
        if shift != 0:
            FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
    def i2len(self, pkt, i):
        return len(i)+self.shift
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        return x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        if self.remain == 0:
            return "",self.m2i(pkt, s)
        else:
            return s[-self.remain:],self.m2i(pkt, s[:-self.remain])
    def randval(self):
        return RandBin(RandNum(0,1200))

class PacketField(StrField):
    holds_packets=1
    def __init__(self, name, default, cls, remain=0, shift=0):
        StrField.__init__(self, name, default, remain=remain, shift=shift)
        self.cls = cls
    def i2m(self, pkt, i):
        return str(i)
    def m2i(self, pkt, m):
        return self.cls(m)
    def getfield(self, pkt, s):
        i = self.m2i(pkt, s)
        remain = ""
        if i.haslayer(Padding):
            r = i.getlayer(Padding)
            del(r.underlayer.payload)
            remain = r.load
        return remain,i
    
class PacketLenField(PacketField):
    holds_packets=1
    def __init__(self, name, default, cls, fld=None, length_from=None, shift=0):
        PacketField.__init__(self, name, default, cls, shift=shift)
        self.length_from = length_from
        if fld is not None or shift != 0:
            FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
            self.count_from = lambda pkt,fld=fld,shift=shift: getattr(pkt,fld)-shift
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        i = self.m2i(pkt, s[:l])
        return s[l:],i


class PacketListField(PacketField):
    islist = 1
    holds_packets=1
    def __init__(self, name, default, cls, fld=None, count_from=None, length_from=None, shift=0):
        if default is None:
            default = []  # Create a new list for each instance
        PacketField.__init__(self, name, default, cls, shift=shift)
        self.count_from = count_from
        self.length_from = length_from

        if fld is not None or shift != 0:
            FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
        if fld is not None:
            self.count_from = lambda pkt,fld=fld,shift=shift: getattr(pkt,fld)-shift

    def any2i(self, pkt, x):
        if type(x) is not list:
            return [x]
        else:
            return x
    def i2count(self, pkt, val):
        if type(val) is list:
            return len(val)
        return 1
    def i2len(self, pkt, val):
        return sum( len(p) for p in val )
    def do_copy(self, x):
        return map(lambda p:p.copy(), x)
    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)
            
        lst = []
        ret = ""
        remain = s
        if l is not None:
            remain,ret = s[:l],s[l:]
        while remain:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            p = self.m2i(pkt,remain)
            if Padding in p:
                pad = p[Padding]
                remain = pad.load
                del(pad.underlayer.payload)
            else:
                remain = ""
            lst.append(p)
        return remain+ret,lst
    def addfield(self, pkt, s, val):
        return s+"".join(map(str, val))


class StrFixedLenField(StrField):
    def __init__(self, name, default, length=None, length_from=None, shift=0):
        StrField.__init__(self, name, default, shift=shift)
        self.length_from  = length_from
        if length is not None:
            self.length_from = lambda pkt,length=length: length
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt,s[:l])
    def addfield(self, pkt, s, val):
        l = self.length_from(pkt)
        return s+struct.pack("%is"%l,self.i2m(pkt, val))
    def randval(self):
        try:
            l = self.length_from(None)
        except:
            l = RandNum(0,200)
        return RandBin(l)

class NetBIOSNameField(StrFixedLenField):
    def __init__(self, name, default, length=31, shift=0):
        StrFixedLenField.__init__(self, name, default, length, shift=shift)
    def i2m(self, pkt, x):
        l = self.length_from(pkt)/2
        if x is None:
            x = ""
        x += " "*(l)
        x = x[:l]
        x = "".join(map(lambda x: chr(0x41+(ord(x)>>4))+chr(0x41+(ord(x)&0xf)), x))
        x = " "+x
        return x
    def m2i(self, pkt, x):
        x = x.strip("\x00").strip(" ")
        return "".join(map(lambda x,y: chr((((ord(x)-1)&0xf)<<4)+((ord(y)-1)&0xf)), x[::2],x[1::2]))

class StrLenField(StrField):
    def __init__(self, name, default, fld=None, length_from=None, shift=0):
        StrField.__init__(self, name, default, shift=shift)
        self.length_from = length_from
        if fld is not None or shift != 0:
            FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
            self.length_from = lambda pkt,fld=fld,shift=shift: getattr(pkt,fld)-shift
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt,s[:l])

class FieldListField(Field):
    islist=1
    def __init__(self, name, default, field, fld=None, shift=0, length_from=None, count_from=None):
        if default is None:
            default = []  # Create a new list for each instance
        Field.__init__(self, name, default)
        self.count_from = count_from
        self.length_from = length_from
        self.field = field
        if fld is not None or shift != 0:
            FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
            self.count_from = lambda pkt,fld=fld,shift=shift: getattr(pkt,fld)-shift
            
            
    def i2count(self, pkt, val):
        if type(val) is list:
            return len(val)
        return 1
    def i2len(self, pkt, val):
        return sum( self.field.i2len(pkt,v) for v in val )
    
    def i2m(self, pkt, val):
        if val is None:
            val = []
        return val
    def any2i(self, pkt, x):
        if type(x) is not list:
            return [x]
        else:
            return x
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        for v in val:
            s = self.field.addfield(pkt, s, v)
        return s
    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)

        val = []
        ret=""
        if l is not None:
            s,ret = s[:l],s[l:]
            
        while s:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            s,v = self.field.getfield(pkt, s)
            val.append(v)
        return s+ret, val

class FieldLenField(Field):
    def __init__(self, name, default,  length_of=None, fmt = "H", count_of=None, adjust=lambda pkt,x:x, fld=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        self.count_of=count_of
        self.adjust=adjust
        if fld is not None:
            FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
            self.length_of = fld
    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld,fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld,fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust(pkt,f)
        return x

# see http://www.iana.org/assignments/ipsec-registry for details
ISAKMPAttributeTypes= { "Encryption":    (1, { "DES-CBC"  : 1,
                                                "IDEA-CBC" : 2,
                                                "Blowfish-CBC" : 3,
                                                "RC5-R16-B64-CBC" : 4,
                                                "3DES-CBC" : 5, 
                                                "CAST-CBC" : 6, 
                                                "AES-CBC" : 7, 
                                                "CAMELLIA-CBC" : 8, }, 0),
                         "Hash":          (2, { "MD5": 1,
                                                "SHA": 2,
                                                "Tiger": 3,
                                                "SHA2-256": 4,
                                                "SHA2-384": 5,
                                                "SHA2-512": 6,}, 0),
                         "Authentication":(3, { "PSK": 1, 
                                                "DSS": 2,
                                                "RSA Sig": 3,
                                                "RSA Encryption": 4,
                                                "RSA Encryption Revised": 5,
                                                "ElGamal Encryption": 6,
                                                "ElGamal Encryption Revised": 7,
                                                "ECDSA Sig": 8,
                                                "HybridInitRSA": 64221,
                                                "HybridRespRSA": 64222,
                                                "HybridInitDSS": 64223,
                                                "HybridRespDSS": 64224,
                                                "XAUTHInitPreShared": 65001,
                                                "XAUTHRespPreShared": 65002,
                                                "XAUTHInitDSS": 65003,
                                                "XAUTHRespDSS": 65004,
                                                "XAUTHInitRSA": 65005,
                                                "XAUTHRespRSA": 65006,
                                                "XAUTHInitRSAEncryption": 65007,
                                                "XAUTHRespRSAEncryption": 65008,
                                                "XAUTHInitRSARevisedEncryption": 65009,
                                                "XAUTHRespRSARevisedEncryptio": 65010, }, 0),
                         "GroupDesc":     (4, { "768MODPgr"  : 1,
                                                "1024MODPgr" : 2, 
                                                "EC2Ngr155"  : 3,
                                                "EC2Ngr185"  : 4,
                                                "1536MODPgr" : 5, 
                                                "2048MODPgr" : 14, 
                                                "3072MODPgr" : 15, 
                                                "4096MODPgr" : 16, 
                                                "6144MODPgr" : 17, 
                                                "8192MODPgr" : 18, }, 0),
                         "GroupType":      (5,  {"MODP":       1,
                                                 "ECP":        2,
                                                 "EC2N":       3}, 0),
                         "GroupPrime":     (6,  {}, 1),
                         "GroupGenerator1":(7,  {}, 1),
                         "GroupGenerator2":(8,  {}, 1),
                         "GroupCurveA":    (9,  {}, 1),
                         "GroupCurveB":    (10, {}, 1),
                         "LifeType":       (11, {"Seconds":     1,
                                                 "Kilobytes":   2,  }, 0),
                         "LifeDuration":   (12, {}, 1),
                         "PRF":            (13, {}, 0),
                         "KeyLength":      (14, {}, 0),
                         "FieldSize":      (15, {}, 0),
                         "GroupOrder":     (16, {}, 1),
                         }

# the name 'ISAKMPTransformTypes' is actually a misnomer (since the table 
# holds info for all ISAKMP Attribute types, not just transforms, but we'll 
# keep it for backwards compatibility... for now at least
ISAKMPTransformTypes = ISAKMPAttributeTypes

ISAKMPTransformNum = {}
for n in ISAKMPTransformTypes:
    val = ISAKMPTransformTypes[n]
    tmp = {}
    for e in val[1]:
        tmp[val[1][e]] = e
    ISAKMPTransformNum[val[0]] = (n,tmp, val[2])
del(n)
del(e)
del(tmp)
del(val)


class ISAKMPTransformSetField(StrLenField):
    islist=1
    def type2num(self, (typ,val)):
        type_val,enc_dict,tlv = ISAKMPTransformTypes.get(typ, (typ,{},0))
        val = enc_dict.get(val, val)
        s = ""
        if (val & ~0xffff):
            if not tlv:
                warning("%r should not be TLV but is too big => using TLV encoding" % typ)
            n = 0
            while val:
                s = chr(val&0xff)+s
                val >>= 8
                n += 1
            val = n
        else:
            type_val |= 0x8000
        return struct.pack("!HH",type_val, val)+s
    def num2type(self, typ, enc):
        val = ISAKMPTransformNum.get(typ,(typ,{}))
        enc = val[1].get(enc,enc)
        return (val[0],enc)
    def i2m(self, pkt, i):
        if i is None:
            return ""
        i = map(self.type2num, i)
        return "".join(i)
    def m2i(self, pkt, m):
        # I try to ensure that we don't read off the end of our packet based
        # on bad length fields we're provided in the packet. There are still
        # conditions where struct.unpack() may not get enough packet data, but
        # worst case that should result in broken attributes (which would
        # be expected). (wam)
        lst = []
        while len(m) >= 4:
            trans_type, = struct.unpack("!H", m[:2])
            is_tlv = not (trans_type & 0x8000)
            if is_tlv:
                # We should probably check to make sure the attribute type we
                # are looking at is allowed to have a TLV format and issue a 
                # warning if we're given an TLV on a basic attribute.
                value_len, = struct.unpack("!H", m[2:4])
                if value_len+4 > len(m):
                    warning("Bad length for ISAKMP tranform type=%#6x" % trans_type)
                value = m[4:4+value_len]
                value = reduce(lambda x,y: (x<<8L)|y, struct.unpack("!%s" % ("B"*len(value),), value),0)
            else:
                trans_type &= 0x7fff
                value_len=0
                value, = struct.unpack("!H", m[2:4])
            m=m[4+value_len:]
            lst.append(self.num2type(trans_type, value))
        if len(m) > 0:
            warning("Extra bytes after ISAKMP transform dissection [%r]" % m)
        return lst

class StrNullField(StrField):
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)+"\x00"
    def getfield(self, pkt, s):
        l = s.find("\x00")
        if l < 0:
            #XXX \x00 not found
            return "",s
        return s[l+1:],self.m2i(pkt, s[:l])
    def randval(self):
        return RandTermString(RandNum(0,1200),"\x00")

class StrStopField(StrField):
    def __init__(self, name, default, stop, additionnal=0):
        Field.__init__(self, name, default)
        self.stop=stop
        self.additionnal=additionnal
    def getfield(self, pkt, s):
        l = s.find(self.stop)
        if l < 0:
            return "",s
#            raise Scapy_Exception,"StrStopField: stop value [%s] not found" %stop
        l += len(self.stop)+self.additionnal
        return s[l:],s[:l]
    def randval(self):
        return RandTermString(RandNum(0,1200),self.stop)

class LenField(Field):
    def i2m(self, pkt, x):
        if x is None:
            x = len(pkt.payload)
        return x

class BCDFloatField(Field):
    def i2m(self, pkt, x):
        return int(256*x)
    def m2i(self, pkt, x):
        return x/256.0

class BitField(Field):
    def __init__(self, name, default, size):
        Field.__init__(self, name, default)
        self.rev = size < 0 
        self.size = abs(size)
    def reverse(self, val):
        if self.size == 16:
            val = socket.ntohs(val)
        elif self.size == 32:
            val = socket.ntohl(val)
        return val
        
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        if type(s) is tuple:
            s,bitsdone,v = s
        else:
            bitsdone = 0
            v = 0
        if self.rev:
            val = self.reverse(val)
        v <<= self.size
        v |= val & ((1L<<self.size) - 1)
        bitsdone += self.size
        while bitsdone >= 8:
            bitsdone -= 8
            s = s+struct.pack("!B", v >> bitsdone)
            v &= (1L<<bitsdone)-1
        if bitsdone:
            return s,bitsdone,v
        else:
            return s
    def getfield(self, pkt, s):
        if type(s) is tuple:
            s,bn = s
        else:
            bn = 0
        # we don't want to process all the string
        nb_bytes = (self.size+bn-1)/8 + 1
        w = s[:nb_bytes]

        # split the substring byte by byte
        bytes = struct.unpack('!%dB' % nb_bytes , w)

        b = 0L
        for c in range(nb_bytes):
            b |= long(bytes[c]) << (nb_bytes-c-1)*8

        # get rid of high order bits
        b &= (1L << (nb_bytes*8-bn)) - 1

        # remove low order bits
        b = b >> (nb_bytes*8 - self.size - bn)

        if self.rev:
            b = self.reverse(b)

        bn += self.size
        s = s[bn/8:]
        bn = bn%8
        b = self.m2i(pkt, b)
        if bn:
            return (s,bn),b
        else:
            return s,b
    def randval(self):
        return RandNum(0,2**self.size-1)


class BitFieldLenField(BitField):
    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt,x:x):
        BitField.__init__(self, name, default, size)
        self.length_of=length_of
        self.count_of=count_of
        self.adjust=adjust
    def i2m(self, pkt, x):
        return FieldLenField.i2m.im_func(self, pkt, x)


class XBitField(BitField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt,x))


class EnumField(Field):
    def __init__(self, name, default, enum, fmt = "H"):
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if filter(lambda x: type(x) is str, keys):
            i2s,s2i = s2i,i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
        Field.__init__(self, name, default, fmt)
    def any2i_one(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x,VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return repr(x)
    
    def any2i(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.any2i_one(pkt,z), x)
        else:
            return self.any2i_one(pkt,x)        
    def i2repr(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.i2repr_one(pkt,z), x)
        else:
            return self.i2repr_one(pkt,x)

class CharEnumField(EnumField):
    def __init__(self, name, default, enum, fmt = "1s"):
        EnumField.__init__(self, name, default, enum, fmt)
        k = self.i2s.keys()
        if k and len(k[0]) != 1:
            self.i2s,self.s2i = self.s2i,self.i2s
    def any2i_one(self, pkt, x):
        if len(x) != 1:
            x = self.s2i[x]
        return x

class BitEnumField(BitField,EnumField):
    def __init__(self, name, default, size, enum):
        EnumField.__init__(self, name, default, enum)
        self.rev = size < 0
        self.size = abs(size)
    def any2i(self, pkt, x):
        return EnumField.any2i(self, pkt, x)
    def i2repr(self, pkt, x):
        return EnumField.i2repr(self, pkt, x)

class ShortEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "H")

class LEShortEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "<H")

class ByteEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "B")

class IntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "I")

class SignedIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "i")
    def randval(self):
        return RandSInt()

class LEIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "<I")

class XShortEnumField(ShortEnumField):
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x,VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return lhex(x)

# Little endian long field
class LELongField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")

# Little endian fixed length field
class LEFieldLenField(FieldLenField):
    def __init__(self, name, default,  length_of=None, fmt = "<H", count_of=None, adjust=lambda pkt,x:x, fld=None):
        FieldLenField.__init__(self, name, default, length_of=length_of, fmt=fmt, fld=fld, adjust=adjust)


class FlagsField(BitField):
    def __init__(self, name, default, size, names):
        BitField.__init__(self, name, default, size)
        self.multi = type(names) is list
        if self.multi:
            self.names = map(lambda x:[x], names)
        else:
            self.names = names
    def any2i(self, pkt, x):
        if type(x) is str:
            if self.multi:
                x = map(lambda y:[y], x.split("+"))
            y = 0
            for i in x:
                y |= 1 << self.names.index(i)
            x = y
        return x
    def i2repr(self, pkt, x):
        if type(x) is list or type(x) is tuple:
            return repr(x)
        if self.multi:
            r = []
        else:
            r = ""
        i=0
        while x:
            if x & 1:
                r += self.names[i]
            i += 1
            x >>= 1
        if self.multi:
            r = "+".join(r)
        return r

            



class IPoptionsField(StrField):
    def i2m(self, pkt, x):
        return x+"\x00"*(3-((len(x)+3)%4))
    def getfield(self, pkt, s):
        opsz = (pkt.ihl-5)*4
        if opsz < 0:
            warning("bad ihl (%i). Assuming ihl=5"%pkt.ihl)
            opsz = 0
        return s[opsz:],s[:opsz]
    def randval(self):
        return RandBin(RandNum(0,39))


TCPOptions = (
              { 0 : ("EOL",None),
                1 : ("NOP",None),
                2 : ("MSS","!H"),
                3 : ("WScale","!B"),
                4 : ("SAckOK",None),
                5 : ("SAck","!"),
                8 : ("Timestamp","!II"),
                14 : ("AltChkSum","!BH"),
                15 : ("AltChkSumOpt",None)
                },
              { "EOL":0,
                "NOP":1,
                "MSS":2,
                "WScale":3,
                "SAckOK":4,
                "SAck":5,
                "Timestamp":8,
                "AltChkSum":14,
                "AltChkSumOpt":15,
                } )

class TCPOptionsField(StrField):
    islist=1
    def getfield(self, pkt, s):
        opsz = (pkt.dataofs-5)*4
        if opsz < 0:
            warning("bad dataofs (%i). Assuming dataofs=5"%pkt.dataofs)
            opsz = 0
        return s[opsz:],self.m2i(pkt,s[:opsz])
    def m2i(self, pkt, x):
        opt = []
        while x:
            onum = ord(x[0])
            if onum == 0:
                opt.append(("EOL",None))
                x=x[1:]
                break
            if onum == 1:
                opt.append(("NOP",None))
                x=x[1:]
                continue
            olen = ord(x[1])
            if olen < 2:
                warning("Malformed TCP option (announced length is %i)" % olen)
                olen = 2
            oval = x[2:olen]
            if TCPOptions[0].has_key(onum):
                oname, ofmt = TCPOptions[0][onum]
                if onum == 5: #SAck
                    ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                opt.append((oname, oval))
            else:
                opt.append((onum, oval))
            x = x[olen:]
        return opt
    
    def i2m(self, pkt, x):
        opt = ""
        for oname,oval in x:
            if type(oname) is str:
                if oname == "NOP":
                    opt += "\x01"
                    continue
                elif oname == "EOL":
                    opt += "\x00"
                    continue
                elif TCPOptions[1].has_key(oname):
                    onum = TCPOptions[1][oname]
                    ofmt = TCPOptions[0][onum][1]
                    if onum == 5: #SAck
                        ofmt += "%iI" % len(oval)
                    if ofmt is not None and (type(oval) is not str or "s" in ofmt):
                        if type(oval) is not tuple:
                            oval = (oval,)
                        oval = struct.pack(ofmt, *oval)
                else:
                    warning("option [%s] unknown. Skipped."%oname)
                    continue
            else:
                onum = oname
                if type(oval) is not str:
                    warning("option [%i] is not string."%onum)
                    continue
            opt += chr(onum)+chr(2+len(oval))+oval
        return opt+"\x00"*(3-((len(opt)+3)%4))
    def randval(self):
        return [] # XXX
    

class DNSStrField(StrField):
    def i2m(self, pkt, x):
        x = [k[:63] for k in x.split(".")] # Truncate chunks that cannont be encoded (more than 63 bytes..)
        x = map(lambda y: chr(len(y))+y, x)
        x = "".join(x)
        if x[-1] != "\x00":
            x += "\x00"
        return x
    def getfield(self, pkt, s):
        n = ""
        while 1:
            l = ord(s[0])
            s = s[1:]
            if not l:
                break
            if l & 0xc0:
                raise Scapy_Exception("DNS message can't be compressed at this point!")
            else:
                n += s[:l]+"."
                s = s[l:]
        return s, n


class DNSRRCountField(ShortField):
    holds_packets=1
    def __init__(self, name, default, rr):
        ShortField.__init__(self, name, default)
        self.rr = rr
    def _countRR(self, pkt):
        x = getattr(pkt,self.rr)
        i = 0
        while isinstance(x, DNSRR) or isinstance(x, DNSQR):
            x = x.payload
            i += 1
        return i
        
    def i2m(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x
    def i2h(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x
    

def DNSgetstr(s,p):
    name = ""
    q = 0
    jpath = [p]
    while 1:
        if p >= len(s):
            warning("DNS RR prematured end (ofs=%i, len=%i)"%(p,len(s)))
            break
        l = ord(s[p])
        p += 1
        if l & 0xc0:
            if not q:
                q = p+1
            if p >= len(s):
                warning("DNS incomplete jump token at (ofs=%i)" % p)
                break
            p = ((l & 0x3f) << 8) + ord(s[p]) - 12
            if p in jpath:
                warning("DNS decompression loop detected")
                break
            jpath.append(p)
            continue
        elif l > 0:
            name += s[p:p+l]+"."
            p += l
            continue
        break
    if q:
        p = q
    return name,p
        

class DNSRRField(StrField):
    holds_packets=1
    def __init__(self, name, countfld, passon=1):
        StrField.__init__(self, name, None)
        self.countfld = countfld
        self.passon = passon
    def i2m(self, pkt, x):
        if x is None:
            return ""
        return str(x)
    def decodeRR(self, name, s, p):
        ret = s[p:p+10]
        type,cls,ttl,rdlen = struct.unpack("!HHIH", ret)
        p += 10
        rr = DNSRR("\x00"+ret+s[p:p+rdlen])
        if rr.type in [2, 3, 4, 5]:
            rr.rdata = DNSgetstr(s,p)[0]
        del(rr.rdlen)
        
        p += rdlen
        
        rr.rrname = name
        return rr,p
    def getfield(self, pkt, s):
        if type(s) is tuple :
            s,p = s
        else:
            p = 0
        ret = None
        c = getattr(pkt, self.countfld)
        if c > len(s):
            warning("wrong value: DNS.%s=%i" % (self.countfld,c))
            return s,""
        while c:
            c -= 1
            name,p = DNSgetstr(s,p)
            rr,p = self.decodeRR(name, s, p)
            if ret is None:
                ret = rr
            else:
                ret.add_payload(rr)
        if self.passon:
            return (s,p),ret
        else:
            return s[p:],ret
            
            
class DNSQRField(DNSRRField):
    holds_packets=1
    def decodeRR(self, name, s, p):
        ret = s[p:p+4]
        p += 4
        rr = DNSQR("\x00"+ret)
        rr.qname = name
        return rr,p
        
        

class RDataField(StrLenField):
    def m2i(self, pkt, s):
        family = None
        if pkt.type == 1:
            family = socket.AF_INET
        elif pkt.type == 28:
            family = socket.AF_INET6
        elif pkt.type == 12:
            s = DNSgetstr(s, 0)[0]
        if family is not None:    
            s = inet_ntop(family, s)
        return s
    def i2m(self, pkt, s):
        if pkt.type == 1:
            if s:
                s = inet_aton(s)
        elif pkt.type == 28:
            if s:
                s = inet_pton(socket.AF_INET6, s)
        elif pkt.type in [2,3,4,5]:
            s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
            if ord(s[-1]):
                s += "\x00"
        return s

class RDLenField(Field):
    def __init__(self, name):
        Field.__init__(self, name, None, "H")
    def i2m(self, pkt, x):
        if x is None:
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    def i2h(self, pkt, x):
        if x is None:
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    
# seconds between 01-01-1900 and 01-01-1970
ntp_basetime = 2208988800

class TimeStampField(BitField):
    def __init__(self, name, default, size):
        BitField.__init__(self, name, default, size)
        self.size  = size
    def getfield(self, pkt, s):
        s,timestamp = BitField.getfield(self, pkt, s)

        if timestamp:
            # timestamp is a 64 bits field :
            #  + first 32 bits : number of seconds since 1900
            #  + last 32 bits  : fraction part
            timestamp >>= 32
            timestamp -= ntp_basetime
            
            from time import gmtime, strftime
            b = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(timestamp))
        else:
            b = 'None'
        
        return s, b
    def addfield(self, pkt, s, val):
        t = -1
        if type(val) is str:
            from time import strptime, mktime
            t = int(mktime(strptime(val))) + ntp_basetime + 3600
        else:
            if val == -1:
                from time import time
                t = int(time()) + ntp_basetime
            else:
                t = val
        t <<= 32
        return BitField.addfield(self,pkt,s, t)

class FloatField(BitField):
    def getfield(self, pkt, s):
        s,b = BitField.getfield(self, pkt, s)
        
        # fraction point between bits 15 and 16.
        sec = b >> 16
        frac = b & (1L << (32+1)) - 1
        frac /= 65536.0
        b = sec+frac
        return s,b    

class Dot11SCField(LEShortField):
    def is_applicable(self, pkt):
        return pkt.type != 1 # control frame
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return LEShortField.addfield(self, pkt, s, val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return LEShortField.getfield(self, pkt, s)
        else:
            return s,None

#####################
#### ASN1 Fields ####
#####################

class ASN1F_badsequence(Exception):
    pass

class ASN1F_element:
    pass

class ASN1F_field(ASN1F_element):
    holds_packets=0
    islist=0

    ASN1_tag = ASN1_Class_UNIVERSAL.ANY
    
    def __init__(self, name, default):
        self.name = name
        self.default = default

    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return repr(x)
    def i2h(self, pkt, x):
        if x is None:
            x = 0
        return x
    def any2i(self, pkt, x):
        return x
    def m2i(self, pkt, x):
        return self.ASN1_tag.get_codec(pkt.ASN1_codec).safedec(x)
    def i2m(self, pkt, x):
        if x is None:
            x = 0
        if isinstance(x, ASN1_Object):
            if ( self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY
                 or x.tag == ASN1_Class_UNIVERSAL.RAW
                 or x.tag == ASN1_Class_UNIVERSAL.ERROR
                 or self.ASN1_tag == x.tag ):
                return x.enc(pkt.ASN1_codec)
            else:
                raise ASN1_Error("Encoding Error: got %r instead of an %r for field [%s]" % (x, self.ASN1_tag, self.name))
        return self.ASN1_tag.get_codec(pkt.ASN1_codec).enc(x)

    def do_copy(self, x):
        if hasattr(x, "copy"):
            return x.copy()
        if type(x) is list:
            x = x[:]
            for i in xrange(len(x)):
                if isinstance(x[i], Packet):
                    x[i] = x[i].copy()
        return x

    def build(self, pkt):
        return self.i2m(pkt, getattr(pkt, self.name))

    def set_val(self, pkt, val):
        setattr(pkt, self.name, val)
    
    def dissect(self, pkt, s):
        v,s = self.m2i(pkt, s)
        self.set_val(pkt, v)
        return s

    def get_fields_list(self):
        return [self]

    def __hash__(self):
        return hash(self.name)
    def __str__(self):
        return self.name
    def __eq__(self, other):
        return self.name == other
    def __repr__(self):
        return self.name
    def randval(self):
        return RandInt()


class ASN1F_INTEGER(ASN1F_field):
    ASN1_tag= ASN1_Class_UNIVERSAL.INTEGER
    def randval(self):
        return RandNum(-2**64, 2**64-1)

class ASN1F_enum_INTEGER(ASN1F_INTEGER):
    def __init__(self, name, default, enum):
        ASN1F_INTEGER.__init__(self, name, default)
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if filter(lambda x: type(x) is str, keys):
            i2s,s2i = s2i,i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
    def any2i_one(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x
    def i2repr_one(self, pkt, x):
        return self.i2s.get(x, repr(x))
    
    def any2i(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.any2i_one(pkt,z), x)
        else:
            return self.any2i_one(pkt,x)        
    def i2repr(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.i2repr_one(pkt,z), x)
        else:
            return self.i2repr_one(pkt,x)

class ASN1F_STRING(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.STRING
    def randval(self):
        return RandString(RandNum(0, 1000))

class ASN1F_OID(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.OID
    def randval(self):
        return RandOID()

class ASN1F_SEQUENCE(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    def __init__(self, *seq, **kargs):
        if "ASN1_tag" in kargs:
            self.ASN1_tag = kargs["ASN1_tag"]
        self.seq = seq
    def __repr__(self):
        return "<%s%r>" % (self.__class__.__name__,self.seq,)
    def get_fields_list(self):
        return reduce(lambda x,y: x+y.get_fields_list(), self.seq, [])
    def build(self, pkt):
        s = reduce(lambda x,y: x+y.build(pkt), self.seq, "")
        return self.i2m(pkt, s)
    def dissect(self, pkt, s):
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        try:
            i,s,remain = codec.check_type_check_len(s)
            for obj in self.seq:
                s = obj.dissect(pkt,s)
            if s:
                warning("Too many bytes to decode sequence: [%r]" % s) # XXX not reversible!
            return remain
        except ASN1_Error,e:
            raise ASN1F_badsequence(e)

class ASN1F_SEQUENCE_OF(ASN1F_SEQUENCE):
    holds_packets = 1
    islist = 1
    def __init__(self, name, default, asn1pkt, ASN1_tag=0x30):
        self.asn1pkt = asn1pkt
        self.tag = chr(ASN1_tag)
        self.name = name
        self.default = default
    def get_fields_list(self):
        return [self]
    def build(self, pkt):
        val = getattr(pkt, self.name)
        if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
            s = val
        else:
            s = "".join(map(str, val ))
        return self.i2m(pkt, s)
    def dissect(self, pkt, s):
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i,s1,remain = codec.check_type_check_len(s)
        lst = []
        while s1:
            try:
                p = self.asn1pkt(s1)
            except ASN1F_badsequence:
                lst.append(Raw(s1))
                break
            lst.append(p)
            if Raw in p:
                s1 = p[Raw].load
                del(p[Raw].underlayer.payload)
            else:
                break
        self.set_val(pkt, lst)
        return remain
    def randval(self):
        return fuzz(self.asn1pkt())

class ASN1F_PACKET(ASN1F_field):
    holds_packets = 1
    def __init__(self, name, default, cls):
        ASN1_field.__init__(self, name, default)
        self.cls = cls
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        return str(x)
    def extract_packet(self, cls, x):
        try:
            c = cls(x)
        except ASN1F_badsequence:
            c = Raw(x)
        cpad = c[Padding]
        x = ""
        if cpad is not None:
            x = cpad.load
            del(cpad.underlayer.payload)
        return c,x
    def m2i(self, pkt, x):
        return self.extract_packet(self.cls, x)


class ASN1F_CHOICE(ASN1F_PACKET):
    ASN1_tag = ASN1_Class_UNIVERSAL.NONE
    def __init__(self, name, default, *args):
        self.name=name
        self.choice = {}
        for p in args:
            self.choice[p.ASN1_root.ASN1_tag] = p
#        self.context=context
        self.default=default
    def m2i(self, pkt, x):
        if len(x) == 0:
            return Raw(),""
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        if ord(x[0]) not in self.choice:
            return Raw(x),"" # XXX return RawASN1 packet ? Raise error 
            raise ASN1_Error("Decoding Error: choice [%i] not found in %r" % (ord(x[0]), self.choice.keys()))

        z = ASN1F_PACKET.extract_packet(self, self.choice[ord(x[0])], x)
        return z
    def randval(self):
        return RandChoice(*map(lambda x:fuzz(x()), self.choice.values()))
            
    

###########################
## Packet abstract class ##
###########################

class Packet_metaclass(type):
    def __new__(cls, name, bases, dct):
        newcls = super(Packet_metaclass, cls).__new__(cls, name, bases, dct)
        for f in newcls.fields_desc:
            f.register_owner(newcls)
        return newcls
    def __getattr__(self, attr):
        for k in self.fields_desc:
            if k.name == attr:
                return k
        raise AttributeError(attr)

class NewDefaultValues(Packet_metaclass):
    """NewDefaultValues metaclass. Example usage:
    class MyPacket(Packet):
        fields_desc = [ StrField("my_field", "my default value"),  ]
        
    class MyPacket_variant(MyPacket):
        __metaclass__ = NewDefaultValues
        my_field = "my new default value"
    """    
    def __new__(cls, name, bases, dct):
        fields = None
        for b in bases:
            if hasattr(b,"fields_desc"):
                fields = b.fields_desc
                break
        if fields is None:
            raise Scapy_Exception("No fields_desc in superclasses")

        new_fields = []
        for f in fields:
            if f.name in dct:
                f = f.copy()
                f.default = dct[f.name]
                del(dct[f.name])
            new_fields.append(f)
        dct["fields_desc"] = new_fields
        return super(NewDefaultValues, cls).__new__(cls, name, bases, dct)

class Packet(Gen):
    __metaclass__ = Packet_metaclass
    name=None

    fields_desc = []

    aliastypes = []
    overload_fields = {}

    underlayer = None

    payload_guess = []
    initialized = 0
    show_indent=1
    explicit = 0

    @classmethod
    def from_hexcap(cls):
        return cls(import_hexcap())

    @classmethod
    def upper_bonds(self):
        for fval,upper in self.payload_guess:
            print "%-20s  %s" % (upper.__name__, ", ".join("%-12s" % ("%s=%r"%i) for i in fval.iteritems()))

    @classmethod
    def lower_bonds(self):
        for lower,fval in self.overload_fields.iteritems():
            print "%-20s  %s" % (lower.__name__, ", ".join("%-12s" % ("%s=%r"%i) for i in fval.iteritems()))

    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):
        self.time  = time.time()
        self.sent_time = 0
        if self.name is None:
            self.name = self.__class__.__name__
        self.aliastypes = [ self.__class__ ] + self.aliastypes
        self.default_fields = {}
        self.overloaded_fields = {}
        self.fields={}
        self.fieldtype={}
        self.packetfields=[]
        self.__dict__["payload"] = NoPayload()
        self.init_fields()
        self.underlayer = _underlayer
        self.initialized = 1
        if _pkt:
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        for f in fields.keys():
            self.fields[f] = self.get_field(f).any2i(self,fields[f])
        if type(post_transform) is list:
            self.post_transforms = post_transform
        elif post_transform is None:
            self.post_transforms = []
        else:
            self.post_transforms = [post_transform]

    def init_fields(self):
        self.do_init_fields(self.fields_desc)

    def do_init_fields(self, flist):
        for f in flist:
            self.default_fields[f.name] = f.default
            self.fieldtype[f.name] = f
            if f.holds_packets:
                self.packetfields.append(f)
            
    def dissection_done(self,pkt):
        """DEV: will be called after a dissection is completed"""
        self.post_dissection(pkt)
        self.payload.dissection_done(pkt)
        
    def post_dissection(self, pkt):
        """DEV: is called after the dissection of the whole packet"""
        pass

    def get_field(self, fld):
        """DEV: returns the field instance from the name of the field"""
        return self.fieldtype[fld]
        
    def add_payload(self, payload):
        if payload is None:
            return
        elif not isinstance(self.payload, NoPayload):
            self.payload.add_payload(payload)
        else:
            if isinstance(payload, Packet):
                self.__dict__["payload"] = payload
                payload.add_underlayer(self)
                for t in self.aliastypes:
                    if payload.overload_fields.has_key(t):
                        self.overloaded_fields = payload.overload_fields[t]
                        break
            elif type(payload) is str:
                self.__dict__["payload"] = Raw(load=payload)
            else:
                raise TypeError("payload must be either 'Packet' or 'str', not [%s]" % repr(payload))
    def remove_payload(self):
        self.payload.remove_underlayer(self)
        self.__dict__["payload"] = NoPayload()
        self.overloaded_fields = {}
    def add_underlayer(self, underlayer):
        self.underlayer = underlayer
    def remove_underlayer(self,other):
        self.underlayer = None
    def copy(self):
        """Returns a deep copy of the instance."""
        clone = self.__class__()
        clone.fields = self.fields.copy()
        for k in clone.fields:
            clone.fields[k]=self.get_field(k).do_copy(clone.fields[k])
        clone.default_fields = self.default_fields.copy()
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.overload_fields = self.overload_fields.copy()
        clone.underlayer=self.underlayer
        clone.explicit=self.explicit
        clone.post_transforms=self.post_transforms[:]
        clone.__dict__["payload"] = self.payload.copy()
        clone.payload.add_underlayer(clone)
        return clone

    def getfieldval(self, attr):
        if attr in self.fields:
            return self.fields[attr]
        if attr in self.overloaded_fields:
            return self.overloaded_fields[attr]
        if attr in self.default_fields:
            return self.default_fields[attr]
        return self.payload.getfieldval(attr)
    
    def getfield_and_val(self, attr):
        if attr in self.fields:
            return self.get_field(attr),self.fields[attr]
        if attr in self.overloaded_fields:
            return self.get_field(attr),self.overloaded_fields[attr]
        if attr in self.default_fields:
            return self.get_field(attr),self.default_fields[attr]
        return self.payload.getfield_and_val(attr)
    
    def __getattr__(self, attr):
        if self.initialized:
            fld,v = self.getfield_and_val(attr)
            if fld is not None:
                return fld.i2h(self, v)
            return v
        raise AttributeError(attr)

    def __setattr__(self, attr, val):
        if self.initialized:
            if self.default_fields.has_key(attr):
                fld = self.get_field(attr)
                if fld is None:
                    any2i = lambda x,y: y
                else:
                    any2i = fld.any2i
                self.fields[attr] = any2i(self, val)
                self.explicit=0
            elif attr == "payload":
                self.remove_payload()
                self.add_payload(val)
            else:
                self.__dict__[attr] = val
        else:
            self.__dict__[attr] = val
    def __delattr__(self, attr):
        if self.initialized:
            if self.fields.has_key(attr):
                del(self.fields[attr])
                self.explicit=0 # in case a default value must be explicited
                return
            elif self.default_fields.has_key(attr):
                return
            elif attr == "payload":
                self.remove_payload()
                return
        if self.__dict__.has_key(attr):
            del(self.__dict__[attr])
        else:
            raise AttributeError(attr)
            
    def __repr__(self):
        s = ""
        ct = conf.color_theme
        for f in self.fields_desc:
            if f.name in self.fields:
                val = f.i2repr(self, self.fields[f.name])
            elif f.name in self.overloaded_fields:
                val =  f.i2repr(self, self.overloaded_fields[f.name])
            else:
                continue
            if isinstance(f, Emph):
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value

                
            s += " %s%s%s" % (ncol(f.name),
                              ct.punct("="),
                              vcol(val))
        return "%s%s %s %s%s%s"% (ct.punct("<"),
                                  ct.layer_name(self.__class__.__name__),
                                  s,
                                  ct.punct("|"),
                                  repr(self.payload),
                                  ct.punct(">"))
    def __str__(self):
        return self.build()
    def __div__(self, other):
        if isinstance(other, Packet):
            cloneA = self.copy()
            cloneB = other.copy()
            cloneA.add_payload(cloneB)
            return cloneA
        elif type(other) is str:
            return self/Raw(load=other)
        else:
            return other.__rdiv__(self)
    def __rdiv__(self, other):
        if type(other) is str:
            return Raw(load=other)/self
        else:
            raise TypeError
    def __mul__(self, other):
        if type(other) is int:
            return  [self]*other
        else:
            raise TypeError
    def __rmul__(self,other):
        return self.__mul__(other)
    
    def __nonzero__(self):
        return True
    def __len__(self):
        return len(self.__str__())
    def do_build(self):
        p=""
        for f in self.fields_desc:
            p = f.addfield(self, p, self.getfieldval(f.name))
        return p
    
    def post_build(self, pkt, pay):
        """DEV: called right after the current layer is build."""
        return pkt+pay

    def build_payload(self):
        return self.payload.build(internal=1)

    def build(self,internal=0):
        if not self.explicit:
            self = self.__iter__().next()
        pkt = self.do_build()
        for t in self.post_transforms:
            pkt = t(pkt)
        pay = self.build_payload()
        try:
            p = self.post_build(pkt,pay)
        except TypeError:
            log_runtime.error("API changed! post_build() now takes 2 arguments. Compatibility is only assured for a short transition time")
            p = self.post_build(pkt+pay)
        if not internal:
            pad = self.payload.getlayer(Padding) 
            if pad: 
                p += pad.build()
            p = self.build_done(p)
        return p

    def build_done(self, p):
        return self.payload.build_done(p)

    def do_build_ps(self):
        p=""
        pl = []
        q=""
        for f in self.fields_desc:
            p = f.addfield(self, p, self.getfieldval(f.name) )
            if type(p) is str:
                r = p[len(q):]
                q = p
            else:
                r = ""
            pl.append( (f, f.i2repr(self,self.getfieldval(f.name)), r) )
            
        pkt,lst = self.payload.build_ps(internal=1)
        p += pkt
        lst.append( (self, pl) )
        
        return p,lst
    
    def build_ps(self,internal=0):
        p,lst = self.do_build_ps()
#        if not internal:
#            pkt = self
#            while pkt.haslayer(Padding):
#                pkt = pkt.getlayer(Padding)
#                lst.append( (pkt, [ ("loakjkjd", pkt.load, pkt.load) ] ) )
#                p += pkt.load
#                pkt = pkt.payload
        return p,lst


    def psdump(self, filename=None, **kargs):
        """psdump(filename=None, layer_shift=0, rebuild=1)
Creates an EPS file describing a packet. If filename is not provided a temporary file is created and gs is called."""
        canvas = self.canvas_dump(**kargs)
        if filename is None:
            fname = "/tmp/scapy.%i"%os.getpid()
            canvas.writeEPSfile(fname)
            os.system("%s '%s.eps' &" % (conf.prog.psreader,fname))
        else:
            canvas.writeEPSfile(filename)

    def pdfdump(self, filename=None, **kargs):
        """pdfdump(filename=None, layer_shift=0, rebuild=1)
        Creates a PDF file describing a packet. If filename is not provided a temporary file is created and xpdf is called."""
        canvas = self.canvas_dump(**kargs)
        if filename is None:
            fname = "/tmp/scapy.%i"%os.getpid()
            canvas.writePDFfile(fname)
            os.system("%s '%s.pdf' &" % (conf.prog.pdfreader,fname))
        else:
            canvas.writePDFfile(filename)

        
    def canvas_dump(self, layer_shift=0, rebuild=1):
        canvas = pyx.canvas.canvas()
        if rebuild:
            p,t = self.__class__(str(self)).build_ps()
        else:
            p,t = self.build_ps()
        YTXT=len(t)
        for n,l in t:
            YTXT += len(l)
        YTXT = float(YTXT)
        YDUMP=YTXT

        XSTART = 1
        XDSTART = 10
        y = 0.0
        yd = 0.0
        xd = 0 
        XMUL= 0.55
        YMUL = 0.4
    
        backcolor=colgen(0.6, 0.8, 1.0, trans=pyx.color.rgb)
        forecolor=colgen(0.2, 0.5, 0.8, trans=pyx.color.rgb)
#        backcolor=makecol(0.376, 0.729, 0.525, 1.0)
        
        
        def hexstr(x):
            s = []
            for c in x:
                s.append("%02x" % ord(c))
            return " ".join(s)

                
        def make_dump_txt(x,y,txt):
            return pyx.text.text(XDSTART+x*XMUL, (YDUMP-y)*YMUL, r"\tt{%s}"%hexstr(txt), [pyx.text.size.Large])

        def make_box(o):
            return pyx.box.rect(o.left(), o.bottom(), o.width(), o.height(), relcenter=(0.5,0.5))

        def make_frame(lst):
            if len(lst) == 1:
                b = lst[0].bbox()
                b.enlarge(pyx.unit.u_pt)
                return b.path()
            else:
                fb = lst[0].bbox()
                fb.enlarge(pyx.unit.u_pt)
                lb = lst[-1].bbox()
                lb.enlarge(pyx.unit.u_pt)
                if len(lst) == 2 and fb.left() > lb.right():
                    return pyx.path.path(pyx.path.moveto(fb.right(), fb.top()),
                                         pyx.path.lineto(fb.left(), fb.top()),
                                         pyx.path.lineto(fb.left(), fb.bottom()),
                                         pyx.path.lineto(fb.right(), fb.bottom()),
                                         pyx.path.moveto(lb.left(), lb.top()),
                                         pyx.path.lineto(lb.right(), lb.top()),
                                         pyx.path.lineto(lb.right(), lb.bottom()),
                                         pyx.path.lineto(lb.left(), lb.bottom()))
                else:
                    # XXX
                    gb = lst[1].bbox()
                    if gb != lb:
                        gb.enlarge(pyx.unit.u_pt)
                    kb = lst[-2].bbox()
                    if kb != gb and kb != lb:
                        kb.enlarge(pyx.unit.u_pt)
                    return pyx.path.path(pyx.path.moveto(fb.left(), fb.top()),
                                         pyx.path.lineto(fb.right(), fb.top()),
                                         pyx.path.lineto(fb.right(), kb.bottom()),
                                         pyx.path.lineto(lb.right(), kb.bottom()),
                                         pyx.path.lineto(lb.right(), lb.bottom()),
                                         pyx.path.lineto(lb.left(), lb.bottom()),
                                         pyx.path.lineto(lb.left(), gb.top()),
                                         pyx.path.lineto(fb.left(), gb.top()),
                                         pyx.path.closepath(),)
                                         

        def make_dump(s, shift=0, y=0, col=None, bkcol=None, larg=16):
            c = pyx.canvas.canvas()
            tlist = []
            while s:
                dmp,s = s[:larg-shift],s[larg-shift:]
                txt = make_dump_txt(shift, y, dmp)
                tlist.append(txt)
                shift += len(dmp)
                if shift >= 16:
                    shift = 0
                    y += 1
            if col is None:
                col = pyx.color.rgb.red
            if bkcol is None:
                col = pyx.color.rgb.white
            c.stroke(make_frame(tlist),[col,pyx.deco.filled([bkcol]),pyx.style.linewidth.Thick])
            for txt in tlist:
                c.insert(txt)
            return c, tlist[-1].bbox(), shift, y
                            

        last_shift,last_y=0,0.0
        while t:
            bkcol = backcolor.next()
            proto,fields = t.pop()
            y += 0.5
            pt = pyx.text.text(XSTART, (YTXT-y)*YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % proto.name, [ pyx.text.size.Large])
            y += 1
            ptbb=pt.bbox()
            ptbb.enlarge(pyx.unit.u_pt*2)
            canvas.stroke(ptbb.path(),[pyx.color.rgb.black, pyx.deco.filled([bkcol])])
            canvas.insert(pt)
            for fname, fval, fdump in fields:
                col = forecolor.next()
                ft = pyx.text.text(XSTART, (YTXT-y)*YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % tex_escape(fname.name))
                if fval is not None:
                    if len(fval) > 18:
                        fval = fval[:18]+"[...]"
                else:
                    fval=""
                vt = pyx.text.text(XSTART+3, (YTXT-y)*YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % tex_escape(fval))
                y += 1.0
                if fdump:
                    dt,target,last_shift,last_y = make_dump(fdump, last_shift, last_y, col, bkcol)

                    dtb = dt.bbox()
                    dtb=target
                    vtb = vt.bbox()
                    bxvt = make_box(vtb)
                    bxdt = make_box(dtb)
                    dtb.enlarge(pyx.unit.u_pt)
                    try:
                        if yd < 0:
                            cnx = pyx.connector.curve(bxvt,bxdt,absangle1=0, absangle2=-90)
                        else:
                            cnx = pyx.connector.curve(bxvt,bxdt,absangle1=0, absangle2=90)
                    except:
                        pass
                    else:
                        canvas.stroke(cnx,[pyx.style.linewidth.thin,pyx.deco.earrow.small,col])
                        
                    canvas.insert(dt)
                
                canvas.insert(ft)
                canvas.insert(vt)
            last_y += layer_shift
    
        return canvas



    def extract_padding(self, s):
        """DEV: to be overloaded to extract current layer's padding. Return a couple of strings (actual layer, padding)"""
        return s,None

    def post_dissect(self, s):
        """DEV: is called right after the current layer has been dissected"""
        return s

    def pre_dissect(self, s):
        """DEV: is called right before the current layer is dissected"""
        return s

    def do_dissect(self, s):
        flist = self.fields_desc[:]
        flist.reverse()
        while s and flist:
            f = flist.pop()
            s,fval = f.getfield(self, s)
            self.fields[f.name] = fval
            
        return s

    def do_dissect_payload(self, s):
        if s:
            cls = self.guess_payload_class(s)
            try:
                p = cls(s, _internal=1, _underlayer=self)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    if isinstance(cls,type) and issubclass(cls,Packet):
                        log_runtime.error("%s dissector failed" % cls.name)
                    else:
                        log_runtime.error("%s.guess_payload_class() returned [%s]" % (self.__class__.__name__,repr(cls)))
                    if cls is not None:
                        raise
                p = Raw(s, _internal=1, _underlayer=self)
            self.add_payload(p)

    def dissect(self, s):
        s = self.pre_dissect(s)

        s = self.do_dissect(s)

        s = self.post_dissect(s)
            
        payl,pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(Padding(pad))


    def guess_payload_class(self, payload):
        """DEV: Guesses the next payload class from layer bonds. Can be overloaded to use a different mechanism."""
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                ok = 1
                for k in fval.keys():
                    if not hasattr(self, k) or fval[k] != self.getfieldval(k):
                        ok = 0
                        break
                if ok:
                    return cls
        return self.default_payload_class(payload)
    
    def default_payload_class(self, payload):
        """DEV: Returns the default payload class if nothing has been found by the guess_payload_class() method."""
        return Raw

    def hide_defaults(self):
        """Removes fields' values that are the same as default values."""
        for k in self.fields.keys():
            if self.default_fields.has_key(k):
                if self.default_fields[k] == self.fields[k]:
                    del(self.fields[k])
        self.payload.hide_defaults()
            

    def __iter__(self):
        def loop(todo, done, self=self):
            if todo:
                eltname = todo.pop()
                elt = self.getfieldval(eltname)
                if not isinstance(elt, Gen):
                    if self.get_field(eltname).islist:
                        elt = SetGen([elt])
                    else:
                        elt = SetGen(elt)
                for e in elt:
                    done[eltname]=e
                    for x in loop(todo[:], done):
                        yield x
            else:
                if isinstance(self.payload,NoPayload):
                    payloads = [None]
                else:
                    payloads = self.payload
                for payl in payloads:
                    done2=done.copy()
                    for k in done2:
                        if isinstance(done2[k], VolatileValue):
                            done2[k] = done2[k]._fix()
                    pkt = self.__class__()
                    pkt.explicit = 1
                    pkt.fields = done2
                    pkt.time = self.time
                    pkt.underlayer = self.underlayer
                    pkt.overload_fields = self.overload_fields.copy()
                    pkt.post_transforms = self.post_transforms
                    if payl is not None:
                        pkt.add_payload(payl)
                    yield pkt

        if self.explicit:
            todo = []
            done = self.fields
        else:
            todo = [ k for (k,v) in itertools.chain(self.default_fields.iteritems(),
                                                    self.overloaded_fields.iteritems())
                     if isinstance(v, VolatileValue) ] + self.fields.keys()
            done = {}
        return loop(todo, done)

    def __gt__(self, other):
        """True if other is an answer from self (self ==> other)."""
        if isinstance(other, Packet):
            return other < self
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))
    def __lt__(self, other):
        """True if self is an answer from other (other ==> self)."""
        if isinstance(other, Packet):
            return self.answers(other)
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        for f in self.fields_desc:
            if f not in other.fields_desc:
                return False
            if self.getfieldval(f.name) != other.getfieldval(f.name):
                return False
        return self.payload == other.payload

    def __ne__(self, other):
        return not self.__eq__(other)

    def hashret(self):
        """DEV: returns a string that has the same value for a request and its answer."""
        return self.payload.hashret()
    def answers(self, other):
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0

    def haslayer(self, cls):
        """true if self has a layer that is an instance of cls. Superseded by "cls in self" syntax."""
        if self.__class__ == cls or self.__class__.__name__ == cls:
            return 1
        for f in self.packetfields:
            fvalue_gen = self.getfieldval(f.name)
            if fvalue_gen is None:
                continue
            if not f.islist:
                fvalue_gen = SetGen(fvalue_gen,_iterpacket=0)
            for fvalue in fvalue_gen:
                if isinstance(fvalue, Packet):
                    ret = fvalue.haslayer(cls)
                    if ret:
                        return ret
        return self.payload.haslayer(cls)
    def getlayer(self, cls, nb=1, _track=None):
        """Return the nb^th layer that is an instance of cls."""
        if type(cls) is str and "." in cls:
            ccls,fld = cls.split(".",1)
        else:
            ccls,fld = cls,None
        if self.__class__ == cls or self.__class__.name == ccls:
            if nb == 1:
                if fld is None:
                    return self
                else:
                    return self.getfieldval(fld)
            else:
                nb -=1
        for f in self.packetfields:
            fvalue_gen = self.getfieldval(f.name)
            if fvalue_gen is None:
                continue
            if not f.islist:
                fvalue_gen = SetGen(fvalue_gen,_iterpacket=0)
            for fvalue in fvalue_gen:
                if isinstance(fvalue, Packet):
                    track=[]
                    ret = fvalue.getlayer(cls, nb, _track=track)
                    if ret is not None:
                        return ret
                    nb = track[0]
        return self.payload.getlayer(cls,nb,_track=_track)

    def __getitem__(self, cls):
        if type(cls) is slice:
            if cls.stop:
                ret = self.getlayer(cls.start, cls.stop)
            else:
                ret = self.getlayer(cls.start)
            if ret is None and cls.step is not None:
                ret = cls.step
            return ret
        else:
            return self.getlayer(cls)
        
    def __contains__(self, cls):
        """"cls in self" returns true if self has a layer which is an instance of cls."""
        return self.haslayer(cls)
        
    

    def display(self,*args,**kargs):  # Deprecated. Use show()
        """Deprecated. Use show() method."""
        self.show(*args,**kargs)
    def show(self, indent=3, lvl="", label_lvl=""):
        """Prints a hierarchical view of the packet. "indent" gives the size of indentation for each layer."""
        ct = conf.color_theme
        print "%s%s %s %s" % (label_lvl,
                              ct.punct("###["),
                              ct.layer_name(self.name),
                              ct.punct("]###"))
        for f in self.fields_desc:
            if isinstance(f, Emph):
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value
            fvalue = self.getfieldval(f.name)
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and type(fvalue) is list):
                print "%s  \\%-10s\\" % (label_lvl+lvl, ncol(f.name))
                fvalue_gen = SetGen(fvalue,_iterpacket=0)
                for fvalue in fvalue_gen:
                    fvalue.show(indent=indent, label_lvl=label_lvl+lvl+"   |")
            else:
                print "%s  %-10s%s %s" % (label_lvl+lvl,
                                          ncol(f.name),
                                          ct.punct("="),
                                          vcol(f.i2repr(self,fvalue)))
        self.payload.show(indent=indent, lvl=lvl+(" "*indent*self.show_indent), label_lvl=label_lvl)
    def show2(self):
        """Prints a hierarchical view of an assembled version of the packet, so that automatic fields are calculated (checksums, etc.)"""
        self.__class__(str(self)).show()

    def sprintf(self, fmt, relax=1):
        """sprintf(format, [relax=1]) -> str
where format is a string that can include directives. A directive begins and
ends by % and has the following format %[fmt[r],][cls[:nb].]field%.

fmt is a classic printf directive, "r" can be appended for raw substitution
(ex: IP.flags=0x18 instead of SA), nb is the number of the layer we want
(ex: for IP/IP packets, IP:2.src is the src of the upper IP layer).
Special case : "%.time%" is the creation time.
Ex : p.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% "
               "%03xr,IP.proto% %r,TCP.flags%")

Moreover, the format string can include conditionnal statements. A conditionnal
statement looks like : {layer:string} where layer is a layer name, and string
is the string to insert in place of the condition if it is true, i.e. if layer
is present. If layer is preceded by a "!", the result si inverted. Conditions
can be imbricated. A valid statement can be :
  p.sprintf("This is a{TCP: TCP}{UDP: UDP}{ICMP:n ICMP} packet")
  p.sprintf("{IP:%IP.dst% {ICMP:%ICMP.type%}{TCP:%TCP.dport%}}")

A side effect is that, to obtain "{" and "}" characters, you must use
"%(" and "%)".
"""

        escape = { "%": "%",
                   "(": "{",
                   ")": "}" }


        # Evaluate conditions 
        while "{" in fmt:
            i = fmt.rindex("{")
            j = fmt[i+1:].index("}")
            cond = fmt[i+1:i+j+1]
            k = cond.find(":")
            if k < 0:
                raise Scapy_Exception("Bad condition in format string: [%s] (read sprintf doc!)"%cond)
            cond,format = cond[:k],cond[k+1:]
            res = False
            if cond[0] == "!":
                res = True
                cond = cond[1:]
            if self.haslayer(cond):
                res = not res
            if not res:
                format = ""
            fmt = fmt[:i]+format+fmt[i+j+2:]

        # Evaluate directives
        s = ""
        while "%" in fmt:
            i = fmt.index("%")
            s += fmt[:i]
            fmt = fmt[i+1:]
            if fmt and fmt[0] in escape:
                s += escape[fmt[0]]
                fmt = fmt[1:]
                continue
            try:
                i = fmt.index("%")
                sfclsfld = fmt[:i]
                fclsfld = sfclsfld.split(",")
                if len(fclsfld) == 1:
                    f = "s"
                    clsfld = fclsfld[0]
                elif len(fclsfld) == 2:
                    f,clsfld = fclsfld
                else:
                    raise Scapy_Exception
                if "." in clsfld:
                    cls,fld = clsfld.split(".")
                else:
                    cls = self.__class__.__name__
                    fld = clsfld
                num = 1
                if ":" in cls:
                    cls,num = cls.split(":")
                    num = int(num)
                fmt = fmt[i+1:]
            except:
                raise Scapy_Exception("Bad format string [%%%s%s]" % (fmt[:25], fmt[25:] and "..."))
            else:
                if fld == "time":
                    val = time.strftime("%H:%M:%S.%%06i", time.localtime(self.time)) % int((self.time-int(self.time))*1000000)
                elif cls == self.__class__.__name__ and hasattr(self, fld):
                    if num > 1:
                        val = self.payload.sprintf("%%%s,%s:%s.%s%%" % (f,cls,num-1,fld), relax)
                        f = "s"
                    elif f[-1] == "r":  # Raw field value
                        val = getattr(self,fld)
                        f = f[:-1]
                        if not f:
                            f = "s"
                    else:
                        val = getattr(self,fld)
                        if fld in self.fieldtype:
                            val = self.fieldtype[fld].i2repr(self,val)
                else:
                    val = self.payload.sprintf("%%%s%%" % sfclsfld, relax)
                    f = "s"
                s += ("%"+f) % val
            
        s += fmt
        return s

    def mysummary(self):
        """DEV: can be overloaded to return a string that summarizes the layer.
           Only one mysummary() is used in a whole packet summary: the one of the upper layer,
           except if a mysummary() also returns (as a couple) a list of layers whose
           mysummary() must be called if they are present."""
        return ""

    def summary(self, intern=0):
        """Prints a one line summary of a packet."""
        found,s,needed = self.payload.summary(intern=1)
        if s:
            s = " / "+s
        ret = ""
        if not found or self.__class__ in needed:
            ret = self.mysummary()
            if type(ret) is tuple:
                ret,n = ret
                needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = self.__class__.__name__
        ret = "%s%s" % (ret,s)
        if intern:
            return found,ret,needed
        else:
            return ret
    
    def lastlayer(self,layer=None):
        """Returns the uppest layer of the packet"""
        return self.payload.lastlayer(self)

    def decode_payload_as(self,cls):
        """Reassembles the payload and decode it using another packet class"""
        s = str(self.payload)
        self.payload = cls(s)

    def libnet(self):
        """Not ready yet. Should give the necessary C code that interfaces with libnet to recreate the packet"""
        print "libnet_build_%s(" % self.__class__.name.lower()
        det = self.__class__(str(self))
        for f in self.fields_desc:
            val = det.getfieldval(f.name)
            if val is None:
                val = 0
            elif type(val) is int:
                val = str(val)
            else:
                val = '"%s"' % str(val)
            print "\t%s, \t\t/* %s */" % (val,f.name)
        print ");"
    def command(self):
        """Returns a string representing the command you have to type to obtain the same packet"""
        f = []
        for fn,fv in self.fields.items():
            fld = self.get_field(fn)
            if isinstance(fv, Packet):
                fv = fv.command()
            elif fld.islist and fld.holds_packets and type(fv) is list:
                fv = "[%s]" % ",".join( map(Packet.command, fv))
            else:
                fv = repr(fv)
            f.append("%s=%s" % (fn, fv))
        c = "%s(%s)" % (self.__class__.__name__, ", ".join(f))
        pc = self.payload.command()
        if pc:
            c += "/"+pc
        return c                    


class ASN1_Packet(Packet):
    ASN1_root = None
    ASN1_codec = None    
    def init_fields(self):
        flist = self.ASN1_root.get_fields_list()
        self.do_init_fields(flist)
        self.fields_desc = flist    
    def do_build(self):
        return self.ASN1_root.build(self)    
    def do_dissect(self, x):
        return self.ASN1_root.dissect(self, x)
        

class NoPayload(Packet,object):
    def __new__(cls, *args, **kargs):
        singl = cls.__dict__.get("__singl__")
        if singl is None:
            cls.__singl__ = singl = object.__new__(cls)
            Packet.__init__(singl, *args, **kargs)
        return singl
    def __init__(self, *args, **kargs):
        pass
    def dissection_done(self,pkt):
        return
    def add_payload(self, payload):
        raise Scapy_Exception("Can't add payload to NoPayload instance")
    def remove_payload(self):
        pass
    def add_underlayer(self,underlayer):
        pass
    def remove_underlayer(self,other):
        pass
    def copy(self):
        return self
    def __repr__(self):
        return ""
    def __str__(self):
        return ""
    def __nonzero__(self):
        return False
    def build(self, internal=0):
        return ""    
    def build_done(self, p):
        return p
    def build_ps(self, internal=0):
        return "",[]
    def getfieldval(self, attr):
        raise AttributeError(attr)
    def getfield_and_val(self, attr):
        raise AttributeError(attr)
    def __getattr__(self, attr):
        if attr in self.__dict__:
            return self.__dict__[attr]
        elif attr in self.__class__.__dict__:
            return self.__class__.__dict__[attr]
        else:
            raise AttributeError, attr
    def hide_defaults(self):
        pass
    def __iter__(self):
        return iter([])
    def __eq__(self, other):
        if isinstance(other, NoPayload):
            return True
        return False
    def hashret(self):
        return ""
    def answers(self, other):
        return isinstance(other, NoPayload) or isinstance(other, Padding)
    def haslayer(self, cls):
        return 0
    def getlayer(self, cls, nb=1, _track=None):
        if _track is not None:
            _track.append(nb)
        return None
    def show(self, indent=3, lvl="", label_lvl=""):
        pass
    def sprintf(self, fmt, relax):
        if relax:
            return "??"
        else:
            raise Scapy_Exception("Format not found [%s]"%fmt)
    def summary(self, intern=0):
        return 0,"",[]
    def lastlayer(self,layer):
        return layer
    def command(self):
        return ""
    

####################
## packet classes ##
####################
    
            
class Raw(Packet):
    name = "Raw"
    fields_desc = [ StrField("load", "") ]
    def answers(self, other):
        return 1
#        s = str(other)
#        t = self.load
#        l = min(len(s), len(t))
#        return  s[:l] == t[:l]
        
class Padding(Raw):
    name = "Padding"
    def build(self, internal=0):
        if internal:
            return ""
        else:
            return Raw.build(self)

class Ether(Packet):
    name = "Ethernet"
    fields_desc = [ DestMACField("dst"),
                    SourceMACField("src"),
                    XShortEnumField("type", 0x0000, ETHER_TYPES) ]
    def hashret(self):
        return struct.pack("H",self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return self.sprintf("%src% > %dst% (%type%)")

class PPPoE(Packet):
    name = "PPP over Ethernet"
    fields_desc = [ BitField("version", 1, 4),
                    BitField("type", 1, 4),
                    ByteEnumField("code", 0, {0:"Session"}),
                    XShortField("sessionid", 0x0),
                    ShortField("len", None) ]

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-6
            p = p[:4]+struct.pack("!H", l)+p[6:]
        return p

class PPPoED(PPPoE):
    name = "PPP over Ethernet Discovery"
    fields_desc = [ BitField("version", 1, 4),
                    BitField("type", 1, 4),
                    ByteEnumField("code", 0x09, {0x09:"PADI",0x07:"PADO",0x19:"PADR",0x65:"PADS",0xa7:"PADT"}),
                    XShortField("sessionid", 0x0),
                    ShortField("len", None) ]

class Dot3(Packet):
    name = "802.3"
    fields_desc = [ MACField("dst", ETHER_BROADCAST),
                    MACField("src", ETHER_ANY),
                    LenField("len", None, "H") ]
    def extract_padding(self,s):
        l = self.len
        return s[:l],s[l:]
    def answers(self, other):
        if isinstance(other,Dot3):
            return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return "802.3 %s > %s" % (self.src, self.dst)


class LLC(Packet):
    name = "LLC"
    fields_desc = [ XByteField("dsap", 0x00),
                    XByteField("ssap", 0x00),
                    ByteField("ctrl", 0) ]


class CookedLinux(Packet):
    name = "cooked linux"
    fields_desc = [ ShortEnumField("pkttype",0, {0: "unicast",
                                                 4:"sent-by-us"}), #XXX incomplete
                    XShortField("lladdrtype",512),
                    ShortField("lladdrlen",0),
                    StrFixedLenField("src","",8),
                    XShortEnumField("proto",0x800,ETHER_TYPES) ]
                    
                                   

class SNAP(Packet):
    name = "SNAP"
    fields_desc = [ X3BytesField("OUI",0x000000),
                    XShortEnumField("code", 0x000, ETHER_TYPES) ]


class Dot1Q(Packet):
    name = "802.1Q"
    aliastypes = [ Ether ]
    fields_desc =  [ BitField("prio", 0, 3),
                     BitField("id", 0, 1),
                     BitField("vlan", 1, 12),
                     XShortEnumField("type", 0x0000, ETHER_TYPES) ]
    def answers(self, other):
        if isinstance(other,Dot1Q):
            if ( (self.type == other.type) and
                 (self.vlan == other.vlan) ):
                return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)
        return 0
    def default_payload_class(self, pay):
        if self.type <= 1500:
            return LLC
        return Raw
    def extract_padding(self,s):
        if self.type <= 1500:
            return s[:self.type],s[self.type:]
        return s,None
    def mysummary(self):
        if isinstance(self.underlayer, Ether):
            return self.underlayer.sprintf("802.1q %Ether.src% > %Ether.dst% (%Dot1Q.type%) vlan %Dot1Q.vlan%")
        else:
            return self.sprintf("802.1q (%Dot1Q.type%) vlan %Dot1Q.vlan%")

            


class RadioTap(Packet):
    name = "RadioTap dummy"
    fields_desc = [ ByteField('version', 0),
                    ByteField('pad', 0),
                    FieldLenField('len', None, 'notdecoded', '@H', adjust=lambda pkt,x:x+8),
                    FlagsField('present', None, -32, ['TSFT','Flags','Rate','Channel','FHSS','dBm_AntSignal',
                                                     'dBm_AntNoise','Lock_Quality','TX_Attenuation','dB_TX_Attenuation',
                                                      'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',
                                                     'b14', 'b15','b16','b17','b18','b19','b20','b21','b22','b23',
                                                     'b24','b25','b26','b27','b28','b29','b30','Ext']),
                    StrLenField('notdecoded', "", length_from= lambda pkt:pkt.len-8) ]

class STP(Packet):
    name = "Spanning Tree Protocol"
    fields_desc = [ ShortField("proto", 0),
                    ByteField("version", 0),
                    ByteField("bpdutype", 0),
                    ByteField("bpduflags", 0),
                    ShortField("rootid", 0),
                    MACField("rootmac", ETHER_ANY),
                    IntField("pathcost", 0),
                    ShortField("bridgeid", 0),
                    MACField("bridgemac", ETHER_ANY),
                    ShortField("portid", 0),
                    BCDFloatField("age", 1),
                    BCDFloatField("maxage", 20),
                    BCDFloatField("hellotime", 2),
                    BCDFloatField("fwddelay", 15) ]


class EAPOL(Packet):
    name = "EAPOL"
    fields_desc = [ ByteField("version", 1),
                    ByteEnumField("type", 0, ["EAP_PACKET", "START", "LOGOFF", "KEY", "ASF"]),
                    LenField("len", None, "H") ]
    
    EAP_PACKET= 0
    START = 1
    LOGOFF = 2
    KEY = 3
    ASF = 4
    def extract_padding(self, s):
        l = self.len
        return s[:l],s[l:]
    def hashret(self):
        return chr(self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,EAPOL):
            if ( (self.type == self.EAP_PACKET) and
                 (other.type == self.EAP_PACKET) ):
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return self.sprintf("EAPOL %EAPOL.type%")
             

class EAP(Packet):
    name = "EAP"
    fields_desc = [ ByteEnumField("code", 4, {1:"REQUEST",2:"RESPONSE",3:"SUCCESS",4:"FAILURE"}),
                    ByteField("id", 0),
                    ShortField("len",None),
                    ConditionalField(ByteEnumField("type",0, {1:"ID",4:"MD5"}), lambda pkt:pkt.code not in [EAP.SUCCESS, EAP.FAILURE])

                                     ]
    
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    TYPE_ID = 1
    TYPE_MD5 = 4
    def answers(self, other):
        if isinstance(other,EAP):
            if self.code == self.REQUEST:
                return 0
            elif self.code == self.RESPONSE:
                if ( (other.code == self.REQUEST) and
                     (other.type == self.type) ):
                    return 1
            elif other.code == self.RESPONSE:
                return 1
        return 0
    
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p)+len(pay)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        return p+pay
             

class ARP(Packet):
    name = "ARP"
    fields_desc = [ XShortField("hwtype", 0x0001),
                    XShortEnumField("ptype",  0x0800, ETHER_TYPES),
                    ByteField("hwlen", 6),
                    ByteField("plen", 4),
                    ShortEnumField("op", 1, {"who-has":1, "is-at":2, "RARP-req":3, "RARP-rep":4, "Dyn-RARP-req":5, "Dyn-RAR-rep":6, "Dyn-RARP-err":7, "InARP-req":8, "InARP-rep":9}),
                    ARPSourceMACField("hwsrc"),
                    SourceIPField("psrc","pdst"),
                    MACField("hwdst", ETHER_ANY),
                    IPField("pdst", "0.0.0.0") ]
    who_has = 1
    is_at = 2
    def answers(self, other):
        if isinstance(other,ARP):
            if ( (self.op == self.is_at) and
                 (other.op == self.who_has) and
                 (self.psrc == other.pdst) ):
                return 1
        return 0
    def extract_padding(self, s):
        return "",s
    def mysummary(self):
        if self.op == self.is_at:
            return "ARP is at %s says %s" % (self.hwsrc, self.psrc)
        elif self.op == self.who_has:
            return "ARP who has %s says %s" % (self.pdst, self.psrc)
        else:
            return "ARP %ARP.op% %ARP.psrc% > %ARP.pdst%"
                 

class IP(Packet, IPTools):
    name = "IP"
    fields_desc = [ BitField("version" , 4 , 4),
                    BitField("ihl", None, 4),
                    XByteField("tos", 0),
                    ShortField("len", None),
                    ShortField("id", 1),
                    FlagsField("flags", 0, 3, ["MF","DF","evil"]),
                    BitField("frag", 0, 13),
                    ByteField("ttl", 64),
                    ByteEnumField("proto", 0, IP_PROTOS),
                    XShortField("chksum", None),
                    #IPField("src", "127.0.0.1"),
                    Emph(SourceIPField("src","dst")),
                    Emph(IPField("dst", "127.0.0.1")),
                    IPoptionsField("options", "") ]
    def post_build(self, p, pay):
        ihl = self.ihl
        if ihl is None:
            ihl = len(p)/4
            p = chr(((self.version&0xf)<<4) | ihl&0x0f)+p[1:]
        if self.len is None:
            l = len(p)+len(pay)
            p = p[:2]+struct.pack("!H", l)+p[4:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:10]+chr(ck>>8)+chr(ck&0xff)+p[12:]
        return p+pay

    def extract_padding(self, s):
        l = self.len - (self.ihl << 2)
        return s[:l],s[l:]

    def send(self, s, slp=0):
        for p in self:
            try:
                s.sendto(str(p), (p.dst,0))
            except socket.error, msg:
                log_runtime.error(msg)
            if slp:
                time.sleep(slp)
    def hashret(self):
        if ( (self.proto == socket.IPPROTO_ICMP)
             and (isinstance(self.payload, ICMP))
             and (self.payload.type in [3,4,5,11,12]) ):
            return self.payload.payload.hashret()
        else:
            if conf.checkIPsrc and conf.checkIPaddr:
                return strxor(inet_aton(self.src),inet_aton(self.dst))+struct.pack("B",self.proto)+self.payload.hashret()
            else:
                return struct.pack("B", self.proto)+self.payload.hashret()
    def answers(self, other):
        if not isinstance(other,IP):
            return 0
        if conf.checkIPaddr and (self.dst != other.src):
            return 0
        if ( (self.proto == socket.IPPROTO_ICMP) and
             (isinstance(self.payload, ICMP)) and
             (self.payload.type in [3,4,5,11,12]) ):
            # ICMP error message
            return self.payload.payload.answers(other)

        else:
            if ( (conf.checkIPaddr and (self.src != other.dst)) or
                 (self.proto != other.proto) ):
                return 0
            return self.payload.answers(other.payload)
    def mysummary(self):
        s = self.sprintf("%IP.src% > %IP.dst% %IP.proto%")
        if self.frag:
            s += " frag:%i" % self.frag
        return s
                 
    

class TCP(Packet):
    name = "TCP"
    fields_desc = [ ShortEnumField("sport", 20, TCP_SERVICES),
                    ShortEnumField("dport", 80, TCP_SERVICES),
                    IntField("seq", 0),
                    IntField("ack", 0),
                    BitField("dataofs", None, 4),
                    BitField("reserved", 0, 4),
                    FlagsField("flags", 0x2, 8, "FSRPAUEC"),
                    ShortField("window", 8192),
                    XShortField("chksum", None),
                    ShortField("urgptr", 0),
                    TCPOptionsField("options", {}) ]
    def post_build(self, p, pay):
        p += pay
        dataofs = self.dataofs
        if dataofs is None:
            dataofs = 5+((len(self.get_field("options").i2m(self,self.options))+3)/4)
            p = p[:12]+chr((dataofs << 4) | ord(p[12])&0x0f)+p[13:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    ln = self.underlayer.len-20
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck=checksum(psdhdr+p)
                p = p[:16]+struct.pack("!H", ck)+p[18:]
            elif isinstance(self.underlayer, IPv6) or isinstance(self.underlayer, _IPv6OptionHeader):
                ck = in6_chksum(socket.IPPROTO_TCP, self.underlayer, p)
                p = p[:16]+struct.pack("!H", ck)+p[18:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def hashret(self):
        if conf.checkIPsrc:
            return struct.pack("H",self.sport ^ self.dport)+self.payload.hashret()
        else:
            return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.dport) and
                    (self.dport == other.sport)):
                return 0
        if (abs(other.seq-self.ack) > 2+len(other.payload)):
            return 0
        return 1
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("TCP %IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% %TCP.flags%")
        elif isinstance(self.underlayer, IPv6):
            return self.underlayer.sprintf("TCP %IPv6.src%:%TCP.sport% > %IPv6.dst%:%TCP.dport% %TCP.flags%")
        else:
            return self.sprintf("TCP %TCP.sport% > %TCP.dport% %TCP.flags%")

class UDP(Packet):
    name = "UDP"
    fields_desc = [ ShortEnumField("sport", 53, UDP_SERVICES),
                    ShortEnumField("dport", 53, UDP_SERVICES),
                    ShortField("len", None),
                    XShortField("chksum", None), ]
    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:4]+struct.pack("!H",l)+p[6:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    ln = self.underlayer.len-20
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck=checksum(psdhdr+p)
                p = p[:6]+struct.pack("!H", ck)+p[8:]
            elif isinstance(self.underlayer, IPv6) or isinstance(self.underlayer, _IPv6OptionHeader):
                ck = in6_chksum(socket.IPPROTO_UDP, self.underlayer, p)
                p = p[:6]+struct.pack("!H", ck)+p[8:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def extract_padding(self, s):
        l = self.len - 8
        return s[:l],s[l:]
    def hashret(self):
        return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if self.dport != other.sport:
                return 0
        return self.payload.answers(other.payload)
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("UDP %IP.src%:%UDP.sport% > %IP.dst%:%UDP.dport%")
        elif isinstance(self.underlayer, IPv6):
            return self.underlayer.sprintf("UDP %IPv6.src%:%UDP.sport% > %IPv6.dst%:%UDP.dport%")
        else:
            return self.sprintf("UDP %UDP.sport% > %UDP.dport%")    

icmptypes = { 0 : "echo-reply",
              3 : "dest-unreach",
              4 : "source-quench",
              5 : "redirect",
              8 : "echo-request",
              9 : "router-advertisement",
              10 : "router-solicitation",
              11 : "time-exceeded",
              12 : "parameter-problem",
              13 : "timestamp-request",
              14 : "timestamp-reply",
              15 : "information-request",
              16 : "information-response",
              17 : "address-mask-request",
              18 : "address-mask-reply" }

class ICMP(Packet):
    name = "ICMP"
    fields_desc = [ ByteEnumField("type",8, icmptypes),
                    ByteField("code",0),
                    XShortField("chksum", None),
                    XShortField("id",0),
                    XShortField("seq",0) ]
    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p
    
    def hashret(self):
        return struct.pack("HH",self.id,self.seq)+self.payload.hashret()
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if ( (other.type,self.type) in [(8,0),(13,14),(15,16),(17,18)] and
             self.id == other.id and
             self.seq == other.seq ):
            return 1
        return 0

    def guess_payload_class(self, payload):
        if self.type in [3,4,5,11,12]:
            return IPerror
        else:
            return None
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("ICMP %IP.src% > %IP.dst% %ICMP.type% %ICMP.code%")
        else:
            return self.sprintf("ICMP %ICMP.type% %ICMP.code%")
    
        



class IPerror(IP):
    name = "IP in ICMP"
    def answers(self, other):
        if not isinstance(other, IP):
            return 0
        if not ( ((conf.checkIPsrc == 0) or (self.dst == other.dst)) and
                 (self.src == other.src) and
                 ( ((conf.checkIPID == 0)
                    or (self.id == other.id)
                    or (conf.checkIPID == 1 and self.id == socket.htons(other.id)))) and
                 (self.proto == other.proto) ):
            return 0
        return self.payload.answers(other.payload)
    def mysummary(self):
        return Packet.mysummary(self)


class TCPerror(TCP):
    name = "TCP in ICMP"
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        if conf.check_TCPerror_seqack:
            if self.seq is not None:
                if self.seq != other.seq:
                    return 0
            if self.ack is not None:
                if self.ack != other.ack:
                    return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)


class UDPerror(UDP):
    name = "UDP in ICMP"
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)

                    

class ICMPerror(ICMP):
    name = "ICMP in ICMP"
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if not ((self.type == other.type) and
                (self.code == other.code)):
            return 0
        if self.code in [0,8,13,14,17,18]:
            if (self.id == other.id and
                self.seq == other.seq):
                return 1
            else:
                return 0
        else:
            return 1
    def mysummary(self):
        return Packet.mysummary(self)

class IPv6(Packet):
    """See http://namabiiru.hongo.wide.ad.jp/scapy6"""
    name = "IPv6 not implemented here." 
    def __init__(self, *args, **kargs):
        log_interactive.error(self.name)
    def __repr__(self):
        return "<IPv6: ERROR not implemented>"
    
class _IPv6OptionHeader(Packet):
    """See http://namabiiru.hongo.wide.ad.jp/scapy6"""
    name = "IPv6 not implemented here."
    def __init__(self, *args, **kargs):
        log_interactive.error(self.name)
    def __repr__(self):
        return "<IPv6: ERROR not implemented>"
                
class PPP(Packet):
    name = "PPP Link Layer"
    fields_desc = [ ShortEnumField("proto", 0x0021, {0x0021: "IP",
                                                     0xc021: "LCP"} ) ]
            
        
class DNS(Packet):
    name = "DNS"
    fields_desc = [ ShortField("id",0),
                    BitField("qr",0, 1),
                    BitEnumField("opcode", 0, 4, {0:"QUERY",1:"IQUERY",2:"STATUS"}),
                    BitField("aa", 0, 1),
                    BitField("tc", 0, 1),
                    BitField("rd", 0, 1),
                    BitField("ra", 0 ,1),
                    BitField("z", 0, 3),
                    BitEnumField("rcode", 0, 4, {0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"}),
                    DNSRRCountField("qdcount", None, "qd"),
                    DNSRRCountField("ancount", None, "an"),
                    DNSRRCountField("nscount", None, "ns"),
                    DNSRRCountField("arcount", None, "ar"),
                    DNSQRField("qd", "qdcount"),
                    DNSRRField("an", "ancount"),
                    DNSRRField("ns", "nscount"),
                    DNSRRField("ar", "arcount",0) ]
    def answers(self, other):
        return (isinstance(other, DNS)
                and self.id == other.id
                and self.qr == 1
                and other.qr == 0)
        
    def mysummary(self):
        type = ["Qry","Ans"][self.qr]
        name = ""
        if self.qr:
            type = "Ans"
            if self.ancount > 0 and isinstance(self.an, DNSRR):
                name = ' "%s"' % self.an.rdata
        else:
            type = "Qry"
            if self.qdcount > 0 and isinstance(self.qd, DNSQR):
                name = ' "%s"' % self.qd.qname
        return 'DNS %s%s ' % (type, name)

dnstypes = { 0:"ANY", 255:"ALL",
             1:"A", 2:"NS", 3:"MD", 4:"MD", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG",
             9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT",
             17:"RP",18:"AFSDB",28:"AAAA", 33:"SRV",38:"A6",39:"DNAME"}

dnsqtypes = {251:"IXFR",252:"AXFR",253:"MAILB",254:"MAILA",255:"ALL"}
dnsqtypes.update(dnstypes)
dnsclasses =  {1: 'IN',  2: 'CS',  3: 'CH',  4: 'HS',  255: 'ANY'}


class DNSQR(Packet):
    name = "DNS Question Record"
    show_indent=0
    fields_desc = [ DNSStrField("qname",""),
                    ShortEnumField("qtype", 1, dnsqtypes),
                    ShortEnumField("qclass", 1, dnsclasses) ]
                    
                    

class DNSRR(Packet):
    name = "DNS Resource Record"
    show_indent=0
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 1, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    RDLenField("rdlen"),
                    RDataField("rdata", "", length_from=lambda pkt:pkt.rdlen) ]

dhcpmagic="c\x82Sc"


class BOOTP(Packet):
    name = "BOOTP"
    fields_desc = [ ByteEnumField("op",1, {1:"BOOTREQUEST", 2:"BOOTREPLY"}),
                    ByteField("htype",1),
                    ByteField("hlen",6),
                    ByteField("hops",0),
                    IntField("xid",0),
                    ShortField("secs",0),
                    FlagsField("flags", 0, 16, "???????????????B"),
                    IPField("ciaddr","0.0.0.0"),
                    IPField("yiaddr","0.0.0.0"),
                    IPField("siaddr","0.0.0.0"),
                    IPField("giaddr","0.0.0.0"),
                    Field("chaddr","", "16s"),
                    Field("sname","","64s"),
                    Field("file","","128s"),
                    StrField("options","") ]
    def guess_payload_class(self, payload):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            return DHCP
        else:
            return Packet.guess_payload_class(self, payload)
    def extract_padding(self,s):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            # set BOOTP options to DHCP magic cookie and make rest a payload of DHCP options
            payload = self.options[len(dhcpmagic):]
            self.options = self.options[:len(dhcpmagic)]
            return payload, None
        else:
            return "", None
    def hashret(self):
        return struct.pack("L", self.xid)
    def answers(self, other):
        if not isinstance(other, BOOTP):
            return 0
        return self.xid == other.xid



#DHCP_UNKNOWN, DHCP_IP, DHCP_IPLIST, DHCP_TYPE \
#= range(4)
#

DHCPTypes = {
                1: "discover",
                2: "offer",
                3: "request",
                4: "decline",
                5: "ack",
                6: "nak",
                7: "release",
                8: "inform",
                9: "force_renew",
                10:"lease_query",
                11:"lease_unassigned",
                12:"lease_unknown",
                13:"lease_active",
                }

DHCPOptions = {
    0: "pad",
    1: IPField("subnet_mask", "0.0.0.0"),
    2: "time_zone",
    3: IPField("router","0.0.0.0"),
    4: IPField("time_server","0.0.0.0"),
    5: IPField("IEN_name_server","0.0.0.0"),
    6: IPField("name_server","0.0.0.0"),
    7: IPField("log_server","0.0.0.0"),
    8: IPField("cookie_server","0.0.0.0"),
    9: IPField("lpr_server","0.0.0.0"),
    12: "hostname",
    14: "dump_path",
    15: "domain",
    17: "root_disk_path",
    22: "max_dgram_reass_size",
    23: "default_ttl",
    24: "pmtu_timeout",
    28: IPField("broadcast_address","0.0.0.0"),
    35: "arp_cache_timeout",
    36: "ether_or_dot3",
    37: "tcp_ttl",
    38: "tcp_keepalive_interval",
    39: "tcp_keepalive_garbage",
    40: "NIS_domain",
    41: IPField("NIS_server","0.0.0.0"),
    42: IPField("NTP_server","0.0.0.0"),
    43: "vendor_specific",
    44: IPField("NetBIOS_server","0.0.0.0"),
    45: IPField("NetBIOS_dist_server","0.0.0.0"),
    50: IPField("requested_addr","0.0.0.0"),
    51: IntField("lease_time", 43200),
    54: IPField("server_id","0.0.0.0"),
    55: "param_req_list",
    57: ShortField("max_dhcp_size", 1500),
    58: IntField("renewal_time", 21600),
    59: IntField("rebinding_time", 37800),
    60: "vendor_class_id",
    61: "client_id",
    
    64: "NISplus_domain",
    65: IPField("NISplus_server","0.0.0.0"),
    69: IPField("SMTP_server","0.0.0.0"),
    70: IPField("POP3_server","0.0.0.0"),
    71: IPField("NNTP_server","0.0.0.0"),
    72: IPField("WWW_server","0.0.0.0"),
    73: IPField("Finger_server","0.0.0.0"),
    74: IPField("IRC_server","0.0.0.0"),
    75: IPField("StreetTalk_server","0.0.0.0"),
    76: "StreetTalk_Dir_Assistance",
    82: "relay_agent_Information",
    53: ByteEnumField("message-type", 1, DHCPTypes),
    #             55: DHCPRequestListField("request-list"),
    255: "end"
    }

DHCPRevOptions = {}

for k,v in DHCPOptions.iteritems():
    if type(v) is str:
        n = v
        v = None
    else:
        n = v.name
    DHCPRevOptions[n] = (k,v)
del(n)
del(v)
del(k)
    
    



class DHCPOptionsField(StrField):
    islist=1
    def i2repr(self,pkt,x):
        s = []
        for v in x:
            if type(v) is tuple and len(v) == 2:
                if  DHCPRevOptions.has_key(v[0]) and isinstance(DHCPRevOptions[v[0]][1],Field):
                    f = DHCPRevOptions[v[0]][1]
                    vv = f.i2repr(pkt,v[1])
                else:
                    vv = repr(v[1])
                s.append("%s=%s" % (v[0],vv))
            else:
                s.append(str(v))
        return "[%s]" % (" ".join(s))
        
    def getfield(self, pkt, s):
        return "", self.m2i(pkt, s)
    def m2i(self, pkt, x):
        opt = []
        while x:
            o = ord(x[0])
            if o == 255:
                opt.append("end")
                x = x[1:]
                continue
            if o == 0:
                opt.append("pad")
                x = x[1:]
                continue
            if DHCPOptions.has_key(o):
                f = DHCPOptions[o]

                if isinstance(f, str):
                    olen = ord(x[1])
                    opt.append( (f,x[2:olen+2]) )
                    x = x[olen+2:]
                else:
                    olen = ord(x[1])
                    left, val = f.getfield(pkt,x[2:olen+2])
#                    val = f.m2i(pkt,val)
#                    if left:
#                        print "m2i data left left=%s" % left
                    opt.append((f.name, val))
                    x = x[olen+2:]
            else:
                olen = ord(x[1])
                opt.append((o, x[2:olen+2]))
                x = x[olen+2:]
        return opt
    def i2m(self, pkt, x):
        #print "i2m x=%s" % x
        s = ""
        for o in x:
            if type(o) is tuple and len(o) == 2:
                name, val = o

                if isinstance(name, int):
                    onum, oval = name, val
                elif DHCPRevOptions.has_key(name):
                    onum, f = DHCPRevOptions[name]
                    if  f is None:
                        oval = val
                    else:
#                        oval = f.addfield(pkt,"",f.i2m(pkt,f.any2i(pkt,val)))
                        oval = f.addfield(pkt,"",f.any2i(pkt,val))
                        
                else:
                    warning("Unknown field option %s" % name)
                    continue

                s += chr(onum)
                s += chr(len(oval))
                s += oval

            elif (type(o) is str and DHCPRevOptions.has_key(o) and 
                  DHCPRevOptions[o][1] == None):
                s += chr(DHCPRevOptions[o][0])
            elif type(o) is int:
                s += chr(o)
            else:
                warning("Malformed option %s" % o)
        return s


class DHCP(Packet):
    name = "DHCP options"
    fields_desc = [ DHCPOptionsField("options","") ]


class Dot11(Packet):
    name = "802.11"
    fields_desc = [
                    BitField("subtype", 0, 4),
                    BitEnumField("type", 0, 2, ["Management", "Control", "Data", "Reserved"]),
                    BitField("proto", 0, 2),
                    FlagsField("FCfield", 0, 8, ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]),
                    ShortField("ID",0),
                    MACField("addr1", ETHER_ANY),
                    Dot11Addr2MACField("addr2", ETHER_ANY),
                    Dot11Addr3MACField("addr3", ETHER_ANY),
                    Dot11SCField("SC", 0),
                    Dot11Addr4MACField("addr4", ETHER_ANY) 
                    ]
    def mysummary(self):
        return self.sprintf("802.11 %Dot11.type% %Dot11.subtype% %Dot11.addr2% > %Dot11.addr1%")
    def guess_payload_class(self, payload):
        if self.type == 0x02 and (self.subtype >= 0x08 and self.subtype <=0xF and self.subtype != 0xD):
            return Dot11QoS
        elif self.FCfield & 0x40:
            return Dot11WEP
        else:
            return Packet.guess_payload_class(self, payload)
    def answers(self, other):
        if isinstance(other,Dot11):
            if self.type == 0: # management
                if self.addr1.lower() != other.addr2.lower(): # check resp DA w/ req SA
                    return 0
                if (other.subtype,self.subtype) in [(0,1),(2,3),(4,5)]:
                    return 1
                if self.subtype == other.subtype == 11: # auth
                    return self.payload.answers(other.payload)
            elif self.type == 1: # control
                return 0
            elif self.type == 2: # data
                return self.payload.answers(other.payload)
            elif self.type == 3: # reserved
                return 0
        return 0
    def unwep(self, key=None, warn=1):
        if self.FCfield & 0x40 == 0:
            if warn:
                warning("No WEP to remove")
            return
        if  isinstance(self.payload.payload, NoPayload):
            if key or conf.wepkey:
                self.payload.decrypt(key)
            if isinstance(self.payload.payload, NoPayload):
                if warn:
                    warning("Dot11 can't be decrypted. Check conf.wepkey.")
                return
        self.FCfield &= ~0x40
        self.payload=self.payload.payload


class Dot11QoS(Packet):
    name = "802.11 QoS"
    fields_desc = [ BitField("TID",None,4),
                    BitField("EOSP",None,1),
                    BitField("Ack Policy",None,2),
                    BitField("Reserved",None,1),
                    ByteField("TXOP",None) ]
    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, Dot11):
            if self.underlayer.FCfield & 0x40:
                return Dot11WEP
        return Packet.guess_payload_class(self, payload)


capability_list = [ "res8", "res9", "short-slot", "res11",
                    "res12", "DSSS-OFDM", "res14", "res15",
                   "ESS", "IBSS", "CFP", "CFP-req",
                   "privacy", "short-preamble", "PBCC", "agility"]

reason_code = {0:"reserved",1:"unspec", 2:"auth-expired",
               3:"deauth-ST-leaving",
               4:"inactivity", 5:"AP-full", 6:"class2-from-nonauth",
               7:"class3-from-nonass", 8:"disas-ST-leaving",
               9:"ST-not-auth"}

status_code = {0:"success", 1:"failure", 10:"cannot-support-all-cap",
               11:"inexist-asso", 12:"asso-denied", 13:"algo-unsupported",
               14:"bad-seq-num", 15:"challenge-failure",
               16:"timeout", 17:"AP-full",18:"rate-unsupported" }

class Dot11Beacon(Packet):
    name = "802.11 Beacon"
    fields_desc = [ LELongField("timestamp", 0),
                    LEShortField("beacon_interval", 0x0064),
                    FlagsField("cap", 0, 16, capability_list) ]
    

class Dot11Elt(Packet):
    name = "802.11 Information Element"
    fields_desc = [ ByteEnumField("ID", 0, {0:"SSID", 1:"Rates", 2: "FHset", 3:"DSset", 4:"CFset", 5:"TIM", 6:"IBSSset", 16:"challenge",
                                            42:"ERPinfo", 46:"QoS Capability", 47:"ERPinfo", 48:"RSNinfo", 50:"ESRates",221:"vendor",68:"reserved"}),
                    FieldLenField("len", None, "info", "B"),
                    StrLenField("info", "", length_from=lambda x:x.len) ]
    def mysummary(self):
        if self.ID == 0:
            return "SSID=%s"%repr(self.info),[Dot11]
        else:
            return ""

class Dot11ATIM(Packet):
    name = "802.11 ATIM"

class Dot11Disas(Packet):
    name = "802.11 Disassociation"
    fields_desc = [ LEShortEnumField("reason", 1, reason_code) ]

class Dot11AssoReq(Packet):
    name = "802.11 Association Request"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    LEShortField("listen_interval", 0x00c8) ]


class Dot11AssoResp(Packet):
    name = "802.11 Association Response"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    LEShortField("status", 0),
                    LEShortField("AID", 0) ]

class Dot11ReassoReq(Packet):
    name = "802.11 Reassociation Request"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    MACField("current_AP", ETHER_ANY),
                    LEShortField("listen_interval", 0x00c8) ]


class Dot11ReassoResp(Dot11AssoResp):
    name = "802.11 Reassociation Response"

class Dot11ProbeReq(Packet):
    name = "802.11 Probe Request"
    
class Dot11ProbeResp(Packet):
    name = "802.11 Probe Response"
    fields_desc = [ LELongField("timestamp", 0),
                    LEShortField("beacon_interval", 0x0064),
                    FlagsField("cap", 0, 16, capability_list) ]
    
class Dot11Auth(Packet):
    name = "802.11 Authentication"
    fields_desc = [ LEShortEnumField("algo", 0, ["open", "sharedkey"]),
                    LEShortField("seqnum", 0),
                    LEShortEnumField("status", 0, status_code) ]
    def answers(self, other):
        if self.seqnum == other.seqnum+1:
            return 1
        return 0

class Dot11Deauth(Packet):
    name = "802.11 Deauthentication"
    fields_desc = [ LEShortEnumField("reason", 1, reason_code) ]



class Dot11WEP(Packet):
    name = "802.11 WEP packet"
    fields_desc = [ StrFixedLenField("iv", "\0\0\0", 3),
                    ByteField("keyid", 0),
                    StrField("wepdata",None,remain=4),
                    IntField("icv",None) ]

    def post_dissect(self, s):
#        self.icv, = struct.unpack("!I",self.wepdata[-4:])
#        self.wepdata = self.wepdata[:-4]
        self.decrypt()

    def build_payload(self):
        if self.wepdata is None:
            return Packet.build_payload(self)
        return ""

    def post_build(self, p, pay):
        if self.wepdata is None:
            key = conf.wepkey
            if key:
                if self.icv is None:
                    pay += struct.pack("<I",crc32(pay))
                    icv = ""
                else:
                    icv = p[4:8]
                c = ARC4.new(self.iv+key)
                p = p[:4]+c.encrypt(pay)+icv
            else:
                warning("No WEP key set (conf.wepkey).. strange results expected..")
        return p
            

    def decrypt(self,key=None):
        if key is None:
            key = conf.wepkey
        if key:
            c = ARC4.new(self.iv+key)
            self.add_payload(LLC(c.decrypt(self.wepdata)))
                    


class PrismHeader(Packet):
    """ iwpriv wlan0 monitor 3 """
    name = "Prism header"
    fields_desc = [ LEIntField("msgcode",68),
                    LEIntField("len",144),
                    StrFixedLenField("dev","",16),
                    LEIntField("hosttime_did",0),
                  LEShortField("hosttime_status",0),
                  LEShortField("hosttime_len",0),
                    LEIntField("hosttime",0),
                    LEIntField("mactime_did",0),
                  LEShortField("mactime_status",0),
                  LEShortField("mactime_len",0),
                    LEIntField("mactime",0),
                    LEIntField("channel_did",0),
                  LEShortField("channel_status",0),
                  LEShortField("channel_len",0),
                    LEIntField("channel",0),
                    LEIntField("rssi_did",0),
                  LEShortField("rssi_status",0),
                  LEShortField("rssi_len",0),
                    LEIntField("rssi",0),
                    LEIntField("sq_did",0),
                  LEShortField("sq_status",0),
                  LEShortField("sq_len",0),
                    LEIntField("sq",0),
                    LEIntField("signal_did",0),
                  LEShortField("signal_status",0),
                  LEShortField("signal_len",0),
              LESignedIntField("signal",0),
                    LEIntField("noise_did",0),
                  LEShortField("noise_status",0),
                  LEShortField("noise_len",0),
                    LEIntField("noise",0),
                    LEIntField("rate_did",0),
                  LEShortField("rate_status",0),
                  LEShortField("rate_len",0),
                    LEIntField("rate",0),
                    LEIntField("istx_did",0),
                  LEShortField("istx_status",0),
                  LEShortField("istx_len",0),
                    LEIntField("istx",0),
                    LEIntField("frmlen_did",0),
                  LEShortField("frmlen_status",0),
                  LEShortField("frmlen_len",0),
                    LEIntField("frmlen",0),
                    ]
    def answers(self, other):
        if isinstance(other, PrismHeader):
            return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)



class HSRP(Packet):
    name = "HSRP"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0, { 0:"Hello"}),
        ByteEnumField("state", 16, { 16:"Active"}),
        ByteField("hellotime", 3),
        ByteField("holdtime", 10),
        ByteField("priority", 120),
        ByteField("group", 1),
        ByteField("reserved", 0),
        StrFixedLenField("auth","cisco",8),
        IPField("virtualIP","192.168.1.1") ]
        


        
        


class NTP(Packet):
    # RFC 1769
    name = "NTP"
    fields_desc = [ 
         BitEnumField('leap', 0, 2,
                      { 0: 'nowarning',
                        1: 'longminute',
                        2: 'shortminute',
                        3: 'notsync'}),
         BitField('version', 3, 3),
         BitEnumField('mode', 3, 3,
                      { 0: 'reserved',
                        1: 'sym_active',
                        2: 'sym_passive',
                        3: 'client',
                        4: 'server',
                        5: 'broadcast',
                        6: 'control',
                        7: 'private'}),
         BitField('stratum', 2, 8),
         BitField('poll', 0xa, 8),          ### XXX : it's a signed int
         BitField('precision', 0, 8),       ### XXX : it's a signed int
         FloatField('delay', 0, 32),
         FloatField('dispersion', 0, 32),
         IPField('id', "127.0.0.1"),
         TimeStampField('ref', 0, 64),
         TimeStampField('orig', -1, 64),  # -1 means current time
         TimeStampField('recv', 0, 64),
         TimeStampField('sent', -1, 64) 
         ]
    def mysummary(self):
        return self.sprintf("NTP v%ir,NTP.version%, %NTP.mode%")


class GRE(Packet):
    name = "GRE"
    fields_desc = [ BitField("chksumpresent",0,1),
                    BitField("reserved0",0,12),
                    BitField("version",0,3),
                    XShortEnumField("proto", 0x0000, ETHER_TYPES),
                    ConditionalField(XShortField("chksum",None),lambda pkt:pkt.chksumpresent==1),
                    ConditionalField(XShortField("reserved1",None),lambda pkt:pkt.chksumpresent==1),
                    ]
    def post_build(self, p, pay):
        p += pay
        if self.chksumpresent and self.chksum is None:
            c = checksum(p)
            p = p[:4]+chr((c>>8)&0xff)+chr(c&0xff)+p[6:]
        return p
            

class Radius(Packet):
    name = "Radius"
    fields_desc = [ ByteEnumField("code", 1, {1: "Access-Request",
                                              2: "Access-Accept",
                                              3: "Access-Reject",
                                              4: "Accounting-Request",
                                              5: "Accounting-Accept",
                                              6: "Accounting-Status",
                                              7: "Password-Request",
                                              8: "Password-Ack",
                                              9: "Password-Reject",
                                              10: "Accounting-Message",
                                              11: "Access-Challenge",
                                              12: "Status-Server",
                                              13: "Status-Client",
                                              21: "Resource-Free-Request",
                                              22: "Resource-Free-Response",
                                              23: "Resource-Query-Request",
                                              24: "Resource-Query-Response",
                                              25: "Alternate-Resource-Reclaim-Request",
                                              26: "NAS-Reboot-Request",
                                              27: "NAS-Reboot-Response",
                                              29: "Next-Passcode",
                                              30: "New-Pin",
                                              31: "Terminate-Session",
                                              32: "Password-Expired",
                                              33: "Event-Request",
                                              34: "Event-Response",
                                              40: "Disconnect-Request",
                                              41: "Disconnect-ACK",
                                              42: "Disconnect-NAK",
                                              43: "CoA-Request",
                                              44: "CoA-ACK",
                                              45: "CoA-NAK",
                                              50: "IP-Address-Allocate",
                                              51: "IP-Address-Release",
                                              253: "Experimental-use",
                                              254: "Reserved",
                                              255: "Reserved"} ),
                    ByteField("id", 0),
                    ShortField("len", None),
                    StrFixedLenField("authenticator","",16) ]
    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:2]+struct.pack("!H",l)+p[4:]
        return p




class RIP(Packet):
    name = "RIP header"
    fields_desc = [
        ByteEnumField("command",1,{1:"req",2:"resp",3:"traceOn",4:"traceOff",5:"sun",
                                   6:"trigReq",7:"trigResp",8:"trigAck",9:"updateReq",
                                   10:"updateResp",11:"updateAck"}),
        ByteField("version",1),
        ShortField("null",0),
        ]

class RIPEntry(Packet):
    name = "RIP entry"
    fields_desc = [
        ShortEnumField("AF",2,{2:"IP"}),
        ShortField("RouteTag",0),
        IPField("addr","0.0.0.0"),
        IPField("mask","0.0.0.0"),
        IPField("nextHop","0.0.0.0"),
        IntEnumField("metric",1,{16:"Unreach"}),
        ]
        



ISAKMP_payload_type = ["None","SA","Proposal","Transform","KE","ID","CERT","CR","Hash",
                       "SIG","Nonce","Notification","Delete","VendorID"]

ISAKMP_exchange_type = ["None","base","identity prot.",
                        "auth only", "aggressive", "info"]


class ISAKMP_class(Packet):
    def guess_payload_class(self, payload):
        np = self.next_payload
        if np == 0:
            return Raw
        elif np < len(ISAKMP_payload_type):
            pt = ISAKMP_payload_type[np]
            return globals().get("ISAKMP_payload_%s" % pt, ISAKMP_payload)
        else:
            return ISAKMP_payload


class ISAKMP(ISAKMP_class): # rfc2408
    name = "ISAKMP"
    fields_desc = [
        StrFixedLenField("init_cookie","",8),
        StrFixedLenField("resp_cookie","",8),
        ByteEnumField("next_payload",0,ISAKMP_payload_type),
        XByteField("version",0x10),
        ByteEnumField("exch_type",0,ISAKMP_exchange_type),
        FlagsField("flags",0, 8, ["encryption","commit","auth_only","res3","res4","res5","res6","res7"]), # XXX use a Flag field
        IntField("id",0),
        IntField("length",None)
        ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return Raw
        return ISAKMP_class.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, ISAKMP):
            if other.init_cookie == self.init_cookie:
                return 1
        return 0
    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = p[:24]+struct.pack("!I",len(p))+p[28:]
        return p
       



class ISAKMP_payload_Transform(ISAKMP_class):
    name = "IKE Transform"
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
#        ShortField("len",None),
        ShortField("length",None),
        ByteField("num",None),
        ByteEnumField("id",1,{1:"KEY_IKE"}),
        ShortField("res2",0),
        ISAKMPTransformSetField("transforms",None,length_from=lambda x:x.length-8)
#        XIntField("enc",0x80010005L),
#        XIntField("hash",0x80020002L),
#        XIntField("auth",0x80030001L),
#        XIntField("group",0x80040002L),
#        XIntField("life_type",0x800b0001L),
#        XIntField("durationh",0x000c0004L),
#        XIntField("durationl",0x00007080L),
        ]
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        p += pay
        return p
            


        
class ISAKMP_payload_Proposal(ISAKMP_class):
    name = "IKE proposal"
#    ISAKMP_payload_type = 0
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"trans","H", adjust=lambda pkt,x:x+8),
        ByteField("proposal",1),
        ByteEnumField("proto",1,{1:"ISAKMP"}),
        FieldLenField("SPIsize",None,"SPI","B"),
        ByteField("trans_nb",None),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        PacketLenField("trans",Raw(),ISAKMP_payload_Transform,length_from=lambda x:x.length-8),
        ]


class ISAKMP_payload(ISAKMP_class):
    name = "ISAKMP payload"
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]


class ISAKMP_payload_VendorID(ISAKMP_class):
    name = "ISAKMP Vendor ID"
    overload_fields = { ISAKMP: { "next_payload":13 }}
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"vendorID","H", adjust=lambda pkt,x:x+4),
        StrLenField("vendorID","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_SA(ISAKMP_class):
    name = "ISAKMP SA"
    overload_fields = { ISAKMP: { "next_payload":1 }}
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"prop","H", adjust=lambda pkt,x:x+12),
        IntEnumField("DOI",1,{1:"IPSEC"}),
        IntEnumField("situation",1,{1:"identity"}),
        PacketLenField("prop",Raw(),ISAKMP_payload_Proposal,length_from=lambda x:x.length-12),
        ]

class ISAKMP_payload_Nonce(ISAKMP_class):
    name = "ISAKMP Nonce"
    overload_fields = { ISAKMP: { "next_payload":10 }}
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_KE(ISAKMP_class):
    name = "ISAKMP Key Exchange"
    overload_fields = { ISAKMP: { "next_payload":4 }}
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_ID(ISAKMP_class):
    name = "ISAKMP Identification"
    overload_fields = { ISAKMP: { "next_payload":5 }}
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+8),
        ByteEnumField("IDtype",1,{1:"IPv4_addr", 11:"Key"}),
        ByteEnumField("ProtoID",0,{0:"Unused"}),
        ShortEnumField("Port",0,{0:"Unused"}),
#        IPField("IdentData","127.0.0.1"),
        StrLenField("load","",length_from=lambda x:x.length-8),
        ]



class ISAKMP_payload_Hash(ISAKMP_class):
    name = "ISAKMP Hash"
    overload_fields = { ISAKMP: { "next_payload":8 }}
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]



ISAKMP_payload_type_overload = {}
for i in range(len(ISAKMP_payload_type)):
    name = "ISAKMP_payload_%s" % ISAKMP_payload_type[i]
    if name in globals():
        ISAKMP_payload_type_overload[globals()[name]] = {"next_payload":i}

del(i)
del(name)
ISAKMP_class.overload_fields = ISAKMP_payload_type_overload.copy()


        

# Cisco Skinny protocol

# shamelessly ripped from Ethereal dissector
skinny_messages = { 
# Station -> Callmanager
  0x0000: "KeepAliveMessage",
  0x0001: "RegisterMessage",
  0x0002: "IpPortMessage",
  0x0003: "KeypadButtonMessage",
  0x0004: "EnblocCallMessage",
  0x0005: "StimulusMessage",
  0x0006: "OffHookMessage",
  0x0007: "OnHookMessage",
  0x0008: "HookFlashMessage",
  0x0009: "ForwardStatReqMessage",
  0x000A: "SpeedDialStatReqMessage",
  0x000B: "LineStatReqMessage",
  0x000C: "ConfigStatReqMessage",
  0x000D: "TimeDateReqMessage",
  0x000E: "ButtonTemplateReqMessage",
  0x000F: "VersionReqMessage",
  0x0010: "CapabilitiesResMessage",
  0x0011: "MediaPortListMessage",
  0x0012: "ServerReqMessage",
  0x0020: "AlarmMessage",
  0x0021: "MulticastMediaReceptionAck",
  0x0022: "OpenReceiveChannelAck",
  0x0023: "ConnectionStatisticsRes",
  0x0024: "OffHookWithCgpnMessage",
  0x0025: "SoftKeySetReqMessage",
  0x0026: "SoftKeyEventMessage",
  0x0027: "UnregisterMessage",
  0x0028: "SoftKeyTemplateReqMessage",
  0x0029: "RegisterTokenReq",
  0x002A: "MediaTransmissionFailure",
  0x002B: "HeadsetStatusMessage",
  0x002C: "MediaResourceNotification",
  0x002D: "RegisterAvailableLinesMessage",
  0x002E: "DeviceToUserDataMessage",
  0x002F: "DeviceToUserDataResponseMessage",
  0x0030: "UpdateCapabilitiesMessage",
  0x0031: "OpenMultiMediaReceiveChannelAckMessage",
  0x0032: "ClearConferenceMessage",
  0x0033: "ServiceURLStatReqMessage",
  0x0034: "FeatureStatReqMessage",
  0x0035: "CreateConferenceResMessage",
  0x0036: "DeleteConferenceResMessage",
  0x0037: "ModifyConferenceResMessage",
  0x0038: "AddParticipantResMessage",
  0x0039: "AuditConferenceResMessage",
  0x0040: "AuditParticipantResMessage",
  0x0041: "DeviceToUserDataVersion1Message",
# Callmanager -> Station */
  0x0081: "RegisterAckMessage",
  0x0082: "StartToneMessage",
  0x0083: "StopToneMessage",
  0x0085: "SetRingerMessage",
  0x0086: "SetLampMessage",
  0x0087: "SetHkFDetectMessage",
  0x0088: "SetSpeakerModeMessage",
  0x0089: "SetMicroModeMessage",
  0x008A: "StartMediaTransmission",
  0x008B: "StopMediaTransmission",
  0x008C: "StartMediaReception",
  0x008D: "StopMediaReception",
  0x008F: "CallInfoMessage",
  0x0090: "ForwardStatMessage",
  0x0091: "SpeedDialStatMessage",
  0x0092: "LineStatMessage",
  0x0093: "ConfigStatMessage",
  0x0094: "DefineTimeDate",
  0x0095: "StartSessionTransmission",
  0x0096: "StopSessionTransmission",
  0x0097: "ButtonTemplateMessage",
  0x0098: "VersionMessage",
  0x0099: "DisplayTextMessage",
  0x009A: "ClearDisplay",
  0x009B: "CapabilitiesReqMessage",
  0x009C: "EnunciatorCommandMessage",
  0x009D: "RegisterRejectMessage",
  0x009E: "ServerResMessage",
  0x009F: "Reset",
  0x0100: "KeepAliveAckMessage",
  0x0101: "StartMulticastMediaReception",
  0x0102: "StartMulticastMediaTransmission",
  0x0103: "StopMulticastMediaReception",
  0x0104: "StopMulticastMediaTransmission",
  0x0105: "OpenReceiveChannel",
  0x0106: "CloseReceiveChannel",
  0x0107: "ConnectionStatisticsReq",
  0x0108: "SoftKeyTemplateResMessage",
  0x0109: "SoftKeySetResMessage",
  0x0110: "SelectSoftKeysMessage",
  0x0111: "CallStateMessage",
  0x0112: "DisplayPromptStatusMessage",
  0x0113: "ClearPromptStatusMessage",
  0x0114: "DisplayNotifyMessage",
  0x0115: "ClearNotifyMessage",
  0x0116: "ActivateCallPlaneMessage",
  0x0117: "DeactivateCallPlaneMessage",
  0x0118: "UnregisterAckMessage",
  0x0119: "BackSpaceReqMessage",
  0x011A: "RegisterTokenAck",
  0x011B: "RegisterTokenReject",
  0x0042: "DeviceToUserDataResponseVersion1Message",
  0x011C: "StartMediaFailureDetection",
  0x011D: "DialedNumberMessage",
  0x011E: "UserToDeviceDataMessage",
  0x011F: "FeatureStatMessage",
  0x0120: "DisplayPriNotifyMessage",
  0x0121: "ClearPriNotifyMessage",
  0x0122: "StartAnnouncementMessage",
  0x0123: "StopAnnouncementMessage",
  0x0124: "AnnouncementFinishMessage",
  0x0127: "NotifyDtmfToneMessage",
  0x0128: "SendDtmfToneMessage",
  0x0129: "SubscribeDtmfPayloadReqMessage",
  0x012A: "SubscribeDtmfPayloadResMessage",
  0x012B: "SubscribeDtmfPayloadErrMessage",
  0x012C: "UnSubscribeDtmfPayloadReqMessage",
  0x012D: "UnSubscribeDtmfPayloadResMessage",
  0x012E: "UnSubscribeDtmfPayloadErrMessage",
  0x012F: "ServiceURLStatMessage",
  0x0130: "CallSelectStatMessage",
  0x0131: "OpenMultiMediaChannelMessage",
  0x0132: "StartMultiMediaTransmission",
  0x0133: "StopMultiMediaTransmission",
  0x0134: "MiscellaneousCommandMessage",
  0x0135: "FlowControlCommandMessage",
  0x0136: "CloseMultiMediaReceiveChannel",
  0x0137: "CreateConferenceReqMessage",
  0x0138: "DeleteConferenceReqMessage",
  0x0139: "ModifyConferenceReqMessage",
  0x013A: "AddParticipantReqMessage",
  0x013B: "DropParticipantReqMessage",
  0x013C: "AuditConferenceReqMessage",
  0x013D: "AuditParticipantReqMessage",
  0x013F: "UserToDeviceDataVersion1Message",
  }


        
class Skinny(Packet):
    name="Skinny"
    fields_desc = [ LEIntField("len",0),
                    LEIntField("res",0),
                    LEIntEnumField("msg",0,skinny_messages) ]

_rtp_payload_types = {
    # http://www.iana.org/assignments/rtp-parameters
    0:  'G.711 PCMU',    3:  'GSM',
    4:  'G723',    5:  'DVI4',
    6:  'DVI4',    7:  'LPC',
    8:  'PCMA',    9:  'G722',
    10: 'L16',     11: 'L16',
    12: 'QCELP',   13: 'CN',
    14: 'MPA',     15: 'G728',
    16: 'DVI4',    17: 'DVI4',
    18: 'G729',    25: 'CelB',
    26: 'JPEG',    28: 'nv',
    31: 'H261',    32: 'MPV',
    33: 'MP2T',    34: 'H263' }

class RTP(Packet):
    name="RTP"
    fields_desc = [ BitField('version', 2, 2),
                    BitField('padding', 0, 1),
                    BitField('extension', 0, 1),
                    BitFieldLenField('numsync', None, 4, count_of='sync'),
                    BitField('marker', 0, 1),
                    BitEnumField('payload', 0, 7, _rtp_payload_types),
                    ShortField('sequence', 0),
                    IntField('timestamp', 0),
                    IntField('sourcesync', 0),
                    FieldListField('sync', [], IntField("id",0), count_from=lambda pkt:pkt.numsync) ]
    
### SEBEK


class SebekHead(Packet):
    name = "Sebek header"
    fields_desc = [ XIntField("magic", 0xd0d0d0),
                    ShortField("version", 1),
                    ShortEnumField("type", 0, {"read":0, "write":1,
                                             "socket":2, "open":3}),
                    IntField("counter", 0),
                    IntField("time_sec", 0),
                    IntField("time_usec", 0) ]
    def mysummary(self):
        return self.sprintf("Sebek Header v%SebekHead.version% %SebekHead.type%")

# we need this because Sebek headers differ between v1 and v3, and
# between v3 type socket and v3 others

class SebekV1(Packet):
    name = "Sebek v1"
    fields_desc = [ IntField("pid", 0),
                    IntField("uid", 0),
                    IntField("fd", 0),
                    StrFixedLenField("command", "", 12),
                    FieldLenField("data_length", None, "data",fmt="I"),
                    StrLenField("data", "", length_from=lambda x:x.data_length) ]
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v1 %SebekHead.type% (%SebekV1.command%)")
        else:
            return self.sprintf("Sebek v1 (%SebekV1.command%)")

class SebekV3(Packet):
    name = "Sebek v3"
    fields_desc = [ IntField("parent_pid", 0),
                    IntField("pid", 0),
                    IntField("uid", 0),
                    IntField("fd", 0),
                    IntField("inode", 0),
                    StrFixedLenField("command", "", 12),
                    FieldLenField("data_length", None, "data",fmt="I"),
                    StrLenField("data", "", length_from=lambda x:x.data_length) ]
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV3.command%)")
        else:
            return self.sprintf("Sebek v3 (%SebekV3.command%)")

class SebekV2(SebekV3):
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV2.command%)")
        else:
            return self.sprintf("Sebek v2 (%SebekV2.command%)")

class SebekV3Sock(Packet):
    name = "Sebek v2 socket"
    fields_desc = [ IntField("parent_pid", 0),
                    IntField("pid", 0),
                    IntField("uid", 0),
                    IntField("fd", 0),
                    IntField("inode", 0),
                    StrFixedLenField("command", "", 12),
                    IntField("data_length", 15),
                    IPField("dip", "127.0.0.1"),
                    ShortField("dport", 0),
                    IPField("sip", "127.0.0.1"),
                    ShortField("sport", 0),
                    ShortEnumField("call", 0, { "bind":2,
                                                "connect":3, "listen":4,
                                               "accept":5, "sendmsg":16,
                                               "recvmsg":17, "sendto":11,
                                               "recvfrom":12}),
                    ByteEnumField("proto", 0, IP_PROTOS) ]
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV3Sock.command%)")
        else:
            return self.sprintf("Sebek v3 socket (%SebekV3Sock.command%)")

class SebekV2Sock(SebekV3Sock):
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV2Sock.command%)")
        else:
            return self.sprintf("Sebek v2 socket (%SebekV2Sock.command%)")

class MGCP(Packet):
    name = "MGCP"
    longname = "Media Gateway Control Protocol"
    fields_desc = [ StrStopField("verb","AUEP"," ", -1),
                    StrFixedLenField("sep1"," ",1),
                    StrStopField("transaction_id","1234567"," ", -1),
                    StrFixedLenField("sep2"," ",1),
                    StrStopField("endpoint","dummy@dummy.net"," ", -1),
                    StrFixedLenField("sep3"," ",1),
                    StrStopField("version","MGCP 1.0 NCS 1.0","\x0a", -1),
                    StrFixedLenField("sep4","\x0a",1),
                    ]
                    
    
#class MGCP(Packet):
#    name = "MGCP"
#    longname = "Media Gateway Control Protocol"
#    fields_desc = [ ByteEnumField("type",0, ["request","response","others"]),
#                    ByteField("code0",0),
#                    ByteField("code1",0),
#                    ByteField("code2",0),
#                    ByteField("code3",0),
#                    ByteField("code4",0),
#                    IntField("trasid",0),
#                    IntField("req_time",0),
#                    ByteField("is_duplicate",0),
#                    ByteField("req_available",0) ]
#
class GPRS(Packet):
    name = "GPRSdummy"
    fields_desc = [
        StrStopField("dummy","","\x65\x00\x00",1)
        ]


class HCI_Hdr(Packet):
    name = "HCI header"
    fields_desc = [ ByteEnumField("type",2,{1:"command",2:"ACLdata",3:"SCOdata",4:"event",5:"vendor"}),]

    def mysummary(self):
        return self.sprintf("HCI %type%")

class HCI_ACL_Hdr(Packet):
    name = "HCI ACL header"
    fields_desc = [ ByteField("handle",0), # Actually, handle is 12 bits and flags is 4.
                    ByteField("flags",0),  # I wait to write a LEBitField
                    LEShortField("len",None), ]
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-4
            p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
        return p
                    

class L2CAP_Hdr(Packet):
    name = "L2CAP header"
    fields_desc = [ LEShortField("len",None),
                    LEShortEnumField("cid",0,{1:"control"}),]
    
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-4
            p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
        return p
                    
                

class L2CAP_CmdHdr(Packet):
    name = "L2CAP command header"
    fields_desc = [
        ByteEnumField("code",8,{1:"rej",2:"conn_req",3:"conn_resp",
                                4:"conf_req",5:"conf_resp",6:"disconn_req",
                                7:"disconn_resp",8:"echo_req",9:"echo_resp",
                                10:"info_req",11:"info_resp"}),
        ByteField("id",0),
        LEShortField("len",None) ]
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-4
            p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
        return p
    def answers(self, other):
        if other.id == self.id:
            if self.code == 1:
                return 1
            if other.code in [2,4,6,8,10] and self.code == other.code+1:
                if other.code == 8:
                    return 1
                return self.payload.answers(other.payload)
        return 0

class L2CAP_ConnReq(Packet):
    name = "L2CAP Conn Req"
    fields_desc = [ LEShortEnumField("psm",0,{1:"SDP",3:"RFCOMM",5:"telephony control"}),
                    LEShortField("scid",0),
                    ]

class L2CAP_ConnResp(Packet):
    name = "L2CAP Conn Resp"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("scid",0),
                    LEShortEnumField("result",0,["no_info","authen_pend","author_pend"]),
                    LEShortEnumField("status",0,["success","pend","bad_psm",
                                               "cr_sec_block","cr_no_mem"]),
                    ]
    def answers(self, other):
        return self.scid == other.scid

class L2CAP_CmdRej(Packet):
    name = "L2CAP Command Rej"
    fields_desc = [ LEShortField("reason",0),
                    ]
    

class L2CAP_ConfReq(Packet):
    name = "L2CAP Conf Req"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("flags",0),
                    ]

class L2CAP_ConfResp(Packet):
    name = "L2CAP Conf Resp"
    fields_desc = [ LEShortField("scid",0),
                    LEShortField("flags",0),
                    LEShortEnumField("result",0,["success","unaccept","reject","unknown"]),
                    ]
    def answers(self, other):
        return self.scid == other.scid


class L2CAP_DisconnReq(Packet):
    name = "L2CAP Disconn Req"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("scid",0), ]

class L2CAP_DisconnResp(Packet):
    name = "L2CAP Disconn Resp"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("scid",0), ]
    def answers(self, other):
        return self.scid == other.scid

    

class L2CAP_InfoReq(Packet):
    name = "L2CAP Info Req"
    fields_desc = [ LEShortEnumField("type",0,{1:"CL_MTU",2:"FEAT_MASK"}),
                    StrField("data","")
                    ]


class L2CAP_InfoResp(Packet):
    name = "L2CAP Info Resp"
    fields_desc = [ LEShortField("type",0),
                    LEShortEnumField("result",0,["success","not_supp"]),
                    StrField("data",""), ]
    def answers(self, other):
        return self.type == other.type




class NetBIOS_DS(Packet):
    name = "NetBIOS datagram service"
    fields_desc = [
        ByteEnumField("type",17, {17:"direct_group"}),
        ByteField("flags",0),
        XShortField("id",0),
        IPField("src","127.0.0.1"),
        ShortField("sport",138),
        ShortField("len",None),
        ShortField("ofs",0),
        NetBIOSNameField("srcname",""),
        NetBIOSNameField("dstname",""),
        ]
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-14
            p = p[:10]+struct.pack("!H", l)+p[12:]
        return p
        
#        ShortField("length",0),
#        ShortField("Delimitor",0),
#        ByteField("command",0),
#        ByteField("data1",0),
#        ShortField("data2",0),
#        ShortField("XMIt",0),
#        ShortField("RSPCor",0),
#        StrFixedLenField("dest","",16),
#        StrFixedLenField("source","",16),
#        
#        ]
#

# IR

class IrLAPHead(Packet):
    name = "IrDA Link Access Protocol Header"
    fields_desc = [ XBitField("Address", 0x7f, 7),
                    BitEnumField("Type", 1, 1, {"Response":0,
                                                "Command":1})]

class IrLAPCommand(Packet):
    name = "IrDA Link Access Protocol Command"
    fields_desc = [ XByteField("Control", 0),
                    XByteField("Format identifier", 0),
                    XIntField("Source address", 0),
                    XIntField("Destination address", 0xffffffffL),
                    XByteField("Discovery flags", 0x1),
                    ByteEnumField("Slot number", 255, {"final":255}),
                    XByteField("Version", 0)]


class IrLMP(Packet):
    name = "IrDA Link Management Protocol"
    fields_desc = [ XShortField("Service hints", 0),
                    XByteField("Character set", 0),
                    StrField("Device name", "") ]


#NetBIOS


# Name Query Request
# Node Status Request
class NBNSQueryRequest(Packet):
    name="NBNS query request"
    fields_desc = [ShortField("NAME_TRN_ID",0),
                   ShortField("FLAGS", 0x0110),
                   ShortField("QDCOUNT",1),
                   ShortField("ANCOUNT",0),
                   ShortField("NSCOUNT",0),
                   ShortField("ARCOUNT",0),
                   NetBIOSNameField("QUESTION_NAME","windows"),
                   ShortEnumField("SUFFIX",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                   ByteField("NULL",0),
                   ShortEnumField("QUESTION_TYPE",0x20, {0x20:"NB",0x21:"NBSTAT"}),
                   ShortEnumField("QUESTION_CLASS",1,{1:"INTERNET"})]

# Name Registration Request
# Name Refresh Request
# Name Release Request or Demand
class NBNSRequest(Packet):
    name="NBNS request"
    fields_desc = [ShortField("NAME_TRN_ID",0),
                   ShortField("FLAGS", 0x2910),
                   ShortField("QDCOUNT",1),
                   ShortField("ANCOUNT",0),
                   ShortField("NSCOUNT",0),
                   ShortField("ARCOUNT",1),
                   NetBIOSNameField("QUESTION_NAME","windows"),
                   ShortEnumField("SUFFIX",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                   ByteField("NULL",0),
                   ShortEnumField("QUESTION_TYPE",0x20, {0x20:"NB",0x21:"NBSTAT"}),
                   ShortEnumField("QUESTION_CLASS",1,{1:"INTERNET"}),
                   ShortEnumField("RR_NAME",0xC00C,{0xC00C:"Label String Pointer to QUESTION_NAME"}),
                   ShortEnumField("RR_TYPE",0x20, {0x20:"NB",0x21:"NBSTAT"}),
                   ShortEnumField("RR_CLASS",1,{1:"INTERNET"}),
                   IntField("TTL", 0),
                   ShortField("RDLENGTH", 6),
                   BitEnumField("G",0,1,{0:"Unique name",1:"Group name"}),
                   BitEnumField("OWNER NODE TYPE",00,2,{00:"B node",01:"P node",02:"M node",03:"H node"}),
                   BitEnumField("UNUSED",0,13,{0:"Unused"}),
                   IPField("NB_ADDRESS", "127.0.0.1")]

# Name Query Response
# Name Registration Response
class NBNSQueryResponse(Packet):
    name="NBNS query response"
    fields_desc = [ShortField("NAME_TRN_ID",0),
                   ShortField("FLAGS", 0x8500),
                   ShortField("QDCOUNT",0),
                   ShortField("ANCOUNT",1),
                   ShortField("NSCOUNT",0),
                   ShortField("ARCOUNT",0),
                   NetBIOSNameField("RR_NAME","windows"),
                   ShortEnumField("SUFFIX",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                   ByteField("NULL",0),
                   ShortEnumField("QUESTION_TYPE",0x20, {0x20:"NB",0x21:"NBSTAT"}),
                   ShortEnumField("QUESTION_CLASS",1,{1:"INTERNET"}),
                   IntField("TTL", 0x493e0),
                   ShortField("RDLENGTH", 6),
                   ShortField("NB_FLAGS", 0),
                   IPField("NB_ADDRESS", "127.0.0.1")]

# Name Query Response (negative)
# Name Release Response
class NBNSQueryResponseNegative(Packet):
    name="NBNS query response (negative)"
    fields_desc = [ShortField("NAME_TRN_ID",0), 
                   ShortField("FLAGS", 0x8506),
                   ShortField("QDCOUNT",0),
                   ShortField("ANCOUNT",1),
                   ShortField("NSCOUNT",0),
                   ShortField("ARCOUNT",0),
                   NetBIOSNameField("RR_NAME","windows"),
                   ShortEnumField("SUFFIX",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                   ByteField("NULL",0),
                   ShortEnumField("RR_TYPE",0x20, {0x20:"NB",0x21:"NBSTAT"}),
                   ShortEnumField("RR_CLASS",1,{1:"INTERNET"}),
                   IntField("TTL",0),
                   ShortField("RDLENGTH",6),
                   BitEnumField("G",0,1,{0:"Unique name",1:"Group name"}),
                   BitEnumField("OWNER NODE TYPE",00,2,{00:"B node",01:"P node",02:"M node",03:"H node"}),
                   BitEnumField("UNUSED",0,13,{0:"Unused"}),
                   IPField("NB_ADDRESS", "127.0.0.1")]
    
# Node Status Response
class NBNSNodeStatusResponse(Packet):
    name="NBNS Node Status Response"
    fields_desc = [ShortField("NAME_TRN_ID",0), 
                   ShortField("FLAGS", 0x8500),
                   ShortField("QDCOUNT",0),
                   ShortField("ANCOUNT",1),
                   ShortField("NSCOUNT",0),
                   ShortField("ARCOUNT",0),
                   NetBIOSNameField("RR_NAME","windows"),
                   ShortEnumField("SUFFIX",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                   ByteField("NULL",0),
                   ShortEnumField("RR_TYPE",0x21, {0x20:"NB",0x21:"NBSTAT"}),
                   ShortEnumField("RR_CLASS",1,{1:"INTERNET"}),
                   IntField("TTL",0),
                   ShortField("RDLENGTH",83),
                   ByteField("NUM_NAMES",1)]

# Service for Node Status Response
class NBNSNodeStatusResponseService(Packet):
    name="NBNS Node Status Response Service"
    fields_desc = [StrFixedLenField("NETBIOS_NAME","WINDOWS         ",15),
                   ByteEnumField("SUFFIX",0,{0:"workstation",0x03:"messenger service",0x20:"file server service",0x1b:"domain master browser",0x1c:"domain controller", 0x1e:"browser election service"}),
                   ByteField("NAME_FLAGS",0x4),
                   ByteEnumField("UNUSED",0,{0:"unused"})]

# End of Node Status Response packet
class NBNSNodeStatusResponseEnd(Packet):
    name="NBNS Node Status Response"
    fields_desc = [SourceMACField("MAC_ADDRESS"),
                   BitField("STATISTICS",0,57*8)]

# Wait for Acknowledgement Response
class NBNSWackResponse(Packet):
    name="NBNS Wait for Acknowledgement Response"
    fields_desc = [ShortField("NAME_TRN_ID",0),
                   ShortField("FLAGS", 0xBC07),
                   ShortField("QDCOUNT",0),
                   ShortField("ANCOUNT",1),
                   ShortField("NSCOUNT",0),
                   ShortField("ARCOUNT",0),
                   NetBIOSNameField("RR_NAME","windows"),
                   ShortEnumField("SUFFIX",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                   ByteField("NULL",0),
                   ShortEnumField("RR_TYPE",0x20, {0x20:"NB",0x21:"NBSTAT"}),
                   ShortEnumField("RR_CLASS",1,{1:"INTERNET"}),
                   IntField("TTL", 2),
                   ShortField("RDLENGTH",2),
                   BitField("RDATA",10512,16)] #10512=0010100100010000

class NBTDatagram(Packet):
    name="NBT Datagram Packet"
    fields_desc= [ByteField("Type", 0x10),
                  ByteField("Flags", 0x02),
                  ShortField("ID", 0),
                  IPField("SourceIP", "127.0.0.1"),
                  ShortField("SourcePort", 138),
                  ShortField("Length", 272),
                  ShortField("Offset", 0),
                  NetBIOSNameField("SourceName","windows"),
                  ShortEnumField("SUFFIX1",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                  ByteField("NULL",0),
                  NetBIOSNameField("DestinationName","windows"),
                  ShortEnumField("SUFFIX2",0x4141,{0x4141:"workstation",0x4141+0x03:"messenger service",0x4141+0x200:"file server service",0x4141+0x10b:"domain master browser",0x4141+0x10c:"domain controller", 0x4141+0x10e:"browser election service"}),
                  ByteField("NULL",0)]
    

class NBTSession(Packet):
    name="NBT Session Packet"
    fields_desc= [ByteEnumField("TYPE",0,{0x00:"Session Message",0x81:"Session Request",0x82:"Positive Session Response",0x83:"Negative Session Response",0x84:"Retarget Session Response",0x85:"Session Keepalive"}),
                  BitField("RESERVED",0x00,7),
                  BitField("LENGTH",0,17)]


# SMB NetLogon Response Header
class SMBNetlogon_Protocol_Response_Header(Packet):
    name="SMBNetlogon Protocol Response Header"
    fields_desc = [StrFixedLenField("Start","\xffSMB",4),
                   ByteEnumField("Command",0x25,{0x25:"Trans"}),
                   ByteField("Error_Class",0x02),
                   ByteField("Reserved",0),
                   LEShortField("Error_code",4),
                   ByteField("Flags",0),
                   LEShortField("Flags2",0x0000),
                   LEShortField("PIDHigh",0x0000),
                   LELongField("Signature",0x0),
                   LEShortField("Unused",0x0),
                   LEShortField("TID",0),
                   LEShortField("PID",0),
                   LEShortField("UID",0),
                   LEShortField("MID",0),
                   ByteField("WordCount",17),
                   LEShortField("TotalParamCount",0),
                   LEShortField("TotalDataCount",112),
                   LEShortField("MaxParamCount",0),
                   LEShortField("MaxDataCount",0),
                   ByteField("MaxSetupCount",0),
                   ByteField("unused2",0),
                   LEShortField("Flags3",0),
                   ByteField("TimeOut1",0xe8),
                   ByteField("TimeOut2",0x03),
                   LEShortField("unused3",0),
                   LEShortField("unused4",0),
                   LEShortField("ParamCount2",0),
                   LEShortField("ParamOffset",0),
                   LEShortField("DataCount",112),
                   LEShortField("DataOffset",92),
                   ByteField("SetupCount", 3),
                   ByteField("unused5", 0)]

# SMB MailSlot Protocol
class SMBMailSlot(Packet):
    name = "SMB Mail Slot Protocol"
    fields_desc = [LEShortField("opcode", 1),
                   LEShortField("priority", 1),
                   LEShortField("class", 2),
                   LEShortField("size", 135),
                   StrNullField("name","\MAILSLOT\NET\GETDC660")]

# SMB NetLogon Protocol Response Tail SAM
class SMBNetlogon_Protocol_Response_Tail_SAM(Packet):
    name = "SMB Netlogon Protocol Response Tail SAM"
    fields_desc = [ByteEnumField("Command", 0x17, {0x12:"SAM logon request", 0x17:"SAM Active directory Response"}),
                   ByteField("unused", 0),
                   ShortField("Data1", 0),
                   ShortField("Data2", 0xfd01),
                   ShortField("Data3", 0),
                   ShortField("Data4", 0xacde),
                   ShortField("Data5", 0x0fe5),
                   ShortField("Data6", 0xd10a),
                   ShortField("Data7", 0x374c),
                   ShortField("Data8", 0x83e2),
                   ShortField("Data9", 0x7dd9),
                   ShortField("Data10", 0x3a16),
                   ShortField("Data11", 0x73ff),
                   ByteField("Data12", 0x04),
                   StrFixedLenField("Data13", "rmff", 4),
                   ByteField("Data14", 0x0),
                   ShortField("Data16", 0xc018),
                   ByteField("Data18", 0x0a),
                   StrFixedLenField("Data20", "rmff-win2k", 10),
                   ByteField("Data21", 0xc0),
                   ShortField("Data22", 0x18c0),
                   ShortField("Data23", 0x180a),
                   StrFixedLenField("Data24", "RMFF-WIN2K", 10),
                   ShortField("Data25", 0),
                   ByteField("Data26", 0x17),
                   StrFixedLenField("Data27", "Default-First-Site-Name", 23),
                   ShortField("Data28", 0x00c0),
                   ShortField("Data29", 0x3c10),
                   ShortField("Data30", 0x00c0),
                   ShortField("Data31", 0x0200),
                   ShortField("Data32", 0x0),
                   ShortField("Data33", 0xac14),
                   ShortField("Data34", 0x0064),
                   ShortField("Data35", 0x0),
                   ShortField("Data36", 0x0),
                   ShortField("Data37", 0x0),
                   ShortField("Data38", 0x0),
                   ShortField("Data39", 0x0d00),
                   ShortField("Data40", 0x0),
                   ShortField("Data41", 0xffff)]                   

# SMB NetLogon Protocol Response Tail LM2.0
class SMBNetlogon_Protocol_Response_Tail_LM20(Packet):
    name = "SMB Netlogon Protocol Response Tail LM20"
    fields_desc = [ByteEnumField("Command",0x06,{0x06:"LM 2.0 Response to logon request"}),
                   ByteField("unused", 0),
                   StrFixedLenField("DblSlash", "\\\\", 2),
                   StrNullField("ServerName","WIN"),
                   LEShortField("LM20Token", 0xffff)]

# SMBNegociate Protocol Request Header
class SMBNegociate_Protocol_Request_Header(Packet):
    name="SMBNegociate Protocol Request Header"
    fields_desc = [StrFixedLenField("Start","\xffSMB",4),
                   ByteEnumField("Command",0x72,{0x72:"SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class",0),
                   ByteField("Reserved",0),
                   LEShortField("Error_code",0),
                   ByteField("Flags",0x18),
                   LEShortField("Flags2",0x0000),
                   LEShortField("PIDHigh",0x0000),
                   LELongField("Signature",0x0),
                   LEShortField("Unused",0x0),
                   LEShortField("TID",0),
                   LEShortField("PID",1),
                   LEShortField("UID",0),
                   LEShortField("MID",2),
                   ByteField("WordCount",0),
                   LEShortField("ByteCount",12)]

# SMB Negociate Protocol Request Tail
class SMBNegociate_Protocol_Request_Tail(Packet):
    name="SMB Negociate Protocol Request Tail"
    fields_desc=[ByteField("BufferFormat",0x02),
                 StrNullField("BufferData","NT LM 0.12")]

# SMBNegociate Protocol Response Advanced Security
class SMBNegociate_Protocol_Response_Advanced_Security(Packet):
    name="SMBNegociate Protocol Response Advanced Security"
    fields_desc = [StrFixedLenField("Start","\xffSMB",4),
                   ByteEnumField("Command",0x72,{0x72:"SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class",0),
                   ByteField("Reserved",0),
                   LEShortField("Error_Code",0),
                   ByteField("Flags",0x98),
                   LEShortField("Flags2",0x0000),
                   LEShortField("PIDHigh",0x0000),
                   LELongField("Signature",0x0),
                   LEShortField("Unused",0x0),
                   LEShortField("TID",0),
                   LEShortField("PID",1),
                   LEShortField("UID",0),
                   LEShortField("MID",2),
                   ByteField("WordCount",17),
                   LEShortField("DialectIndex",7),
                   ByteField("SecurityMode",0x03),
                   LEShortField("MaxMpxCount",50),
                   LEShortField("MaxNumberVC",1),
                   LEIntField("MaxBufferSize",16144),
                   LEIntField("MaxRawSize",65536),
                   LEIntField("SessionKey",0x0000),
                   LEShortField("ServerCapabilities",0xf3f9),
                   BitField("UnixExtensions",0,1),
                   BitField("Reserved2",0,7),
                   BitField("ExtendedSecurity",1,1),
                   BitField("CompBulk",0,2),
                   BitField("Reserved3",0,5),
# There have been 127490112000000000 tenths of micro-seconds between 1st january 1601 and 1st january 2005. 127490112000000000=0x1C4EF94D6228000, so ServerTimeHigh=0xD6228000 and ServerTimeLow=0x1C4EF94.
                   LEIntField("ServerTimeHigh",0xD6228000L),
                   LEIntField("ServerTimeLow",0x1C4EF94),
                   LEShortField("ServerTimeZone",0x3c),
                   ByteField("EncryptionKeyLength",0),
                   LEFieldLenField("ByteCount", None, "SecurityBlob", adjust=lambda pkt,x:x-16),
                   BitField("GUID",0,128),
                   StrLenField("SecurityBlob", "", length_from=lambda x:x.ByteCount+16)]

# SMBNegociate Protocol Response No Security
# When using no security, with EncryptionKeyLength=8, you must have an EncryptionKey before the DomainName
class SMBNegociate_Protocol_Response_No_Security(Packet):
    name="SMBNegociate Protocol Response No Security"
    fields_desc = [StrFixedLenField("Start","\xffSMB",4),
                   ByteEnumField("Command",0x72,{0x72:"SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class",0),
                   ByteField("Reserved",0),
                   LEShortField("Error_Code",0),
                   ByteField("Flags",0x98),
                   LEShortField("Flags2",0x0000),
                   LEShortField("PIDHigh",0x0000),
                   LELongField("Signature",0x0),
                   LEShortField("Unused",0x0),
                   LEShortField("TID",0),
                   LEShortField("PID",1),
                   LEShortField("UID",0),
                   LEShortField("MID",2),
                   ByteField("WordCount",17),
                   LEShortField("DialectIndex",7),
                   ByteField("SecurityMode",0x03),
                   LEShortField("MaxMpxCount",50),
                   LEShortField("MaxNumberVC",1),
                   LEIntField("MaxBufferSize",16144),
                   LEIntField("MaxRawSize",65536),
                   LEIntField("SessionKey",0x0000),
                   LEShortField("ServerCapabilities",0xf3f9),
                   BitField("UnixExtensions",0,1),
                   BitField("Reserved2",0,7),
                   BitField("ExtendedSecurity",0,1),
                   FlagsField("CompBulk",0,2,"CB"),
                   BitField("Reserved3",0,5),
                   # There have been 127490112000000000 tenths of micro-seconds between 1st january 1601 and 1st january 2005. 127490112000000000=0x1C4EF94D6228000, so ServerTimeHigh=0xD6228000 and ServerTimeLow=0x1C4EF94.
                   LEIntField("ServerTimeHigh",0xD6228000L),
                   LEIntField("ServerTimeLow",0x1C4EF94),
                   LEShortField("ServerTimeZone",0x3c),
                   ByteField("EncryptionKeyLength",8),
                   LEShortField("ByteCount",24),
                   BitField("EncryptionKey",0,64),
                   StrNullField("DomainName","WORKGROUP"),
                   StrNullField("ServerName","RMFF1")]
    
# SMBNegociate Protocol Response No Security No Key
class SMBNegociate_Protocol_Response_No_Security_No_Key(Packet):
    namez="SMBNegociate Protocol Response No Security No Key"
    fields_desc = [StrFixedLenField("Start","\xffSMB",4),
                   ByteEnumField("Command",0x72,{0x72:"SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class",0),
                   ByteField("Reserved",0),
                   LEShortField("Error_Code",0),
                   ByteField("Flags",0x98),
                   LEShortField("Flags2",0x0000),
                   LEShortField("PIDHigh",0x0000),
                   LELongField("Signature",0x0),
                   LEShortField("Unused",0x0),
                   LEShortField("TID",0),
                   LEShortField("PID",1),
                   LEShortField("UID",0),
                   LEShortField("MID",2),
                   ByteField("WordCount",17),
                   LEShortField("DialectIndex",7),
                   ByteField("SecurityMode",0x03),
                   LEShortField("MaxMpxCount",50),
                   LEShortField("MaxNumberVC",1),
                   LEIntField("MaxBufferSize",16144),
                   LEIntField("MaxRawSize",65536),
                   LEIntField("SessionKey",0x0000),
                   LEShortField("ServerCapabilities",0xf3f9),
                   BitField("UnixExtensions",0,1),
                   BitField("Reserved2",0,7),
                   BitField("ExtendedSecurity",0,1),
                   FlagsField("CompBulk",0,2,"CB"),
                   BitField("Reserved3",0,5),
                   # There have been 127490112000000000 tenths of micro-seconds between 1st january 1601 and 1st january 2005. 127490112000000000=0x1C4EF94D6228000, so ServerTimeHigh=0xD6228000 and ServerTimeLow=0x1C4EF94.
                   LEIntField("ServerTimeHigh",0xD6228000L),
                   LEIntField("ServerTimeLow",0x1C4EF94),
                   LEShortField("ServerTimeZone",0x3c),
                   ByteField("EncryptionKeyLength",0),
                   LEShortField("ByteCount",16),
                   StrNullField("DomainName","WORKGROUP"),
                   StrNullField("ServerName","RMFF1")]
    
# Session Setup AndX Request
class SMBSession_Setup_AndX_Request(Packet):
    name="Session Setup AndX Request"
    fields_desc=[StrFixedLenField("Start","\xffSMB",4),
                ByteEnumField("Command",0x73,{0x73:"SMB_COM_SESSION_SETUP_ANDX"}),
                 ByteField("Error_Class",0),
                 ByteField("Reserved",0),
                 LEShortField("Error_Code",0),
                 ByteField("Flags",0x18),
                 LEShortField("Flags2",0x0001),
                 LEShortField("PIDHigh",0x0000),
                 LELongField("Signature",0x0),
                 LEShortField("Unused",0x0),
                 LEShortField("TID",0),
                 LEShortField("PID",1),
                 LEShortField("UID",0),
                 LEShortField("MID",2),
                 ByteField("WordCount",13),
                 ByteEnumField("AndXCommand",0x75,{0x75:"SMB_COM_TREE_CONNECT_ANDX"}),
                 ByteField("Reserved2",0),
                 LEShortField("AndXOffset",96),
                 LEShortField("MaxBufferS",2920),
                 LEShortField("MaxMPXCount",50),
                 LEShortField("VCNumber",0),
                 LEIntField("SessionKey",0),
                 LEFieldLenField("ANSIPasswordLength",None,"ANSIPassword"),
                 LEShortField("UnicodePasswordLength",0),
                 LEIntField("Reserved3",0),
                 LEShortField("ServerCapabilities",0x05),
                 BitField("UnixExtensions",0,1),
                 BitField("Reserved4",0,7),
                 BitField("ExtendedSecurity",0,1),
                 BitField("CompBulk",0,2),
                 BitField("Reserved5",0,5),
                 LEShortField("ByteCount",35),
                 StrLenField("ANSIPassword", "Pass",length_from=lambda x:x.ANSIPasswordLength),
                 StrNullField("Account","GUEST"),
                 StrNullField("PrimaryDomain",  ""),
                 StrNullField("NativeOS","Windows 4.0"),
                 StrNullField("NativeLanManager","Windows 4.0"),
                 ByteField("WordCount2",4),
                 ByteEnumField("AndXCommand2",0xFF,{0xFF:"SMB_COM_NONE"}),
                 ByteField("Reserved6",0),
                 LEShortField("AndXOffset2",0),
                 LEShortField("Flags3",0x2),
                 LEShortField("PasswordLength",0x1),
                 LEShortField("ByteCount2",18),
                 ByteField("Password",0),
                 StrNullField("Path","\\\\WIN2K\\IPC$"),
                 StrNullField("Service","IPC")]

# Session Setup AndX Response
class SMBSession_Setup_AndX_Response(Packet):
    name="Session Setup AndX Response"
    fields_desc=[StrFixedLenField("Start","\xffSMB",4),
                 ByteEnumField("Command",0x73,{0x73:"SMB_COM_SESSION_SETUP_ANDX"}),
                 ByteField("Error_Class",0),
                 ByteField("Reserved",0),
                 LEShortField("Error_Code",0),
                 ByteField("Flags",0x90),
                 LEShortField("Flags2",0x1001),
                 LEShortField("PIDHigh",0x0000),
                 LELongField("Signature",0x0),
                 LEShortField("Unused",0x0),
                 LEShortField("TID",0),
                 LEShortField("PID",1),
                 LEShortField("UID",0),
                 LEShortField("MID",2),
                 ByteField("WordCount",3),
                 ByteEnumField("AndXCommand",0x75,{0x75:"SMB_COM_TREE_CONNECT_ANDX"}),
                 ByteField("Reserved2",0),
                 LEShortField("AndXOffset",66),
                 LEShortField("Action",0),
                 LEShortField("ByteCount",25),
                 StrNullField("NativeOS","Windows 4.0"),
                 StrNullField("NativeLanManager","Windows 4.0"),
                 StrNullField("PrimaryDomain",""),
                 ByteField("WordCount2",3),
                 ByteEnumField("AndXCommand2",0xFF,{0xFF:"SMB_COM_NONE"}),
                 ByteField("Reserved3",0),
                 LEShortField("AndXOffset2",80),
                 LEShortField("OptionalSupport",0x01),
                 LEShortField("ByteCount2",5),
                 StrNullField("Service","IPC"),
                 StrNullField("NativeFileSystem","")]

class MobileIP(Packet):
    name = "Mobile IP (RFC3344)"
    fields_desc = [ ByteEnumField("type", 1, {1:"RRQ", 3:"RRP"}) ]

class MobileIPRRQ(Packet):
    name = "Mobile IP Registration Request (RFC3344)"
    fields_desc = [ XByteField("flags", 0),
                    ShortField("lifetime", 180),
                    IPField("homeaddr", "0.0.0.0"),
                    IPField("haaddr", "0.0.0.0"),
                    IPField("coaddr", "0.0.0.0"),
                    Field("id", "", "64s") ]

class MobileIPRRP(Packet):
    name = "Mobile IP Registration Reply (RFC3344)"
    fields_desc = [ ByteField("code", 0),
                    ShortField("lifetime", 180),
                    IPField("homeaddr", "0.0.0.0"),
                    IPField("haaddr", "0.0.0.0"),
                    Field("id", "", "64s") ]

class MobileIPTunnelData(Packet):
    name = "Mobile IP Tunnel Data Message (RFC3519)"
    fields_desc = [ ByteField("nexthdr", 4),
                    ShortField("res", 0) ]


# Cisco Netflow Protocol version 1
class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ ShortField("version", 1) ]
    
class NetflowHeaderV1(Packet):
    name = "Netflow Header V1"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0) ]


class NetflowRecordV1(Packet):
    name = "Netflow Record"
    fields_desc = [ IPField("ipsrc", "0.0.0.0"),
                    IPField("ipdst", "0.0.0.0"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("inputIfIndex", 0),
                    ShortField("outpuIfIndex", 0),
                    IntField("dpkts", 0),
                    IntField("dbytes", 0),
                    IntField("starttime", 0),
                    IntField("endtime", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ShortField("padding", 0),
                    ByteField("proto", 0),
                    ByteField("tos", 0),
                    IntField("padding1", 0),
                    IntField("padding2", 0) ]


TFTP_operations = { 1:"RRQ",2:"WRQ",3:"DATA",4:"ACK",5:"ERROR",6:"OACK" }


class TFTP(Packet):
    name = "TFTP opcode"
    fields_desc = [ ShortEnumField("op", 1, TFTP_operations), ]
    


class TFTP_RRQ(Packet):
    name = "TFTP Read Request"
    fields_desc = [ StrNullField("filename", ""),
                    StrNullField("mode", "octet") ]
    def answers(self, other):
        return 0
    def mysummary(self):
        return self.sprintf("RRQ %filename%"),[UDP]
        

class TFTP_WRQ(Packet):
    name = "TFTP Write Request"
    fields_desc = [ StrNullField("filename", ""),
                    StrNullField("mode", "octet") ]
    def answers(self, other):
        return 0
    def mysummary(self):
        return self.sprintf("WRQ %filename%"),[UDP]

class TFTP_DATA(Packet):
    name = "TFTP Data"
    fields_desc = [ ShortField("block", 0) ]
    def answers(self, other):
        return  self.block == 1 and isinstance(other, TFTP_RRQ)
    def mysummary(self):
        return self.sprintf("DATA %block%"),[UDP]

class TFTP_Option(Packet):
    fields_desc = [ StrNullField("oname",""),
                    StrNullField("value","") ]
    def extract_padding(self, pkt):
        return "",pkt

class TFTP_Options(Packet):
    fields_desc = [ PacketListField("options", [], TFTP_Option, length_from=lambda x:None) ]

    
class TFTP_ACK(Packet):
    name = "TFTP Ack"
    fields_desc = [ ShortField("block", 0) ]
    def answers(self, other):
        if isinstance(other, TFTP_DATA):
            return self.block == other.block
        elif isinstance(other, TFTP_RRQ) or isinstance(other, TFTP_WRQ) or isinstance(other, TFTP_OACK):
            return self.block == 0
        return 0
    def mysummary(self):
        return self.sprintf("ACK %block%"),[UDP]

TFTP_Error_Codes = {  0: "Not defined",
                      1: "File not found",
                      2: "Access violation",
                      3: "Disk full or allocation exceeded",
                      4: "Illegal TFTP operation",
                      5: "Unknown transfer ID",
                      6: "File already exists",
                      7: "No such user",
                      8: "Terminate transfer due to option negotiation",
                      }
    
class TFTP_ERROR(Packet):
    name = "TFTP Error"
    fields_desc = [ ShortEnumField("errorcode", 0, TFTP_Error_Codes),
                    StrNullField("errormsg", "")]
    def answers(self, other):
        return (isinstance(other, TFTP_DATA) or
                isinstance(other, TFTP_RRQ) or
                isinstance(other, TFTP_WRQ) or 
                isinstance(other, TFTP_ACK))
    def mysummary(self):
        return self.sprintf("ERROR %errorcode%: %errormsg%"),[UDP]


class TFTP_OACK(Packet):
    name = "TFTP Option Ack"
    fields_desc = [  ]
    def answers(self, other):
        return isinstance(other, TFTP_WRQ) or isinstance(other, TFTP_RRQ)


##########
## SNMP ##
##########

######[ ASN1 class ]######

class ASN1_Class_SNMP(ASN1_Class_UNIVERSAL):
    name="SNMP"
    PDU_GET = 0xa0
    PDU_NEXT = 0xa1
    PDU_RESPONSE = 0xa2
    PDU_SET = 0xa3
    PDU_TRAPv1 = 0xa4
    PDU_BULK = 0xa5
    PDU_INFORM = 0xa6
    PDU_TRAPv2 = 0xa7


class ASN1_SNMP_PDU_GET(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_GET

class ASN1_SNMP_PDU_NEXT(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_NEXT

class ASN1_SNMP_PDU_RESPONSE(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_RESPONSE

class ASN1_SNMP_PDU_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_SET

class ASN1_SNMP_PDU_TRAPv1(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv1

class ASN1_SNMP_PDU_BULK(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_BULK

class ASN1_SNMP_PDU_INFORM(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_INFORM

class ASN1_SNMP_PDU_TRAPv2(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv2


######[ BER codecs ]#######

class BERcodec_SNMP_PDU_GET(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_GET

class BERcodec_SNMP_PDU_NEXT(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_NEXT

class BERcodec_SNMP_PDU_RESPONSE(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_RESPONSE

class BERcodec_SNMP_PDU_SET(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_SET

class BERcodec_SNMP_PDU_TRAPv1(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv1

class BERcodec_SNMP_PDU_BULK(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_BULK

class BERcodec_SNMP_PDU_INFORM(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_INFORM

class BERcodec_SNMP_PDU_TRAPv2(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv2



######[ ASN1 fields ]######

class ASN1F_SNMP_PDU_GET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_GET

class ASN1F_SNMP_PDU_NEXT(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_NEXT

class ASN1F_SNMP_PDU_RESPONSE(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_RESPONSE

class ASN1F_SNMP_PDU_SET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_SET

class ASN1F_SNMP_PDU_TRAPv1(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_TRAPv1

class ASN1F_SNMP_PDU_BULK(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_BULK

class ASN1F_SNMP_PDU_INFORM(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_INFORM

class ASN1F_SNMP_PDU_TRAPv2(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_TRAPv2



######[ SNMP Packet ]######

SNMP_error = { 0: "no_error",
               1: "too_big",
               2: "no_such_name",
               3: "bad_value",
               4: "read_only",
               5: "generic_error",
               6: "no_access",
               7: "wrong_type",
               8: "wrong_length",
               9: "wrong_encoding",
              10: "wrong_value",
              11: "no_creation",
              12: "inconsistent_value",
              13: "ressource_unavailable",
              14: "commit_failed",
              15: "undo_failed",
              16: "authorization_error",
              17: "not_writable",
              18: "inconsistent_name",
               }

SNMP_trap_types = { 0: "cold_start",
                    1: "warm_start",
                    2: "link_down",
                    3: "link_up",
                    4: "auth_failure",
                    5: "egp_neigh_loss",
                    6: "enterprise_specific",
                    }

class SNMPvarbind(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE( ASN1F_OID("oid","1.3"),
                                ASN1F_field("value",ASN1_NULL(0))
                                )


class SNMPget(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_GET( ASN1F_INTEGER("id",0),
                                    ASN1F_enum_INTEGER("error",0, SNMP_error),
                                    ASN1F_INTEGER("error_index",0),
                                    ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                    )

class SNMPnext(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_NEXT( ASN1F_INTEGER("id",0),
                                     ASN1F_enum_INTEGER("error",0, SNMP_error),
                                     ASN1F_INTEGER("error_index",0),
                                     ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                     )

class SNMPresponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_RESPONSE( ASN1F_INTEGER("id",0),
                                         ASN1F_enum_INTEGER("error",0, SNMP_error),
                                         ASN1F_INTEGER("error_index",0),
                                         ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                         )

class SNMPset(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_SET( ASN1F_INTEGER("id",0),
                                    ASN1F_enum_INTEGER("error",0, SNMP_error),
                                    ASN1F_INTEGER("error_index",0),
                                    ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                    )
    
class SNMPtrapv1(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_TRAPv1( ASN1F_INTEGER("id",0),
                                       ASN1F_OID("enterprise", "1.3"),
                                       ASN1F_STRING("agent_addr",""),
                                       ASN1F_enum_INTEGER("generic_trap", 0, SNMP_trap_types),
                                       ASN1F_INTEGER("specific_trap", 0),
                                       ASN1F_INTEGER("time_stamp", IntAutoTime()),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )

class SNMPbulk(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_BULK( ASN1F_INTEGER("id",0),
                                     ASN1F_INTEGER("non_repeaters",0),
                                     ASN1F_INTEGER("max_repetitions",0),
                                     ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                     )
    
class SNMPinform(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_INFORM( ASN1F_INTEGER("id",0),
                                       ASN1F_enum_INTEGER("error",0, SNMP_error),
                                       ASN1F_INTEGER("error_index",0),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )
    
class SNMPtrapv2(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_TRAPv2( ASN1F_INTEGER("id",0),
                                       ASN1F_enum_INTEGER("error",0, SNMP_error),
                                       ASN1F_INTEGER("error_index",0),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )
    

class SNMP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 1, {0:"v1", 1:"v2c", 2:"v2", 3:"v3"}),
        ASN1F_STRING("community","public"),
        ASN1F_CHOICE("PDU", SNMPget(),
                     SNMPget, SNMPnext, SNMPresponse, SNMPset,
                     SNMPtrapv1, SNMPbulk, SNMPinform, SNMPtrapv2)
        )
    def answers(self, other):
        return ( isinstance(self.PDU, SNMPresponse)    and
                 ( isinstance(other.PDU, SNMPget) or
                   isinstance(other.PDU, SNMPnext) or
                   isinstance(other.PDU, SNMPset)    ) and
                 self.PDU.id == other.PDU.id )



#################
## Bind layers ##
#################


def bind_bottom_up(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    lower.payload_guess = lower.payload_guess[:]
    lower.payload_guess.append((fval, upper))
    

def bind_top_down(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    upper.overload_fields = upper.overload_fields.copy()
    upper.overload_fields[lower] = fval
    
def bind_layers(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    bind_top_down(lower, upper, **fval)
    bind_bottom_up(lower, upper, **fval)

def split_bottom_up(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    def do_filter((f,u),upper=upper,fval=fval):
        if u != upper:
            return True
        for k in fval:
            if k not in f or f[k] != fval[k]:
                return True
        return False
    lower.payload_guess = filter(do_filter, lower.payload_guess)
        
def split_top_down(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    if lower in upper.overload_fields:
        ofval = upper.overload_fields[lower]
        for k in fval:
            if k not in ofval or ofval[k] != fval[k]:
                return
        upper.overload_fields = upper.overload_fields.copy()
        del(upper.overload_fields[lower])

def split_layers(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    split_bottom_up(lower, upper, **fval)
    split_top_down(lower, upper, **fval)


bind_layers( Dot3,          LLC,           )
bind_layers( GPRS,          IP,            )
bind_layers( PrismHeader,   Dot11,         )
bind_layers( RadioTap,      Dot11,         )
bind_layers( Dot11,         LLC,           type=2)
bind_layers( Dot11QoS,      LLC,           )
bind_layers( PPP,           IP,            proto=33)
bind_layers( Ether,         LLC,           type=122)
bind_layers( Ether,         Dot1Q,         type=33024)
bind_layers( Ether,         Ether,         type=1)
bind_layers( Ether,         ARP,           type=2054)
bind_layers( Ether,         IP,            type=2048)
bind_layers( Ether,         EAPOL,         type=34958)
bind_layers( Ether,         EAPOL,         dst='01:80:c2:00:00:03', type=34958)
bind_layers( Ether,         PPPoED,        type=34915)
bind_layers( Ether,         PPPoE,         type=34916)
bind_layers( CookedLinux,   LLC,           proto=122)
bind_layers( CookedLinux,   Dot1Q,         proto=33024)
bind_layers( CookedLinux,   Ether,         proto=1)
bind_layers( CookedLinux,   ARP,           proto=2054)
bind_layers( CookedLinux,   IP,            proto=2048)
bind_layers( CookedLinux,   EAPOL,         proto=34958)
bind_layers( CookedLinux,   PPPoED,        proto=34915)
bind_layers( CookedLinux,   PPPoE,         proto=34916)
bind_layers( GRE,           LLC,           proto=122)
bind_layers( GRE,           Dot1Q,         proto=33024)
bind_layers( GRE,           Ether,         proto=1)
bind_layers( GRE,           ARP,           proto=2054)
bind_layers( GRE,           IP,            proto=2048)
bind_layers( GRE,           EAPOL,         proto=34958)
bind_layers( PPPoE,         PPP,           code=0)
bind_layers( EAPOL,         EAP,           type=0)
bind_layers( LLC,           STP,           dsap=66, ssap=66, ctrl=3)
bind_layers( LLC,           SNAP,          dsap=170, ssap=170, ctrl=3)
bind_layers( SNAP,          Dot1Q,         code=33024)
bind_layers( SNAP,          Ether,         code=1)
bind_layers( SNAP,          ARP,           code=2054)
bind_layers( SNAP,          IP,            code=2048)
bind_layers( SNAP,          EAPOL,         code=34958)
bind_layers( SNAP,          STP,           code=267)
bind_layers( IPerror,       IPerror,       frag=0, proto=4)
bind_layers( IPerror,       ICMPerror,     frag=0, proto=1)
bind_layers( IPerror,       TCPerror,      frag=0, proto=6)
bind_layers( IPerror,       UDPerror,      frag=0, proto=17)
bind_layers( IP,            IP,            frag=0, proto=4)
bind_layers( IP,            ICMP,          frag=0, proto=1)
bind_layers( IP,            TCP,           frag=0, proto=6)
bind_layers( IP,            UDP,           frag=0, proto=17)
bind_layers( IP,            GRE,           frag=0, proto=47)
bind_layers( UDP,           SNMP,          sport=161)
bind_layers( UDP,           SNMP,          dport=161)
bind_layers( UDP,           MGCP,          dport=2727)
bind_layers( UDP,           MGCP,          sport=2727)
bind_layers( UDP,           DNS,           dport=53)
bind_layers( UDP,           DNS,           sport=53)
bind_layers( UDP,           ISAKMP,        dport=500, sport=500)
bind_layers( UDP,           HSRP,          dport=1985, sport=1985)
bind_layers( UDP,           NTP,           dport=123, sport=123)
bind_layers( UDP,           BOOTP,         dport=67, sport=68)
bind_layers( UDP,           BOOTP,         dport=68, sport=67)
bind_layers( BOOTP,         DHCP,          options='c\x82Sc')
bind_layers( UDP,           RIP,           sport=520)
bind_layers( UDP,           RIP,           dport=520)
bind_layers( RIP,           RIPEntry,      )
bind_layers( RIPEntry,      RIPEntry,      )
bind_layers( Dot11,         Dot11AssoReq,    subtype=0, type=0)
bind_layers( Dot11,         Dot11AssoResp,   subtype=1, type=0)
bind_layers( Dot11,         Dot11ReassoReq,  subtype=2, type=0)
bind_layers( Dot11,         Dot11ReassoResp, subtype=3, type=0)
bind_layers( Dot11,         Dot11ProbeReq,   subtype=4, type=0)
bind_layers( Dot11,         Dot11ProbeResp,  subtype=5, type=0)
bind_layers( Dot11,         Dot11Beacon,     subtype=8, type=0)
bind_layers( Dot11,         Dot11ATIM,       subtype=9, type=0)
bind_layers( Dot11,         Dot11Disas,      subtype=10, type=0)
bind_layers( Dot11,         Dot11Auth,       subtype=11, type=0)
bind_layers( Dot11,         Dot11Deauth,     subtype=12, type=0)
bind_layers( Dot11Beacon,     Dot11Elt,    )
bind_layers( Dot11AssoReq,    Dot11Elt,    )
bind_layers( Dot11AssoResp,   Dot11Elt,    )
bind_layers( Dot11ReassoReq,  Dot11Elt,    )
bind_layers( Dot11ReassoResp, Dot11Elt,    )
bind_layers( Dot11ProbeReq,   Dot11Elt,    )
bind_layers( Dot11ProbeResp,  Dot11Elt,    )
bind_layers( Dot11Auth,       Dot11Elt,    )
bind_layers( Dot11Elt,        Dot11Elt,    )
bind_layers( TCP,           Skinny,        dport=2000)
bind_layers( TCP,           Skinny,        sport=2000)
bind_layers( UDP,           SebekHead,     sport=1101)
bind_layers( UDP,           SebekHead,     dport=1101)
bind_layers( UDP,           SebekHead,     dport=1101, sport=1101)
bind_layers( SebekHead,     SebekV1,       version=1)
bind_layers( SebekHead,     SebekV2Sock,   version=2, type=2)
bind_layers( SebekHead,     SebekV2,       version=2)
bind_layers( SebekHead,     SebekV3Sock,   version=3, type=2)
bind_layers( SebekHead,     SebekV3,       version=3)
bind_layers( CookedLinux,   IrLAPHead,     proto=23)
bind_layers( IrLAPHead,     IrLAPCommand,  Type=1)
bind_layers( IrLAPCommand,  IrLMP,         )
bind_layers( UDP,           NBNSQueryRequest,  dport=137)
bind_layers( UDP,           NBNSRequest,       dport=137)
bind_layers( UDP,           NBNSQueryResponse, sport=137)
bind_layers( UDP,           NBNSQueryResponseNegative, sport=137)
bind_layers( UDP,           NBNSNodeStatusResponse,    sport=137)
bind_layers( NBNSNodeStatusResponse,        NBNSNodeStatusResponseService, )
bind_layers( NBNSNodeStatusResponse,        NBNSNodeStatusResponseService, )
bind_layers( NBNSNodeStatusResponseService, NBNSNodeStatusResponseService, )
bind_layers( NBNSNodeStatusResponseService, NBNSNodeStatusResponseEnd, )
bind_layers( UDP,           NBNSWackResponse, sport=137)
bind_layers( UDP,           NBTDatagram,      dport=138)
bind_layers( TCP,           NBTSession,       dport=139)
bind_layers( NBTSession,                           SMBNegociate_Protocol_Request_Header, )
bind_layers( SMBNegociate_Protocol_Request_Header, SMBNegociate_Protocol_Request_Tail, )
bind_layers( SMBNegociate_Protocol_Request_Tail,   SMBNegociate_Protocol_Request_Tail, )
bind_layers( NBTSession,    SMBNegociate_Protocol_Response_Advanced_Security,  ExtendedSecurity=1)
bind_layers( NBTSession,    SMBNegociate_Protocol_Response_No_Security,        ExtendedSecurity=0, EncryptionKeyLength=8)
bind_layers( NBTSession,    SMBNegociate_Protocol_Response_No_Security_No_Key, ExtendedSecurity=0, EncryptionKeyLength=0)
bind_layers( NBTSession,    SMBSession_Setup_AndX_Request, )
bind_layers( NBTSession,    SMBSession_Setup_AndX_Response, )
bind_layers( HCI_Hdr,       HCI_ACL_Hdr,   type=2)
bind_layers( HCI_Hdr,       Raw,           )
bind_layers( HCI_ACL_Hdr,   L2CAP_Hdr,     )
bind_layers( L2CAP_Hdr,     L2CAP_CmdHdr,      cid=1)
bind_layers( L2CAP_CmdHdr,  L2CAP_CmdRej,      code=1)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnReq,     code=2)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnResp,    code=3)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfReq,     code=4)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfResp,    code=5)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnReq,  code=6)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnResp, code=7)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoReq,     code=10)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoResp,    code=11)
bind_layers( UDP,           MobileIP,           sport=434)
bind_layers( UDP,           MobileIP,           dport=434)
bind_layers( MobileIP,      MobileIPRRQ,        type=1)
bind_layers( MobileIP,      MobileIPRRP,        type=3)
bind_layers( MobileIP,      MobileIPTunnelData, type=4)
bind_layers( MobileIPTunnelData, IP,           nexthdr=4)
bind_layers( NetflowHeader,   NetflowHeaderV1, version=1)
bind_layers( NetflowHeaderV1, NetflowRecordV1, )

bind_layers(UDP, TFTP, dport=69)
bind_layers(TFTP, TFTP_RRQ, op=1)
bind_layers(TFTP, TFTP_WRQ, op=2)
bind_layers(TFTP, TFTP_DATA, op=3)
bind_layers(TFTP, TFTP_ACK, op=4)
bind_layers(TFTP, TFTP_ERROR, op=5)
bind_layers(TFTP, TFTP_OACK, op=6)
bind_layers(TFTP_RRQ, TFTP_Options)
bind_layers(TFTP_WRQ, TFTP_Options)
bind_layers(TFTP_OACK, TFTP_Options)


###################
## Fragmentation ##
###################

def fragment(pkt, fragsize=1480):
    fragsize = (fragsize+7)/8*8
    lst = []
    for p in pkt:
        s = str(p[IP].payload)
        nb = (len(s)+fragsize-1)/fragsize
        for i in range(nb):            
            q = p.copy()
            del(q[IP].payload)
            del(q[IP].chksum)
            del(q[IP].len)
            if i == nb-1:
                q[IP].flags &= ~1
            else:
                q[IP].flags |= 1 
            q[IP].frag = i*fragsize/8
            r = Raw(load=s[i*fragsize:(i+1)*fragsize])
            r.overload_fields = p[IP].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst

def overlap_frag(p, overlap, fragsize=8, overlap_fragsize=None):
    if overlap_fragsize is None:
        overlap_fragsize = fragsize
    q = p.copy()
    del(q[IP].payload)
    q[IP].add_payload(overlap)

    qfrag = fragment(q, overlap_fragsize)
    qfrag[-1][IP].flags |= 1
    return qfrag+fragment(p, fragsize)

def defrag(plist):
    """defrag(plist) -> ([not fragmented], [defragmented],
                  [ [bad fragments], [bad fragments], ... ])"""
    frags = {}
    nofrag = PacketList()
    for p in plist:
        ip = p[IP]
        if IP not in p:
            nofrag.append(p)
            continue
        if ip.frag == 0 and ip.flags & 1 == 0:
            nofrag.append(p)
            continue
        uniq = (ip.id,ip.src,ip.dst,ip.proto)
        if uniq in frags:
            frags[uniq].append(p)
        else:
            frags[uniq] = PacketList([p])
    defrag = []
    missfrag = []
    for lst in frags.itervalues():
        lst.sort(lambda x,y:cmp(x.frag, y.frag))
        p = lst[0]
        if p.frag > 0:
            missfrag.append(lst)
            continue
        p = p.copy()
        if Padding in p:
            del(p[Padding].underlayer.payload)
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl<<2)
        txt = Raw()
        for q in lst[1:]:
            if clen != q.frag<<3:
                if clen > q.frag<<3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag<<3, p,txt,q))
                missfrag.append(lst)
                txt = None
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl<<2)
            if Padding in q:
                del(q[Padding].underlayer.payload)
            txt.add_payload(q[IP].payload.copy())
            
        if txt is None:
            continue

        ip.flags &= ~1 # !MF
        del(ip.chksum)
        del(ip.len)
        p = p/txt
        defrag.append(p)
    defrag2=PacketList()
    for p in defrag:
        defrag2.append(p.__class__(str(p)))
    return nofrag,defrag2,missfrag
            
def defragment(plist):
    """defrag(plist) -> plist defragmented as much as possible """
    frags = {}
    final = []

    pos = 0
    for p in plist:
        p._defrag_pos = pos
        pos += 1
        if IP in p:
            ip = p[IP]
            if ip.frag != 0 or ip.flags & 1:
                ip = p[IP]
                uniq = (ip.id,ip.src,ip.dst,ip.proto)
                if uniq in frags:
                    frags[uniq].append(p)
                else:
                    frags[uniq] = [p]
                continue
        final.append(p)

    defrag = []
    missfrag = []
    for lst in frags.itervalues():
        lst.sort(lambda x,y:cmp(x.frag, y.frag))
        p = lst[0]
        if p.frag > 0:
            missfrag += lst
            continue
        p = p.copy()
        if Padding in p:
            del(p[Padding].underlayer.payload)
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl<<2)
        txt = Raw()
        for q in lst[1:]:
            if clen != q.frag<<3:
                if clen > q.frag<<3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag<<3, p,txt,q))
                missfrag += lst
                txt = None
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl<<2)
            if Padding in q:
                del(q[Padding].underlayer.payload)
            txt.add_payload(q[IP].payload.copy())
            
        if txt is None:
            continue

        ip.flags &= ~1 # !MF
        del(ip.chksum)
        del(ip.len)
        p = p/txt
        p._defrag_pos = lst[-1]._defrag_pos
        defrag.append(p)
    defrag2=[]
    for p in defrag:
        q = p.__class__(str(p))
        q._defrag_pos = p._defrag_pos
        defrag2.append(q)
    final += defrag2
    final += missfrag
    final.sort(lambda x,y: cmp(x._defrag_pos, y._defrag_pos))
    for p in final:
        del(p._defrag_pos)

    if hasattr(plist, "listname"):
        name = "Defragmented %s" % plist.listname
    else:
        name = "Defragmented"
        
    
    return PacketList(final, name=name)
            
            
        
    


###################
## Super sockets ##
###################

def Ether_Dot3_Dispatcher(pkt=None, **kargs):
    if type(pkt) is str and len(pkt) >= 14 and struct.unpack("!H", pkt[12:14])[0] <= 1500:
        return Dot3(pkt, **kargs)
    return Ether(pkt, **kargs)

# According to libdnet
LLTypes = { ARPHDR_ETHER : Ether_Dot3_Dispatcher,
            ARPHDR_METRICOM : Ether_Dot3_Dispatcher,
            ARPHDR_LOOPBACK : Ether_Dot3_Dispatcher,
            12 : IP,
            101 : IP,
            801 : Dot11,
            802 : PrismHeader,
            803 : RadioTap,
            105 : Dot11,
            113 : CookedLinux,
            119 : PrismHeader, # for atheros
            127 : RadioTap,
            144 : CookedLinux, # called LINUX_IRDA, similar to CookedLinux
            783 : IrLAPHead,
            0xB1E70073L : HCI_Hdr, # I invented this one
            }

LLNumTypes = { Ether : ARPHDR_ETHER,
               IP  : 12,
               IP  : 101,
               Dot11  : 801,
               PrismHeader : 802,
               RadioTap    : 803,
               RadioTap    : 127,
               Dot11 : 105,
               CookedLinux : 113,
               CookedLinux : 144,
               IrLAPHead : 783
            }

L3Types = { ETH_P_IP : IP,
            ETH_P_ARP : ARP,
            ETH_P_ALL : IP
            }


def flush_fd(fd):
    if type(fd) is not int:
        fd = fd.fileno()
    while 1:
        r,w,e = select([fd],[],[],0)
        if r:
            os.read(fd,MTU)
        else:
            break

class SuperSocket:
    closed=0
    def __init__(self, family=socket.AF_INET,type=socket.SOCK_STREAM, proto=0):
        self.ins = socket.socket(family, type, proto)
        self.outs = self.ins
        self.promisc=None
    def send(self, x):
        sx = str(x)
        x.sent_time = time.time()
        return self.outs.send(sx)
    def recv(self, x):
        return Raw(self.ins.recv(x))
    def fileno(self):
        return self.ins.fileno()
    def close(self):
        if self.closed:
            return
        self.closed=1
        if self.ins != self.outs:
            if self.outs and self.outs.fileno() != -1:
                self.outs.close()
        if self.ins and self.ins.fileno() != -1:
            self.ins.close()
    def bind_in(self, addr):
        self.ins.bind(addr)
    def bind_out(self, addr):
        self.outs.bind(addr)


class L3RawSocket(SuperSocket):
    def __init__(self, type = ETH_P_IP, filter=None, iface=None, promisc=None, nofilter=0):
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
    def recv(self, x):
        return Ether(self.ins.recv(x)).payload
    def send(self, x):
        try:
            sx = str(x)
            x.sent_time = time.time()
            self.outs.sendto(sx,(x.dst,0))
        except socket.error,msg:
            log_runtime.error(msg)
        


class L3PacketSocket(SuperSocket):
    def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
        self.type = type
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        flush_fd(self.ins)
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        if promisc is None:
            promisc = conf.promisc
        self.promisc = promisc
        if self.promisc:
            if iface is None:
                self.iff = get_if_list()
            else:
                if iface.__class__ is list:
                    self.iff = iface
                else:
                    self.iff = [iface]
            for i in self.iff:
                set_promisc(self.ins, i)
    def close(self):
        if self.closed:
            return
        self.closed=1
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)
    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        if sa_ll[2] == socket.PACKET_OUTGOING:
            return None
        if LLTypes.has_key(sa_ll[3]):
            cls = LLTypes[sa_ll[3]]
            lvl = 2
        elif L3Types.has_key(sa_ll[1]):
            cls = L3Types[sa_ll[1]]
            lvl = 3
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            cls = Ether
            lvl = 2

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        if lvl == 2:
            pkt = pkt.payload
            
        if pkt is not None:
            pkt.time = get_last_packet_timestamp(self.ins)
        return pkt
    
    def send(self, x):
        if isinstance(x, IPv6):
            iff,a,gw = conf.route6.route(x.dst)
        elif hasattr(x,"dst"):
            iff,a,gw = conf.route.route(x.dst)
        else:
            iff = conf.iface
        sdto = (iff, self.type)
        self.outs.bind(sdto)
        sn = self.outs.getsockname()
        ll = lambda x:x
        if sn[3] in (ARPHDR_PPP,ARPHDR_TUN):
            sdto = (iff, ETH_P_IP)
        if LLTypes.has_key(sn[3]):
            ll = lambda x:LLTypes[sn[3]]()/x
        try:
            sx = str(ll(x))
            x.sent_time = time.time()
            self.outs.sendto(sx, sdto)
        except socket.error,msg:
            x.sent_time = time.time()  # bad approximation
            if conf.auto_fragment and msg[0] == 90:
                for p in fragment(x):
                    self.outs.sendto(str(ll(p)), sdto)
            else:
                raise
                    



class L2Socket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
        if iface is None:
            iface = conf.iface
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        flush_fd(self.ins)
        if not nofilter: 
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        self.ins.bind((iface, type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs = self.ins
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        sa_ll = self.outs.getsockname()
        if LLTypes.has_key(sa_ll[3]):
            self.LL = LLTypes[sa_ll[3]]
        elif L3Types.has_key(sa_ll[1]):
            self.LL = L3Types[sa_ll[1]]
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            self.LL = Ether
            
    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        if sa_ll[2] == socket.PACKET_OUTGOING:
            return None
        try:
            q = self.LL(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            q = Raw(pkt)
        q.time = get_last_packet_timestamp(self.ins)
        return q


class L2ListenSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None, nofilter=0):
        self.type = type
        self.outs = None
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        flush_fd(self.ins)
        if iface is not None:
            self.ins.bind((iface, type))
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        if iface is None:
            self.iff = get_if_list()
        else:
            if iface.__class__ is list:
                self.iff = iface
            else:
                self.iff = [iface]
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    def close(self):
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)

    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        if LLTypes.has_key(sa_ll[3]):
            cls = LLTypes[sa_ll[3]]
        elif L3Types.has_key(sa_ll[1]):
            cls = L3Types[sa_ll[1]]
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            cls = Ether

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = get_last_packet_timestamp(self.ins)
        return pkt
    
    def send(self, x):
        raise Scapy_Exception("Can't send anything with L2ListenSocket")



class L3dnetSocket(SuperSocket):
    def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
        self.iflist = {}
        self.ins = pcap.pcapObject()
        if iface is None:
            iface = conf.iface
        self.iface = iface
        self.ins.open_live(iface, 1600, 0, 100)
        try:
            ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
        except:
            pass
        if nofilter:
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                filter = "ether proto %i" % type
            else:
                filter = None
        else:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                if filter:
                    filter = "(ether proto %i) and (%s)" % (type,filter)
                else:
                    filter = "ether proto %i" % type
        if filter:
            self.ins.setfilter(filter, 0, 0)
    def send(self, x):
        if isinstance(x, IPv6):
            iff,a,gw = conf.route6.route(x.dst)
        elif hasattr(x,"dst"):
            iff,a,gw = conf.route.route(x.dst)
        else:
            iff = conf.iface
        ifs = self.iflist.get(iff)
        if ifs is None:
            self.iflist[iff] = ifs = dnet.eth(iff)
        sx = str(Ether()/x)
        x.sent_time = time.time()
        ifs.send(sx)
    def recv(self,x=MTU):
        ll = self.ins.datalink()
        if LLTypes.has_key(ll):
            cls = LLTypes[ll]
        else:
            warning("Unable to guess datalink type (interface=%s linktype=%i). Using Ethernet" % (self.iface, ll))
            cls = Ether

        pkt = self.ins.next()
        if pkt is not None:
            l,pkt,ts = pkt
        if pkt is None:
            return

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = ts
        return pkt.payload

    def nonblock_recv(self):
        self.ins.setnonblock(1)
        p = self.recv()
        self.ins.setnonblock(0)
        return p

    def close(self):
        if hasattr(self, "ins"):
            del(self.ins)
        if hasattr(self, "outs"):
            del(self.outs)

class L2dnetSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
        if iface is None:
            iface = conf.iface
        self.iface = iface
        self.ins = pcap.pcapObject()
        self.ins.open_live(iface, 1600, 0, 100)
        try:
            ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
        except:
            pass
        if nofilter:
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                filter = "ether proto %i" % type
            else:
                filter = None
        else:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                if filter:
                    filter = "(ether proto %i) and (%s)" % (type,filter)
                else:
                    filter = "ether proto %i" % type
        if filter:
            self.ins.setfilter(filter, 0, 0)
        self.outs = dnet.eth(iface)
    def recv(self,x):
        ll = self.ins.datalink()
        if LLTypes.has_key(ll):
            cls = LLTypes[ll]
        else:
            warning("Unable to guess datalink type (interface=%s linktype=%i). Using Ethernet" % (self.iface, ll))
            cls = Ether

        pkt = self.ins.next()
        if pkt is not None:
            l,pkt,ts = pkt
        if pkt is None:
            return
        
        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = ts
        return pkt

    def nonblock_recv(self):
        self.ins.setnonblock(1)
        p = self.recv(MTU)
        self.ins.setnonblock(0)
        return p

    def close(self):
        if hasattr(self, "ins"):
            del(self.ins)
        if hasattr(self, "outs"):
            del(self.outs)
    
    
    


class L2pcapListenSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
        self.type = type
        self.outs = None
        self.ins = pcap.pcapObject()
        self.iface = iface
        if iface is None:
            iface = conf.iface
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        self.ins.open_live(iface, 1600, self.promisc, 100)
        try:
            ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
        except:
            pass
        if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter:
                self.ins.setfilter(filter, 0, 0)

    def close(self):
        del(self.ins)
        
    def recv(self, x):
        ll = self.ins.datalink()
        if LLTypes.has_key(ll):
            cls = LLTypes[ll]
        else:
            warning("Unable to guess datalink type (interface=%s linktype=%i). Using Ethernet" % (self.iface, ll))
            cls = Ether

        pkt = None
        while pkt is None:
            pkt = self.ins.next()
            if pkt is not None:
                l,pkt,ts = pkt
        
        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = ts
        return pkt

    def send(self, x):
        raise Scapy_Exception("Can't send anything with L2pcapListenSocket")


class SimpleSocket(SuperSocket):
    def __init__(self, sock):
        self.ins = sock
        self.outs = sock


class StreamSocket(SimpleSocket):
    def __init__(self, sock, basecls=Raw):
        SimpleSocket.__init__(self, sock)
        self.basecls = basecls
        
    def recv(self, x=MTU):
        pkt = self.ins.recv(x, socket.MSG_PEEK)
        x = len(pkt)
        pkt = self.basecls(pkt)
        pad = pkt[Padding]
        if pad is not None and pad.underlayer is not None:
            del(pad.underlayer.payload)
        while pad is not None and not isinstance(pad, NoPayload):
            x -= len(pad.load)
            pad = pad.payload
        self.ins.recv(x)
        return pkt
        
        
class BluetoothL2CAPSocket(SuperSocket):
    def __init__(self, peer):
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                          socket.BTPROTO_L2CAP)
        s.connect((peer,0))
        
        self.ins = self.outs = s

    def recv(self, x):
        return L2CAP_CmdHdr(self.ins.recv(x))
    

class BluetoothHCISocket(SuperSocket):
    def __init__(self, iface=0x10000, type=None):
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        s.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR,1)
        s.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP,1)
        s.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, struct.pack("IIIh2x", 0xffffffffL,0xffffffffL,0xffffffffL,0)) #type mask, event mask, event mask, opcode
        s.bind((iface,))
        self.ins = self.outs = s
#        s.connect((peer,0))
        

    def recv(self, x):
        return HCI_Hdr(self.ins.recv(x))
    


####################
## Send / Receive ##
####################




def sndrcv(pks, pkt, timeout = 2, inter = 0, verbose=None, chainCC=0, retry=0, multi=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
        
    if verbose is None:
        verbose = conf.verb
    debug.recv = PacketList([],"Unanswered")
    debug.sent = PacketList([],"Sent")
    debug.match = SndRcvList([])
    nbrecv=0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    all_stimuli = tobesent = [p for p in pkt]
    notans = len(tobesent)

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]
    if retry < 0:
        retry = -retry
        autostop=retry
    else:
        autostop=0


    while retry >= 0:
        found=0
    
        if timeout < 0:
            timeout = None
            
        rdpipe,wrpipe = os.pipe()
        rdpipe=os.fdopen(rdpipe)
        wrpipe=os.fdopen(wrpipe,"w")

        pid=1
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    sys.stdin.close()
                    rdpipe.close()
                    try:
                        i = 0
                        if verbose:
                            print "Begin emission:"
                        for p in tobesent:
                            pks.send(p)
                            i += 1
                            time.sleep(inter)
                        if verbose:
                            print "Finished to send %i packets." % i
                    except SystemExit:
                        pass
                    except KeyboardInterrupt:
                        pass
                    except:
                        log_runtime.exception("--- Error in child %i" % os.getpid())
                        log_runtime.info("--- Error in child %i" % os.getpid())
                finally:
                    try:
                        os.setpgrp() # Chance process group to avoid ctrl-C
                        sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
                        cPickle.dump( (arp_cache,sent_times), wrpipe )
                        wrpipe.close()
                    except:
                        pass
            elif pid < 0:
                log_runtime.error("fork error")
            else:
                wrpipe.close()
                stoptime = 0
                remaintime = None
                inmask = [rdpipe,pks]
                try:
                    try:
                        while 1:
                            if stoptime:
                                remaintime = stoptime-time.time()
                                if remaintime <= 0:
                                    break
                            r = None
                            if FREEBSD or DARWIN:
                                inp, out, err = select(inmask,[],[], 0.05)
                                if len(inp) == 0 or pks in inp:
                                    r = pks.nonblock_recv()
                            else:
                                inp, out, err = select(inmask,[],[], remaintime)
                                if len(inp) == 0:
                                    break
                                if pks in inp:
                                    r = pks.recv(MTU)
                            if rdpipe in inp:
                                if timeout:
                                    stoptime = time.time()+timeout
                                del(inmask[inmask.index(rdpipe)])
                            if r is None:
                                continue
                            ok = 0
                            h = r.hashret()
                            if h in hsent:
                                hlst = hsent[h]
                                for i in range(len(hlst)):
                                    if r.answers(hlst[i]):
                                        ans.append((hlst[i],r))
                                        if verbose > 1:
                                            os.write(1, "*")
                                        ok = 1                                
                                        if not multi:
                                            del(hlst[i])
                                            notans -= 1;
                                        else:
                                            if not hasattr(hlst[i], '_answered'):
                                                notans -= 1;
                                            hlst[i]._answered = 1;
                                        break
                            if notans == 0 and not multi:
                                break
                            if not ok:
                                if verbose > 1:
                                    os.write(1, ".")
                                nbrecv += 1
                                if conf.debug_match:
                                    debug.recv.append(r)
                    except KeyboardInterrupt:
                        if chainCC:
                            raise
                finally:
                    try:
                        ac,sent_times = cPickle.load(rdpipe)
                    except EOFError:
                        warning("Child died unexpectedly. Packets may have not been sent %i"%os.getpid())
                    else:
                        arp_cache.update(ac)
                        for p,t in zip(all_stimuli, sent_times):
                            p.sent_time = t
                    os.waitpid(pid,0)
        finally:
            if pid == 0:
                os._exit(0)

        remain = reduce(list.__add__, hsent.values(), [])
        if multi:
            remain = filter(lambda p: not hasattr(p, '_answered'), remain);
            
        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        if len(tobesent) == 0:
            break
        retry -= 1
        
    if conf.debug_match:
        debug.sent=PacketList(remain[:],"Sent")
        debug.match=SndRcvList(ans[:])

    #clean the ans list to delete the field _answered
    if (multi):
        for s,r in ans:
            if hasattr(s, '_answered'):
                del(s._answered)
    
    if verbose:
        print "\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans)
    return SndRcvList(ans),PacketList(remain,"Unanswered"),debug.recv


def __gen_send(s, x, inter=0, loop=0, count=None, verbose=None, *args, **kargs):
    if not isinstance(x, Gen):
        x = SetGen(x)
    if verbose is None:
        verbose = conf.verb
    n = 0
    if count is not None:
        loop = -count
    elif not loop:
        loop=-1
    try:
        while loop:
            for p in x:
                s.send(p)
                n += 1
                if verbose:
                    os.write(1,".")
                time.sleep(inter)
            if loop < 0:
                loop += 1
    except KeyboardInterrupt:
        pass
    s.close()
    if verbose:
        print "\nSent %i packets." % n

def send(x, inter=0, loop=0, count=None, verbose=None, *args, **kargs):
    """Send packets at layer 3
send(packets, [inter=0], [loop=0], [verbose=conf.verb]) -> None"""
    __gen_send(conf.L3socket(*args, **kargs), x, inter=inter, loop=loop, count=count,verbose=verbose)

def sendp(x, inter=0, loop=0, iface=None, iface_hint=None, count=None, verbose=None, *args, **kargs):
    """Send packets at layer 2
send(packets, [inter=0], [loop=0], [verbose=conf.verb]) -> None"""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    __gen_send(conf.L2socket(iface=iface, *args, **kargs), x, inter=inter, loop=loop, count=count, verbose=verbose)

def sendpfast(x, pps=None, mbps=None, realtime=None, loop=0, iface=None):
    """Send packets at layer 2 using tcpreplay for performance
    pps:  packets per second
    mpbs: MBits per second
    realtime: use packet's timestamp, bending time with realtime value
    loop: number of times to process the packet list
    iface: output interface """
    if iface is None:
        iface = conf.iface
    options = ["--intf1=%s" % iface ]
    if pps is not None:
        options.append("--pps=%i" % pps)
    elif mbps is not None:
        options.append("--mbps=%i" % mbps)
    elif realtime is not None:
        options.append("--multiplier=%i" % realtime)
    else:
        options.append("--topspeed")

    if loop:
        options.append("--loop=%i" % loop)

    f = os.tempnam("scapy")
    options.append(f)
    wrpcap(f, x)
    try:
        try:
            os.spawnlp(os.P_WAIT, conf.prog.tcpreplay, conf.prog.tcpreplay, *options)
        except KeyboardInterrupt:
            log_interactive.info("Interrupted by user")
    finally:
        os.unlink(f)

        

        
    
def sr(x,filter=None, iface=None, nofilter=0, *args,**kargs):
    """Send and receive packets at layer 3
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    s = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)
    a,b,c=sndrcv(s,x,*args,**kargs)
    s.close()
    return a,b

def sr1(x,filter=None,iface=None, nofilter=0, *args,**kargs):
    """Send packets at layer 3 and return only the first answer
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    s=conf.L3socket(filter=filter, nofilter=nofilter, iface=iface)
    a,b,c=sndrcv(s,x,*args,**kargs)
    s.close()
    if len(a) > 0:
        return a[0][1]
    else:
        return None

def srp(x,iface=None, iface_hint=None, filter=None, nofilter=0, type=ETH_P_ALL, *args,**kargs):
    """Send and receive packets at layer 2
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    a,b,c=sndrcv(conf.L2socket(iface=iface, filter=filter, nofilter=nofilter, type=type),x,*args,**kargs)
    return a,b

def srp1(*args,**kargs):
    """Send and receive packets at layer 2 and return only the first answer
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b=srp(*args,**kargs)
    if len(a) > 0:
        return a[0][1]
    else:
        return None

def __sr_loop(srfunc, pkts, prn=lambda x:x[1].summary(), prnfail=lambda x:x.summary(), inter=1, timeout=None, count=None, verbose=0, store=1, *args, **kargs):
    n = 0
    r = 0
    ct = conf.color_theme
    parity = 0
    ans=[]
    unans=[]
    if timeout is None:
        timeout = min(2*inter, 5)
    try:
        while 1:
            parity ^= 1
            col = [ct.even,ct.odd][parity]
            if count is not None:
                if count == 0:
                    break
                count -= 1
            start = time.time()
            print "\rsend...\r",
            res = srfunc(pkts, timeout=timeout, verbose=0, chainCC=1, *args, **kargs)
            n += len(res[0])+len(res[1])
            r += len(res[0])
            if prn and len(res[0]) > 0:
                msg = "RECV %i:" % len(res[0])
                print  "\r"+ct.success(msg),
                for p in res[0]:
                    print col(prn(p))
                    print " "*len(msg),
            if prnfail and len(res[1]) > 0:
                msg = "fail %i:" % len(res[1])
                print "\r"+ct.fail(msg),
                for p in res[1]:
                    print col(prnfail(p))
                    print " "*len(msg),
            if not (prn or prnfail):
                print "recv:%i  fail:%i" % tuple(map(len, res[:2]))
            if store:
                ans += res[0]
                unans += res[1]
            end=time.time()
            if end-start < inter:
                time.sleep(inter+start-end)
    except KeyboardInterrupt:
        pass
 
    if n>0:
        print "%s\nSent %i packets, received %i packets. %3.1f%% hits." % (Color.normal,n,r,100.0*r/n)

    return SndRcvList(ans),PacketList(unans)

def srloop(pkts, *args, **kargs):
    """Send a packet at layer 3 in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    return __sr_loop(sr, pkts, *args, **kargs)

def srploop(pkts, *args, **kargs):
    """Send a packet at layer 2 in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    return __sr_loop(srp, pkts, *args, **kargs)


def sndrcvflood(pks, pkt, prn=lambda (s,r):r.summary(), chainCC=0, store=1, unique=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
    tobesent = [p for p in pkt]
    received = SndRcvList()
    seen = {}

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]

    def send_in_loop(tobesent):
        while 1:
            for p in tobesent:
                yield p

    packets_to_send = send_in_loop(tobesent)

    ssock = rsock = pks.fileno()

    try:
        while 1:
            readyr,readys,_ = select([rsock],[ssock],[])
            if ssock in readys:
                pks.send(packets_to_send.next())
                
            if rsock in readyr:
                p = pks.recv(MTU)
                if p is None:
                    continue
                h = p.hashret()
                if h in hsent:
                    hlst = hsent[h]
                    for i in hlst:
                        if p.answers(i):
                            res = prn((i,p))
                            if unique:
                                if res in seen:
                                    continue
                                seen[res] = None
                            if res is not None:
                                print res
                            if store:
                                received.append((i,p))
    except KeyboardInterrupt:
        if chainCC:
            raise
    return received

def srflood(x,filter=None, iface=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 3
prn:      function applied to packets received. Ret val is printed if not None
store:    if 1 (default), store answers and return them
unique:   only consider packets whose print 
nofilter: put 1 to avoid use of bpf filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)
    r=sndrcvflood(s,x,*args,**kargs)
    s.close()
    return r

def srpflood(x,filter=None, iface=None, iface_hint=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 2
prn:      function applied to packets received. Ret val is printed if not None
store:    if 1 (default), store answers and return them
unique:   only consider packets whose print 
nofilter: put 1 to avoid use of bpf filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]    
    s = conf.L2socket(filter=filter, iface=iface, nofilter=nofilter)
    r=sndrcvflood(s,x,*args,**kargs)
    s.close()
    return r

           
## Bluetooth


def srbt(peer, pkts, inter=0.1, *args, **kargs):
    s = conf.BTsocket(peer=peer)
    a,b,c=sndrcv(s,pkts,inter=inter,*args,**kargs)
    s.close()
    return a,b

def srbt1(peer, pkts, *args, **kargs):
    a,b = srbt(peer, pkts, *args, **kargs)
    if len(a) > 0:
        return a[0][1]
        
    



#############################
## pcap capture file stuff ##
#############################

def wrpcap(filename, pkt, *args, **kargs):
    """Write a list of packets to a pcap file
gz: set to 1 to save a gzipped capture
linktype: force linktype value
endianness: "<" or ">", force endianness"""
    PcapWriter(filename, *args, **kargs).write(pkt)

def rdpcap(filename, count=-1):
    """Read a pcap file and return a packet list
count: read only <count> packets"""
    return PcapReader(filename).read_all(count=count)

class PcapReader:
    """A stateful pcap reader
    
    Based entirely on scapy.rdpcap(), this class allows for packets
    to be dispatched without having to be loaded into memory all at
    once
    """

    def __init__(self, filename):
        self.filename = filename
        try:
            self.f = gzip.open(filename,"rb")
            magic = self.f.read(4)
        except IOError:
            self.f = open(filename,"rb")
            magic = self.f.read(4)
        if magic == "\xa1\xb2\xc3\xd4": #big endian
            self.endian = ">"
        elif  magic == "\xd4\xc3\xb2\xa1": #little endian
            self.endian = "<"
        else:
            raise RuntimeWarning, "Not a pcap capture file (bad magic)"
        hdr = self.f.read(20)
        if len(hdr)<20:
            raise RuntimeWarning, "Invalid pcap file (too short)"
        vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(self.endian+"HHIIII",hdr)
        self.LLcls = LLTypes.get(linktype, Raw)
        if self.LLcls == Raw:
            warning("PcapReader: unkonwon LL type [%i]/[%#x]. Using Raw packets" % (linktype,linktype))

    def __iter__(self):
        return self

    def next(self):
        """impliment the iterator protocol on a set of packets in a
        pcap file
        """
        pkt = self.read_packet()
        if pkt == None:
            raise StopIteration
        return pkt


    def read_packet(self):
        """return a single packet read from the file
        
        returns None when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            return None
        sec,usec,caplen,olen = struct.unpack(self.endian+"IIII", hdr)
        s = self.f.read(caplen)
        try:
            p = self.LLcls(s)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            p = Raw(s)
        p.time = sec+0.000001*usec
        return p

    def dispatch(self, callback):
        """call the specified callback routine for each packet read
        
        This is just a convienience function for the main loop
        that allows for easy launching of packet processing in a 
        thread.
        """
        p = self.read_packet()
        while p != None:
            callback(p)
            p = self.read_packet()

    def read_all(self,count=-1):
        """return a list of all packets in the pcap file
        """
        res=[]
        while count != 0:
            count -= 1
            p = self.read_packet()
            if p is None:
                break
            res.append(p)
        return PacketList(res,name = os.path.basename(self.filename))

    def recv(self, size):
        """ Emulate a socket
        """
        return self.read_packet()

    def fileno(self):
        return self.f.fileno()
        


class PcapWriter:
    """A pcap writer with more control than wrpcap()
    
    This routine is based entirely on scapy.wrpcap(), but adds capability
    of writing one packet at a time in a streaming manner.
    """
    def __init__(self, filename, linktype=None, gz=0, endianness=""):
        self.linktype = linktype
        self.header_done = 0
        if gz:
            self.f = gzip.open(filename,"wb")
        else:
            self.f = open(filename,"wb")
        self.endian = endianness

    def fileno(self):
        return self.f.fileno()

    def write(self, pkt):
        """accepts a either a single packet or a list of packets
        to be written to the dumpfile
        """
        
        if self.header_done == 0:
            if self.linktype == None:
                if isinstance(pkt,Packet):
                    self.linktype = LLNumTypes.get(pkt.__class__,1)
                else:
                    self.linktype = LLNumTypes.get(pkt[0].__class__,1)

            self.f.write(struct.pack(self.endian+"IHHIIII", 0xa1b2c3d4L,
                                     2, 4, 0, 0, MTU, self.linktype))
            self.header_done = 1

        for p in pkt:
            self._write_packet(p)

    def _write_packet(self, packet):
        """writes a single packet to the pcap file
        """
        s = str(packet)
        l = len(s)
        sec = int(packet.time)
        usec = int((packet.time-sec)*1000000)
        self.f.write(struct.pack(self.endian+"IIII", sec, usec, l, l))
        self.f.write(s)

re_extract_hexcap = re.compile("^(0x[0-9a-fA-F]{2,}[ :\t]|(0x)?[0-9a-fA-F]{2,}:|(0x)?[0-9a-fA-F]{3,}[: \t]|) *(([0-9a-fA-F]{2} {,2}){,16})")

def import_hexcap():
    p = ""
    try:
        while 1:
            l = raw_input().strip()
            try:
                p += re_extract_hexcap.match(l).groups()[3]
            except:
                warning("Parsing error during hexcap")
                continue
    except EOFError:
        pass
    
    p = p.replace(" ","")
    p2=""
    for i in range(len(p)/2):
        p2 += chr(int(p[2*i:2*i+2],16))
    return p2
        


def wireshark(pktlist):
    f = os.tempnam("scapy")
    wrpcap(f, pktlist)
    os.spawnlp(os.P_NOWAIT, conf.prog.wireshark, conf.prog.wireshark, "-r", f)

def hexedit(x):
    x = str(x)
    f = os.tempnam("scapy")
    open(f,"w").write(x)
    os.spawnlp(os.P_WAIT, conf.prog.hexedit, conf.prog.hexedit, f)
    x = open(f).read()
    os.unlink(f)
    return x


#####################
## knowledge bases ##
#####################

class KnowledgeBase:
    def __init__(self, filename):
        self.filename = filename
        self.base = None

    def lazy_init(self):
        self.base = ""

    def reload(self, filename = None):
        if filename is not None:
            self.filename = filename
        oldbase = self.base
        self.base = None
        self.lazy_init()
        if self.base is None:
            self.base = oldbase

    def get_base(self):
        if self.base is None:
            self.lazy_init()
        return self.base
    


##########################
## IP location database ##
##########################

class IPCountryKnowledgeBase(KnowledgeBase):
    """
How to generate the base :
db = []
for l in open("GeoIPCountryWhois.csv").readlines():
    s,e,c = l.split(",")[2:5]
    db.append((int(s[1:-1]),int(e[1:-1]),c[1:-1]))
cPickle.dump(gzip.open("xxx","w"),db)
"""
    def lazy_init(self):
        self.base = load_object(self.filename)


class CountryLocKnowledgeBase(KnowledgeBase):
    def lazy_init(self):
        f=open(self.filename)
        self.base = {}
        while 1:
            l = f.readline()
            if not l:
                break
            l = l.strip().split(",")
            if len(l) != 3:
                continue
            c,lat,long = l
            
            self.base[c] = (float(long),float(lat))
        f.close()
            
        


def locate_ip(ip):
    ip=map(int,ip.split("."))
    ip = ip[3]+(ip[2]<<8L)+(ip[1]<<16L)+(ip[0]<<24L)

    cloc = country_loc_kdb.get_base()
    db = IP_country_kdb.get_base()

    d=0
    f=len(db)-1
    while (f-d) > 1:
        guess = (d+f)/2
        if ip > db[guess][0]:
            d = guess
        else:
            f = guess
    s,e,c = db[guess]
    if  s <= ip and ip <= e:
        return cloc.get(c,None)


    

###############
## p0f stuff ##
###############

# File format (according to p0f.fp) :
#
# wwww:ttt:D:ss:OOO...:QQ:OS:Details
#
# wwww    - window size
# ttt     - initial TTL
# D       - don't fragment bit  (0=unset, 1=set) 
# ss      - overall SYN packet size
# OOO     - option value and order specification
# QQ      - quirks list
# OS      - OS genre
# details - OS description



class p0fKnowledgeBase(KnowledgeBase):
    def __init__(self, filename):
        KnowledgeBase.__init__(self, filename)
        #self.ttl_range=[255]
    def lazy_init(self):
        try:
            f=open(self.filename)
        except IOError:
            warning("Can't open base %s" % self.filename)
            return
        try:
            self.base = []
            for l in f:
                if l[0] in ["#","\n"]:
                    continue
                l = tuple(l.split(":"))
                if len(l) < 8:
                    continue
                li = map(int,l[1:4])
                #if li[0] not in self.ttl_range:
                #    self.ttl_range.append(li[0])
                #    self.ttl_range.sort()
                self.base.append((l[0], li[0], li[1], li[2], l[4], l[5], l[6], l[7][:-1]))
        except:
            warning("Can't parse p0f database (new p0f version ?)")
            self.base = None
        f.close()


def packet2p0f(pkt):
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    if not isinstance(pkt, IP) or not isinstance(pkt.payload, TCP):
        raise TypeError("Not a TCP/IP packet")
    if pkt.payload.flags & 0x13 != 0x02: #S,!A,!F
        raise TypeError("Not a syn packet")
    
    #t = p0f_kdb.ttl_range[:]
    #t += [pkt.ttl]
    #t.sort()
    #ttl=t[t.index(pkt.ttl)+1]
    ttl = pkt.ttl

    df = (pkt.flags & 2) / 2
    ss = len(pkt)
    # from p0f/config.h : PACKET_BIG = 100
    if ss > 100:
        ss = 0

    ooo = ""
    mss = -1
    qqT = False
    qqP = False
    #qqBroken = False
    ilen = (pkt[TCP].dataofs << 2) - 20 # from p0f.c
    for option in pkt.payload.options:
        ilen -= 1
        if option[0] == "MSS":
            ooo += "M" + str(option[1]) + ","
            mss = option[1]
            # FIXME: qqBroken
            ilen -= 3
        elif option[0] == "WScale":
            ooo += "W" + str(option[1]) + ","
            # FIXME: qqBroken
            ilen -= 2
        elif option[0] == "Timestamp":
            if option[1][0] == 0:
                ooo += "T0,"
            else:
                ooo += "T,"
            if option[1][1] != 0:
                qqT = True
            ilen -= 9
        elif option[0] == "SAckOK":
            ooo += "S,"
            ilen -= 1
        elif option[0] == "NOP":
            ooo += "N,"
        elif option[0] == "EOL":
            ooo += "E,"
            if ilen > 0:
                qqP = True
        else:
            ooo += "?,"
            # FIXME: ilen
    ooo = ooo[:-1]
    if ooo == "": ooo = "."

    win = pkt.payload.window
    if mss != -1:
        if win % mss == 0:
            win = "S" + str(win/mss)
        elif win % (mss + 40) == 0:
            win = "T" + str(win/(mss+40))
        win = str(win)

    qq = ""

    if qqP:
        qq += "P"
    if pkt[IP].id == 0:
        qq += "Z"
    if pkt[IP].options != '':
        qq += "I"
    if pkt[TCP].urgptr != 0:
        qq += "U"
    if pkt[TCP].reserved != 0:
        qq += "X"
    if pkt[TCP].ack != 0:
        qq += "A"
    if qqT:
        qq += "T"
    if pkt[TCP].flags & 40 != 0:
        # U or P
        qq += "F"
    if not isinstance(pkt[TCP].payload, NoPayload):
        qq += "D"
    # FIXME : "!" - broken options segment

    if qq == "":
        qq = "."

    return (win,
            ttl,
            df,
            ss,
            ooo,
            qq)

def p0f_correl(x,y):
    d = 0
    # wwww can be "*" or "%nn"
    d += (x[0] == y[0] or y[0] == "*" or (y[0][0] == "%" and x[0].isdigit() and (int(x[0]) % int(y[0][1:])) == 0))
    # ttl
    d += (y[1] >= x[1] and y[1] - x[1] < 32)
    for i in [2, 3, 5]:
        d += (x[i] == y[i])
    xopt = x[4].split(",")
    yopt = y[4].split(",")
    if len(xopt) == len(yopt):
        same = True
        for i in range(len(xopt)):
            if not (xopt[i] == yopt[i] or
                    (len(yopt[i]) == 2 and len(xopt[i]) > 1 and
                     yopt[i][1] == "*" and xopt[i][0] == yopt[i][0]) or
                    (len(yopt[i]) > 2 and len(xopt[i]) > 1 and
                     yopt[i][1] == "%" and xopt[i][0] == yopt[i][0] and
                     int(xopt[i][1:]) % int(yopt[i][2:]) == 0)):
                same = False
                break
        if same:
            d += len(xopt)
    return d


def p0f(pkt):
    """Passive OS fingerprinting: which OS emitted this TCP SYN ?
p0f(packet) -> accuracy, [list of guesses]
"""
    pb = p0f_kdb.get_base()
    if not pb:
        warning("p0f base empty.")
        return []
    s = len(pb[0][0])
    r = []
    sig = packet2p0f(pkt)
    max = len(sig[4].split(",")) + 5
    for b in pb:
        d = p0f_correl(sig,b)
        if d == max:
            r.append((b[6], b[7], b[1] - pkt[IP].ttl))
    return r
            

def prnp0f(pkt):
    try:
        r = p0f(pkt)
    except:
        return
    if r == []:
        r = ("UNKNOWN", "[" + ":".join(map(str, packet2p0f(pkt))) + ":?:?]", None)
    else:
        r = r[0]
    uptime = None
    try:
        uptime = pkt2uptime(pkt)
    except:
        pass
    if uptime == 0:
        uptime = None
    res = pkt.sprintf("%IP.src%:%TCP.sport% - " + r[0] + " " + r[1])
    if uptime is not None:
        res += pkt.sprintf(" (up: " + str(uptime/3600) + " hrs)\n  -> %IP.dst%:%TCP.dport%")
    else:
        res += pkt.sprintf("\n  -> %IP.dst%:%TCP.dport%")
    if r[2] is not None:
        res += " (distance " + str(r[2]) + ")"
    print res


def pkt2uptime(pkt, HZ=100):
    """Calculate the date the machine which emitted the packet booted using TCP timestamp
pkt2uptime(pkt, [HZ=100])"""
    if not isinstance(pkt, Packet):
        raise TypeError("Not a TCP packet")
    if isinstance(pkt,NoPayload):
        raise TypeError("Not a TCP packet")
    if not isinstance(pkt, TCP):
        return pkt2uptime(pkt.payload)
    for opt in pkt.options:
        if opt[0] == "Timestamp":
            #t = pkt.time - opt[1][0] * 1.0/HZ
            #return time.ctime(t)
            t = opt[1][0] / HZ
            return t
    raise TypeError("No timestamp option")



#################
## Queso stuff ##
#################


def quesoTCPflags(flags):
    if flags == "-":
        return "-"
    flv = "FSRPAUXY"
    v = 0
    for i in flags:
        v |= 2**flv.index(i)
    return "%x" % v

class QuesoKnowledgeBase(KnowledgeBase):
    def lazy_init(self):
        try:
            f = open(self.filename)
        except IOError:
            return
        self.base = {}
        p = None
        try:
            for l in f:
                l = l.strip()
                if not l or l[0] == ';':
                    continue
                if l[0] == '*':
                    if p is not None:
                        p[""] = name
                    name = l[1:].strip()
                    p = self.base
                    continue
                if l[0] not in list("0123456"):
                    continue
                res = l[2:].split()
                res[-1] = quesoTCPflags(res[-1])
                res = " ".join(res)
                if not p.has_key(res):
                    p[res] = {}
                p = p[res]
            if p is not None:
                p[""] = name
        except:
            self.base = None
            warning("Can't load queso base [%s]", self.filename)
        f.close()
            
        

    
def queso_sig(target, dport=80, timeout=3):
    p = queso_kdb.get_base()
    ret = []
    for flags in ["S", "SA", "F", "FA", "SF", "P", "SEC"]:
        ans, unans = sr(IP(dst=target)/TCP(dport=dport,flags=flags,seq=RandInt()),
                        timeout=timeout, verbose=0)
        if len(ans) == 0:
            rs = "- - - -"
        else:
            s,r = ans[0]
            rs = "%i" % (r.seq != 0)
            if not r.ack:
                r += " 0"
            elif r.ack-s.seq > 666:
                rs += " R" % 0
            else:
                rs += " +%i" % (r.ack-s.seq)
            rs += " %X" % r.window
            rs += " %x" % r.payload.flags
        ret.append(rs)
    return ret
            
def queso_search(sig):
    p = queso_kdb.get_base()
    sig.reverse()
    ret = []
    try:
        while sig:
            s = sig.pop()
            p = p[s]
            if p.has_key(""):
                ret.append(p[""])
    except KeyError:
        pass
    return ret
        

def queso(*args,**kargs):
    """Queso OS fingerprinting
queso(target, dport=80, timeout=3)"""
    return queso_search(queso_sig(*args, **kargs))



######################
## nmap OS fp stuff ##
######################


class NmapKnowledgeBase(KnowledgeBase):
    def lazy_init(self):
        try:
            f=open(self.filename)
        except IOError:
            return

        self.base = []
        name = None
        try:
            for l in f:
                l = l.strip()
                if not l or l[0] == "#":
                    continue
                if l[:12] == "Fingerprint ":
                    if name is not None:
                        self.base.append((name,sig))
                    name = l[12:].strip()
                    sig={}
                    p = self.base
                    continue
                elif l[:6] == "Class ":
                    continue
                op = l.find("(")
                cl = l.find(")")
                if op < 0 or cl < 0:
                    warning("error reading nmap os fp base file")
                    continue
                test = l[:op]
                s = map(lambda x: x.split("="), l[op+1:cl].split("%"))
                si = {}
                for n,v in s:
                    si[n] = v
                sig[test]=si
            if name is not None:
                self.base.append((name,sig))
        except:
            self.base = None
            warning("Can't read nmap database [%s](new nmap version ?)" % self.filename)
        f.close()
        
def TCPflags2str(f):
    fl="FSRPAUEC"
    s=""
    for i in range(len(fl)):
        if f & 1:
            s = fl[i]+s
        f >>= 1
    return s

def nmap_tcppacket_sig(pkt):
    r = {}
    if pkt is not None:
#        r["Resp"] = "Y"
        r["DF"] = (pkt.flags & 2) and "Y" or "N"
        r["W"] = "%X" % pkt.window
        r["ACK"] = pkt.ack==2 and "S++" or pkt.ack==1 and "S" or "O"
        r["Flags"] = TCPflags2str(pkt.payload.flags)
        r["Ops"] = "".join(map(lambda x: x[0][0],pkt.payload.options))
    else:
        r["Resp"] = "N"
    return r


def nmap_udppacket_sig(S,T):
    r={}
    if T is None:
        r["Resp"] = "N"
    else:
        r["DF"] = (T.flags & 2) and "Y" or "N"
        r["TOS"] = "%X" % T.tos
        r["IPLEN"] = "%X" % T.len
        r["RIPTL"] = "%X" % T.payload.payload.len
        r["RID"] = S.id == T.payload.payload.id and "E" or "F"
        r["RIPCK"] = S.chksum == T.getlayer(IPerror).chksum and "E" or T.getlayer(IPerror).chksum == 0 and "0" or "F"
        r["UCK"] = S.payload.chksum == T.getlayer(UDPerror).chksum and "E" or T.getlayer(UDPerror).chksum ==0 and "0" or "F"
        r["ULEN"] = "%X" % T.getlayer(UDPerror).len
        r["DAT"] = T.getlayer(Raw) is None and "E" or S.getlayer(Raw).load == T.getlayer(Raw).load and "E" or "F"
    return r
    


def nmap_match_one_sig(seen, ref):
    c = 0
    for k in seen.keys():
        if ref.has_key(k):
            if seen[k] in ref[k].split("|"):
                c += 1
    if c == 0 and seen.get("Resp") == "N":
        return 0.7
    else:
        return 1.0*c/len(seen.keys())
        
        

def nmap_sig(target, oport=80, cport=81, ucport=1):
    res = {}

    tcpopt = [ ("WScale", 10),
               ("NOP",None),
               ("MSS", 256),
               ("Timestamp",(123,0)) ]
    tests = [ IP(dst=target, id=1)/TCP(seq=1, sport=5001, dport=oport, options=tcpopt, flags="CS"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5002, dport=oport, options=tcpopt, flags=0),
              IP(dst=target, id=1)/TCP(seq=1, sport=5003, dport=oport, options=tcpopt, flags="SFUP"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5004, dport=oport, options=tcpopt, flags="A"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5005, dport=cport, options=tcpopt, flags="S"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5006, dport=cport, options=tcpopt, flags="A"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5007, dport=cport, options=tcpopt, flags="FPU"),
              IP(str(IP(dst=target)/UDP(sport=5008,dport=ucport)/(300*"i"))) ]

    ans, unans = sr(tests, timeout=2)
    ans += map(lambda x: (x,None), unans)

    for S,T in ans:
        if S.sport == 5008:
            res["PU"] = nmap_udppacket_sig(S,T)
        else:
            t = "T%i" % (S.sport-5000)
            if T is not None and T.haslayer(ICMP):
                warning("Test %s answered by an ICMP" % t)
                T=None
            res[t] = nmap_tcppacket_sig(T)

    return res

def nmap_probes2sig(tests):
    tests=tests.copy()
    res = {}
    if "PU" in tests:
        res["PU"] = nmap_udppacket_sig(*tests["PU"])
        del(tests["PU"])
    for k in tests:
        res[k] = nmap_tcppacket_sig(tests[k])
    return res
        

def nmap_search(sigs):
    guess = 0,[]
    for os,fp in nmap_kdb.get_base():
        c = 0.0
        for t in sigs.keys():
            if t in fp:
                c += nmap_match_one_sig(sigs[t], fp[t])
        c /= len(sigs.keys())
        if c > guess[0]:
            guess = c,[ os ]
        elif c == guess[0]:
            guess[1].append(os)
    return guess
    
    
def nmap_fp(target, oport=80, cport=81):
    """nmap fingerprinting
nmap_fp(target, [oport=80,] [cport=81,]) -> list of best guesses with accuracy
"""
    sigs = nmap_sig(target, oport, cport)
    return nmap_search(sigs)
        

def nmap_sig2txt(sig):
    torder = ["TSeq","T1","T2","T3","T4","T5","T6","T7","PU"]
    korder = ["Class", "gcd", "SI", "IPID", "TS",
              "Resp", "DF", "W", "ACK", "Flags", "Ops",
              "TOS", "IPLEN", "RIPTL", "RID", "RIPCK", "UCK", "ULEN", "DAT" ]
    txt=[]
    for i in sig.keys():
        if i not in torder:
            torder.append(i)
    for t in torder:
        sl = sig.get(t)
        if sl is None:
            continue
        s = []
        for k in korder:
            v = sl.get(k)
            if v is None:
                continue
            s.append("%s=%s"%(k,v))
        txt.append("%s(%s)" % (t, "%".join(s)))
    return "\n".join(txt)
            
        



###################
## User commands ##
###################


def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
    """
    c = 0

    if offline is None:
        if L2socket is None:
            L2socket = conf.L2listen
        s = L2socket(type=ETH_P_ALL, *arg, **karg)
    else:
        s = PcapReader(offline)

    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    while 1:
        try:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break
            sel = select([s],[],[],remain)
            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                c += 1
                if prn:
                    r = prn(p)
                    if r is not None:
                        print r
                if count > 0 and c >= count:
                    break
        except KeyboardInterrupt:
            break
    return PacketList(lst,"Sniffed")



def arpcachepoison(target, victim, interval=60):
    """Poison target's cache with (your MAC,victim's IP) couple
arpcachepoison(target, victim, [interval=60]) -> None
"""
    tmac = getmacbyip(target)
    p = Ether(dst=tmac)/ARP(op="who-has", psrc=victim, pdst=target)
    try:
        while 1:
            sendp(p, iface_hint=target)
            if conf.verb > 1:
                os.write(1,".")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

def traceroute(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), l4 = None, filter=None, timeout=2, verbose=None, **kargs):
    """Instant TCP traceroute
traceroute(target, [maxttl=30,] [dport=80,] [sport=80,] [verbose=conf.verb]) -> None
"""
    if verbose is None:
        verbose = conf.verb
    if filter is None:
        filter="(icmp and icmp[0]=11) or (tcp and (tcp[13] & 0x16 > 0x10))"
    if l4 is None:
        a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/TCP(seq=RandInt(),sport=sport, dport=dport),
                 timeout=timeout, filter=filter, verbose=verbose, **kargs)
    else:
        a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/l4,
                 verbose=verbose, timeout=timeout, **kargs)

    a = TracerouteResult(a.res)
    if verbose:
        a.show()
    return a,b




def arping(net, timeout=2, cache=0, verbose=None, **kargs):
    """Send ARP who-has requests to determine which hosts are up
arping(net, [cache=0,] [iface=conf.iface,] [verbose=conf.verb]) -> None
Set cache=True if you want arping to modify internal ARP-Cache"""
    if verbose is None:
        verbose = conf.verb
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net), verbose=verbose,
                    filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)
    ans = ARPingResult(ans.res)

    if cache and ans is not None:
        for pair in ans:
            arp_cache[pair[1].psrc] = (pair[1].hwsrc, time.time())
    if verbose:
        ans.show()
    return ans,unans

def dyndns_add(nameserver, name, rdata, type="A", ttl=10):
    """Send a DNS add message to a nameserver for "name" to have a new "rdata"
dyndns_add(nameserver, name, rdata, type="A", ttl=10) -> result code (0=ok)

example: dyndns_add("ns1.toto.com", "dyn.toto.com", "127.0.0.1")
RFC2136
"""
    zone = name[name.find(".")+1:]
    r=sr1(IP(dst=nameserver)/UDP()/DNS(opcode=5,
                                       qd=[DNSQR(qname=zone, qtype="SOA")],
                                       ns=[DNSRR(rrname=name, type="A",
                                                 ttl=ttl, rdata=rdata)]),
          verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1
    
    
    

def dyndns_del(nameserver, name, type="ALL", ttl=10):
    """Send a DNS delete message to a nameserver for "name"
dyndns_del(nameserver, name, type="ANY", ttl=10) -> result code (0=ok)

example: dyndns_del("ns1.toto.com", "dyn.toto.com")
RFC2136
"""
    zone = name[name.find(".")+1:]
    r=sr1(IP(dst=nameserver)/UDP()/DNS(opcode=5,
                                       qd=[DNSQR(qname=zone, qtype="SOA")],
                                       ns=[DNSRR(rrname=name, type=type,
                                                 rclass="ANY", ttl=0, rdata="")]),
          verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1
    

def is_promisc(ip, fake_bcast="ff:ff:00:00:00:00",**kargs):
    """Try to guess if target is in Promisc mode. The target is provided by its ip."""

    responses = srp1(Ether(dst=fake_bcast) / ARP(op="who-has", pdst=ip),type=ETH_P_ARP, iface_hint=ip, timeout=1, verbose=0,**kargs)

    return responses is not None

def promiscping(net, timeout=2, fake_bcast="ff:ff:ff:ff:ff:fe", **kargs):
    """Send ARP who-has requests to determine which hosts are in promiscuous mode
    promiscping(net, iface=conf.iface)"""
    ans,unans = srp(Ether(dst=fake_bcast)/ARP(pdst=net),
                    filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)
    ans = ARPingResult(ans.res, name="PROMISCPing")

    ans.display()
    return ans,unans

def ikescan(ip):
    return sr(IP(dst=ip)/UDP()/ISAKMP(init_cookie=RandString(8),
                                      exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal()))


def dhcp_request(iface=None,**kargs):
    if conf.checkIPaddr != 0:
        warning("conf.checkIPaddr is not 0, I may not be able to match the answer")
    if iface is None:
        iface = conf.iface
    fam,hw = get_if_raw_hwaddr(iface)
    return srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)
                 /BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"]),iface=iface,**kargs)

def snmpwalk(dst, oid="1", community="public"):
    try:
        while 1:
            r = sr1(IP(dst=dst)/UDP(sport=RandShort())/SNMP(community=community, PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=oid)])),timeout=2, chainCC=1, verbose=0, retry=2)
            if ICMP in r:
                print repr(r)
                break
            if r is None:
                print "No answers"
                break
            print "%-40s: %r" % (r[SNMPvarbind].oid.val,r[SNMPvarbind].value)
            oid = r[SNMPvarbind].oid
            
    except KeyboardInterrupt:
        pass


#####################
## Reporting stuff ##
#####################

def report_ports(target, ports):
    """portscan a target and output a LaTeX table
report_ports(target, ports) -> string"""
    ans,unans = sr(IP(dst=target)/TCP(dport=ports),timeout=5)
    rep = "\\begin{tabular}{|r|l|l|}\n\\hline\n"
    for s,r in ans:
        if not r.haslayer(ICMP):
            if r.payload.flags == 0x12:
                rep += r.sprintf("%TCP.sport% & open & SA \\\\\n")
    rep += "\\hline\n"
    for s,r in ans:
        if r.haslayer(ICMP):
            rep += r.sprintf("%TCPerror.dport% & closed & ICMP type %ICMP.type%/%ICMP.code% from %IP.src% \\\\\n")
        elif r.payload.flags != 0x12:
            rep += r.sprintf("%TCP.sport% & closed & TCP %TCP.flags% \\\\\n")
    rep += "\\hline\n"
    for i in unans:
        rep += i.sprintf("%TCP.dport% & ? & unanswered \\\\\n")
    rep += "\\hline\n\\end{tabular}\n"
    return rep


def __make_table(yfmtfunc, fmtfunc, endline, list, fxyz, sortx=None, sorty=None, seplinefunc=None):
    vx = {} 
    vy = {} 
    vz = {}
    vxf = {}
    vyf = {}
    l = 0
    for e in list:
        xx,yy,zz = map(str, fxyz(e))
        l = max(len(yy),l)
        vx[xx] = max(vx.get(xx,0), len(xx), len(zz))
        vy[yy] = None
        vz[(xx,yy)] = zz

    vxk = vx.keys()
    vyk = vy.keys()
    if sortx:
        vxk.sort(sortx)
    else:
        try:
            vxk.sort(lambda x,y:int(x)-int(y))
        except:
            try:
                vxk.sort(lambda x,y: cmp(atol(x),atol(y)))
            except:
                vxk.sort()
    if sorty:
        vyk.sort(sorty)
    else:
        try:
            vyk.sort(lambda x,y:int(x)-int(y))
        except:
            try:
                vyk.sort(lambda x,y: cmp(atol(x),atol(y)))
            except:
                vyk.sort()


    if seplinefunc:
        sepline = seplinefunc(l, map(lambda x:vx[x],vxk))
        print sepline

    fmt = yfmtfunc(l)
    print fmt % "",
    for x in vxk:
        vxf[x] = fmtfunc(vx[x])
        print vxf[x] % x,
    print endline
    if seplinefunc:
        print sepline
    for y in vyk:
        print fmt % y,
        for x in vxk:
            print vxf[x] % vz.get((x,y), "-"),
        print endline
    if seplinefunc:
        print sepline

def make_table(*args, **kargs):
    __make_table(lambda l:"%%-%is" % l, lambda l:"%%-%is" % l, "", *args, **kargs)
    
def make_lined_table(*args, **kargs):
    __make_table(lambda l:"%%-%is |" % l, lambda l:"%%-%is |" % l, "",
                 seplinefunc=lambda a,x:"+".join(map(lambda y:"-"*(y+2), [a-1]+x+[-2])),
                 *args, **kargs)

def make_tex_table(*args, **kargs):
    __make_table(lambda l: "%s", lambda l: "& %s", "\\\\", seplinefunc=lambda a,x:"\\hline", *args, **kargs)
    

######################
## Online doc stuff ##
######################


def lsc(cmd=None):
    """List user commands"""
    if cmd is None:
        for c in user_commands:
            doc = "No doc. available"
            if c.__doc__:
                doc = c.__doc__.split("\n")[0]
            
            print "%-16s : %s" % (c.__name__, doc)
    else:
        print cmd.__doc__

def ls(obj=None):
    """List  available layers, or infos on a given layer"""
    if obj is None:
        import __builtin__
        all = __builtin__.__dict__.copy()
        all.update(globals())
        objlst = filter(lambda (n,o): isinstance(o,type) and issubclass(o,Packet), all.items())
        objlst.sort(lambda x,y:cmp(x[0],y[0]))
        for n,o in objlst:
            print "%-10s : %s" %(n,o.name)
    else:
        if isinstance(obj, type) and issubclass(obj, Packet):
            for f in obj.fields_desc:
                print "%-10s : %-20s = (%s)" % (f.name, f.__class__.__name__,  repr(f.default))
        elif isinstance(obj, Packet):
            for f in obj.fields_desc:
                print "%-10s : %-20s = %-15s (%s)" % (f.name, f.__class__.__name__, repr(getattr(obj,f.name)), repr(f.default))
            if not isinstance(obj.payload, NoPayload):
                print "--"
                ls(obj.payload)
                

        else:
            print "Not a packet class. Type 'ls()' to list packet classes."


    


user_commands = [ sr, sr1, srp, srp1, srloop, srploop, sniff, p0f, arpcachepoison, send, sendp, traceroute, arping, ls, lsc, queso, nmap_fp, report_ports, dyndns_add, dyndns_del, is_promisc, promiscping ]


##############
## Automata ##
##############

class ATMT:
    STATE = "State"
    ACTION = "Action"
    CONDITION = "Condition"
    RECV = "Receive condition"
    TIMEOUT = "Timeout condition"

    class NewStateRequested(Exception):
        def __init__(self, state_func, automaton, *args, **kargs):
            self.func = state_func
            self.state = state_func.atmt_state
            self.initial = state_func.atmt_initial
            self.error = state_func.atmt_error
            self.final = state_func.atmt_final
            Exception.__init__(self, "Request state [%s]" % self.state)
            self.automaton = automaton
            self.args = args
            self.kargs = kargs
            self.action_parameters() # init action parameters
        def action_parameters(self, *args, **kargs):
            self.action_args = args
            self.action_kargs = kargs
            return self
        def run(self):
            return self.func(self.automaton, *self.args, **self.kargs)

    @staticmethod
    def state(initial=0,final=0,error=0):
        def deco(f,initial=initial, final=final):
            f.atmt_type = ATMT.STATE
            f.atmt_state = f.func_name
            f.atmt_initial = initial
            f.atmt_final = final
            f.atmt_error = error
            def state_wrapper(self, *args, **kargs):
                return ATMT.NewStateRequested(f, self, *args, **kargs)

            state_wrapper.func_name = "%s_wrapper" % f.func_name
            state_wrapper.atmt_type = ATMT.STATE
            state_wrapper.atmt_state = f.func_name
            state_wrapper.atmt_initial = initial
            state_wrapper.atmt_final = final
            state_wrapper.atmt_error = error
            state_wrapper.atmt_origfunc = f
            return state_wrapper
        return deco
    @staticmethod
    def action(cond, prio=0):
        def deco(f,cond=cond):
            if not hasattr(f,"atmt_type"):
                f.atmt_cond = {}
            f.atmt_type = ATMT.ACTION
            f.atmt_cond[cond.atmt_condname] = prio
            return f
        return deco
    @staticmethod
    def condition(state, prio=0):
        def deco(f, state=state):
            f.atmt_type = ATMT.CONDITION
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.func_name
            f.atmt_prio = prio
            return f
        return deco
    @staticmethod
    def receive_condition(state, prio=0):
        def deco(f, state=state):
            f.atmt_type = ATMT.RECV
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.func_name
            f.atmt_prio = prio
            return f
        return deco
    @staticmethod
    def timeout(state, timeout):
        def deco(f, state=state, timeout=timeout):
            f.atmt_type = ATMT.TIMEOUT
            f.atmt_state = state.atmt_state
            f.atmt_timeout = timeout
            f.atmt_condname = f.func_name
            return f
        return deco


class Automaton_metaclass(type):
    def __new__(cls, name, bases, dct):
        cls = super(Automaton_metaclass, cls).__new__(cls, name, bases, dct)
        cls.states={}
        cls.state = None
        cls.recv_conditions={}
        cls.conditions={}
        cls.timeout={}
        cls.actions={}
        cls.initial_states=[]

        members = {}
        classes = [cls]
        while classes:
            c = classes.pop(0) # order is important to avoid breaking method overloading
            classes += list(c.__bases__)
            for k,v in c.__dict__.iteritems():
                if k not in members:
                    members[k] = v

        decorated = [v for v in members.itervalues()
                     if type(v) is types.FunctionType and hasattr(v, "atmt_type")]
        
        for m in decorated:
            if m.atmt_type == ATMT.STATE:
                s = m.atmt_state
                cls.states[s] = m
                cls.recv_conditions[s]=[]
                cls.conditions[s]=[]
                cls.timeout[s]=[]
                if m.atmt_initial:
                    cls.initial_states.append(m)
            elif m.atmt_type in [ATMT.CONDITION, ATMT.RECV, ATMT.TIMEOUT]:
                cls.actions[m.atmt_condname] = []
    
        for m in decorated:
            if m.atmt_type == ATMT.CONDITION:
                cls.conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.RECV:
                cls.recv_conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.TIMEOUT:
                cls.timeout[m.atmt_state].append((m.atmt_timeout, m))
            elif m.atmt_type == ATMT.ACTION:
                for c in m.atmt_cond:
                    cls.actions[c].append(m)
            

        for v in cls.timeout.itervalues():
            v.sort(lambda (t1,f1),(t2,f2): cmp(t1,t2))
            v.append((None, None))
        for v in itertools.chain(cls.conditions.itervalues(),
                                 cls.recv_conditions.itervalues()):
            v.sort(lambda c1,c2: cmp(c1.atmt_prio,c2.atmt_prio))
        for condname,actlst in cls.actions.iteritems():
            actlst.sort(lambda c1,c2: cmp(c1.atmt_cond[condname], c2.atmt_cond[condname]))

        return cls

        
    def graph(self, **kargs):
        s = 'digraph "%s" {\n'  % self.__class__.__name__
        
        se = "" # Keep initial nodes at the begining for better rendering
        for st in self.states.itervalues():
            if st.atmt_initial:
                se = ('\t"%s" [ style=filled, fillcolor=blue, shape=box, root=true];\n' % st.atmt_state)+se
            elif st.atmt_final:
                se += '\t"%s" [ style=filled, fillcolor=green, shape=octagon ];\n' % st.atmt_state
            elif st.atmt_error:
                se += '\t"%s" [ style=filled, fillcolor=red, shape=octagon ];\n' % st.atmt_state
        s += se

        for st in self.states.values():
            for n in st.atmt_origfunc.func_code.co_names+st.atmt_origfunc.func_code.co_consts:
                if n in self.states:
                    s += '\t"%s" -> "%s" [ color=green ];\n' % (st.atmt_state,n)
            

        for c,k,v in [("purple",k,v) for k,v in self.conditions.items()]+[("red",k,v) for k,v in self.recv_conditions.items()]:
            for f in v:
                for n in f.func_code.co_names+f.func_code.co_consts:
                    if n in self.states:
                        l = f.atmt_condname
                        for x in self.actions[f.atmt_condname]:
                            l += "\\l>[%s]" % x.func_name
                        s += '\t"%s" -> "%s" [label="%s", color=%s];\n' % (k,n,l,c)
        for k,v in self.timeout.iteritems():
            for t,f in v:
                if f is None:
                    continue
                for n in f.func_code.co_names+f.func_code.co_consts:
                    if n in self.states:
                        l = "%s/%.1fs" % (f.atmt_condname,t)                        
                        for x in self.actions[f.atmt_condname]:
                            l += "\\l>[%s]" % x.func_name
                        s += '\t"%s" -> "%s" [label="%s",color=blue];\n' % (k,n,l)
        s += "}\n"
        return do_graph(s, **kargs)
        


class Automaton:
    __metaclass__ = Automaton_metaclass

    def __init__(self, *args, **kargs):
        self.debug_level=0
        self.init_args=args
        self.init_kargs=kargs
        self.parse_args(*args, **kargs)

    def debug(self, lvl, msg):
        if self.debug_level >= lvl:
            log_interactive.debug(msg)
            



    class ErrorState(Exception):
        def __init__(self, msg, result=None):
            Exception.__init__(self, msg)
            self.result = result
    class Stuck(ErrorState):
        pass

    def parse_args(self, debug=0, store=1, **kargs):
        self.debug_level=debug
        self.socket_kargs = kargs
        self.store_packets = store
        

    def master_filter(self, pkt):
        return True

    def run_condition(self, cond, *args, **kargs):
        try:
            cond(self,*args, **kargs)
        except ATMT.NewStateRequested, state_req:
            self.debug(2, "%s [%s] taken to state [%s]" % (cond.atmt_type, cond.atmt_condname, state_req.state))
            if cond.atmt_type == ATMT.RECV:
                self.packets.append(args[0])
            for action in self.actions[cond.atmt_condname]:
                self.debug(2, "   + Running action [%s]" % action.func_name)
                action(self, *state_req.action_args, **state_req.action_kargs)
            raise
        else:
            self.debug(2, "%s [%s] not taken" % (cond.atmt_type, cond.atmt_condname))
            

    def run(self, *args, **kargs):
        # Update default parameters
        a = args+self.init_args[len(args):]
        k = self.init_kargs
        k.update(kargs)
        self.parse_args(*a,**k)

        # Start the automaton
        self.state=self.initial_states[0](self)
        self.send_sock = conf.L3socket()
        l = conf.L2listen(**self.socket_kargs)
        self.packets = PacketList(name="session[%s]"%self.__class__.__name__)
        while 1:
            try:
                self.debug(1, "## state=[%s]" % self.state.state)

                # Entering a new state. First, call new state function
                state_output = self.state.run()
                if self.state.error:
                    raise self.ErrorState("Reached %s: [%r]" % (self.state.state, state_output), result=state_output)
                if self.state.final:
                    return state_output

                if state_output is None:
                    state_output = ()
                elif type(state_output) is not list:
                    state_output = state_output,
                
                # Then check immediate conditions
                for cond in self.conditions[self.state.state]:
                    self.run_condition(cond, *state_output)

                # If still there and no conditions left, we are stuck!
                if ( len(self.recv_conditions[self.state.state]) == 0
                     and len(self.timeout[self.state.state]) == 1 ):
                    raise self.Stuck("stuck in [%s]" % self.state.state,result=state_output)

                # Finally listen and pay attention to timeouts
                expirations = iter(self.timeout[self.state.state])
                next_timeout,timeout_func = expirations.next()
                t0 = time.time()
                
                while 1:
                    t = time.time()-t0
                    if next_timeout is not None:
                        if next_timeout <= t:
                            self.run_condition(timeout_func, *state_output)
                            next_timeout,timeout_func = expirations.next()
                    if next_timeout is None:
                        remain = None
                    else:
                        remain = next_timeout-t
    
                    r,_,_ = select([l],[],[],remain)
                    if l in r:
                        pkt = l.recv(MTU)
                        if pkt is not None:
                            if self.master_filter(pkt):
                                self.debug(3, "RECVD: %s" % pkt.summary())
                                for rcvcond in self.recv_conditions[self.state.state]:
                                    self.run_condition(rcvcond, pkt, *state_output)
                            else:
                                self.debug(4, "FILTR: %s" % pkt.summary())

            except ATMT.NewStateRequested,state_req:
                self.debug(2, "switching from [%s] to [%s]" % (self.state.state,state_req.state))
                self.state = state_req
            except KeyboardInterrupt:
                self.debug(1,"Interrupted by user")
                break

    def my_send(self, pkt):
        self.send_sock.send(pkt)

    def send(self, pkt):
        self.my_send(pkt)
        self.debug(3,"SENT : %s" % pkt.summary())
        self.packets.append(pkt.copy())


        

    

class TFTP_read(Automaton):
    def parse_args(self, filename, server, sport = None, port=69, **kargs):
        Automaton.parse_args(self, **kargs)
        self.filename = filename
        self.server = server
        self.port = port
        self.sport = sport


    def master_filter(self, pkt):
        return ( IP in pkt and pkt[IP].src == self.server and UDP in pkt
                 and pkt[UDP].dport == self.my_tid
                 and (self.server_tid is None or pkt[UDP].sport == self.server_tid) )
        
    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.blocksize=512
        self.my_tid = self.sport or RandShort()._fix()
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)
        self.server_tid = None
        self.res = ""

        self.l3 = IP(dst=self.server)/UDP(sport=self.my_tid, dport=self.port)/TFTP()
        self.last_packet = self.l3/TFTP_RRQ(filename=self.filename, mode="octet")
        self.send(self.last_packet)
        self.awaiting=1
        
        raise self.WAITING()
        
    # WAITING
    @ATMT.state()
    def WAITING(self):
        pass


    @ATMT.receive_condition(WAITING)
    def receive_data(self, pkt):
        if TFTP_DATA in pkt and pkt[TFTP_DATA].block == self.awaiting:
            if self.server_tid is None:
                self.server_tid = pkt[UDP].sport
                self.l3[UDP].dport = self.server_tid
            raise self.RECEIVING(pkt)

    @ATMT.receive_condition(WAITING, prio=1)
    def receive_error(self, pkt):
        if TFTP_ERROR in pkt:
            raise self.ERROR(pkt)
    
        
    @ATMT.timeout(WAITING, 3)
    def timeout_waiting(self):
        raise self.WAITING()
    @ATMT.action(timeout_waiting)
    def retransmit_last_packet(self):
        self.send(self.last_packet)

    @ATMT.action(receive_data)
#    @ATMT.action(receive_error)
    def send_ack(self):
        self.last_packet = self.l3 / TFTP_ACK(block = self.awaiting)
        self.send(self.last_packet)
    

    # RECEIVED
    @ATMT.state()
    def RECEIVING(self, pkt):
        if Raw in pkt:
            recvd = pkt[Raw].load
        else:
            recvd = ""
        self.res += recvd
        self.awaiting += 1
        if len(recvd) == self.blocksize:
            raise self.WAITING()
        raise self.END()

    # ERROR
    @ATMT.state(error=1)
    def ERROR(self,pkt):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        return pkt[TFTP_ERROR].summary()
    
    #END
    @ATMT.state(final=1)
    def END(self):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        return self.res




class TFTP_write(Automaton):
    def parse_args(self, filename, data, server, sport=None, port=69,**kargs):
        Automaton.parse_args(self, **kargs)
        self.filename = filename
        self.server = server
        self.port = port
        self.sport = sport
        self.blocksize = 512
        self.origdata = data

    def master_filter(self, pkt):
        return ( IP in pkt and pkt[IP].src == self.server and UDP in pkt
                 and pkt[UDP].dport == self.my_tid
                 and (self.server_tid is None or pkt[UDP].sport == self.server_tid) )
        

    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.data = [ self.origdata[i*self.blocksize:(i+1)*self.blocksize]
                      for i in range( len(self.origdata)/self.blocksize+1) ] 
        self.my_tid = self.sport or RandShort()._fix()
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)
        self.server_tid = None
        
        self.l3 = IP(dst=self.server)/UDP(sport=self.my_tid, dport=self.port)/TFTP()
        self.last_packet = self.l3/TFTP_WRQ(filename=self.filename, mode="octet")
        self.send(self.last_packet)
        self.res = ""
        self.awaiting=0

        raise self.WAITING_ACK()
        
    # WAITING_ACK
    @ATMT.state()
    def WAITING_ACK(self):
        pass

    @ATMT.receive_condition(WAITING_ACK)    
    def received_ack(self,pkt):
        if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.awaiting:
            if self.server_tid is None:
                self.server_tid = pkt[UDP].sport
                self.l3[UDP].dport = self.server_tid
            raise self.SEND_DATA()

    @ATMT.receive_condition(WAITING_ACK)
    def received_error(self, pkt):
        if TFTP_ERROR in pkt:
            raise self.ERROR(pkt)

    @ATMT.timeout(WAITING_ACK, 3)
    def timeout_waiting(self):
        raise self.WAITING_ACK()
    @ATMT.action(timeout_waiting)
    def retransmit_last_packet(self):
        self.send(self.last_packet)
    
    # SEND_DATA
    @ATMT.state()
    def SEND_DATA(self):
        self.awaiting += 1
        self.last_packet = self.l3/TFTP_DATA(block=self.awaiting)/self.data.pop(0)
        self.send(self.last_packet)
        if self.data:
            raise self.WAITING_ACK()
        raise self.END()
    

    # ERROR
    @ATMT.state(error=1)
    def ERROR(self,pkt):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        return pkt[TFTP_ERROR].summary()

    # END
    @ATMT.state(final=1)
    def END(self):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)


class TFTP_WRQ_server(Automaton):

    def parse_args(self, ip=None, sport=None, *args, **kargs):
        Automaton.parse_args(self, *args, **kargs)
        self.ip = ip
        self.sport = sport

    def master_filter(self, pkt):
        return TFTP in pkt and (not self.ip or pkt[IP].dst == self.ip)

    @ATMT.state(initial=1)
    def BEGIN(self):
        self.blksize=512
        self.blk=1
        self.filedata=""
        self.my_tid = self.sport or random.randint(10000,65500)
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)

    @ATMT.receive_condition(BEGIN)
    def receive_WRQ(self,pkt):
        if TFTP_WRQ in pkt:
            raise self.WAIT_DATA().action_parameters(pkt)
        
    @ATMT.action(receive_WRQ)
    def ack_WRQ(self, pkt):
        ip = pkt[IP]
        self.ip = ip.dst
        self.dst = ip.src
        self.filename = pkt[TFTP_WRQ].filename
        options = pkt[TFTP_Options]
        self.l3 = IP(src=ip.dst, dst=ip.src)/UDP(sport=self.my_tid, dport=pkt.sport)/TFTP()
        if options is None:
            self.last_packet = self.l3/TFTP_ACK(block=0)
            self.send(self.last_packet)
        else:
            opt = [x for x in options.options if x.oname.upper() == "BLKSIZE"]
            if opt:
                self.blksize = int(opt[0].value)
                self.debug(2,"Negotiated new blksize at %i" % self.blksize)
            self.last_packet = self.l3/TFTP_OACK()/TFTP_Options(options=opt)
            self.send(self.last_packet)

    @ATMT.state()
    def WAIT_DATA(self):
        pass

    @ATMT.timeout(WAIT_DATA, 1)
    def resend_ack(self):
        self.send(self.last_packet)
        raise self.WAIT_DATA()
        
    @ATMT.receive_condition(WAIT_DATA)
    def receive_data(self, pkt):
        if TFTP_DATA in pkt:
            data = pkt[TFTP_DATA]
            if data.block == self.blk:
                raise self.DATA(data)

    @ATMT.action(receive_data)
    def ack_data(self):
        self.last_packet = self.l3/TFTP_ACK(block = self.blk)
        self.send(self.last_packet)

    @ATMT.state()
    def DATA(self, data):
        self.filedata += data.load
        if len(data.load) < self.blksize:
            raise self.END()
        self.blk += 1
        raise self.WAIT_DATA()

    @ATMT.state(final=1)
    def END(self):
        return self.filename,self.filedata
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        

class TFTP_RRQ_server(Automaton):
    def parse_args(self, store=None, joker=None, dir=None, ip=None, sport=None, serve_one=False, **kargs):
        Automaton.parse_args(self,**kargs)
        if store is None:
            store = {}
        if dir is not None:
            self.dir = os.path.join(os.path.abspath(dir),"")
        else:
            self.dir = None
        self.store = store
        self.joker = joker
        self.ip = ip
        self.sport = sport
        self.serve_one = serve_one
        self.my_tid = self.sport or random.randint(10000,65500)
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)
        
    def master_filter(self, pkt):
        return TFTP in pkt and (not self.ip or pkt[IP].dst == self.ip)

    @ATMT.state(initial=1)
    def WAIT_RRQ(self):
        self.blksize=512
        self.blk=0

    @ATMT.receive_condition(WAIT_RRQ)
    def receive_rrq(self, pkt):
        if TFTP_RRQ in pkt:
            raise self.RECEIVED_RRQ(pkt)


    @ATMT.state()
    def RECEIVED_RRQ(self, pkt):
        ip = pkt[IP]
        options = pkt[TFTP_Options]
        self.l3 = IP(src=ip.dst, dst=ip.src)/UDP(sport=self.my_tid, dport=ip.sport)/TFTP()
        self.filename = pkt[TFTP_RRQ].filename
        self.blk=1
        self.data = None
        if self.filename in self.store:
            self.data = self.store[self.filename]
        elif self.dir is not None:
            fn = os.path.abspath(os.path.join(self.dir, self.filename))
            if fn.startswith(self.dir): # Check we're still in the server's directory
                try:
                    self.data=open(fn).read()
                except IOError:
                    pass
        if self.data is None:
            self.data = self.joker

        if options:
            opt = [x for x in options.options if x.oname.upper() == "BLKSIZE"]
            if opt:
                self.blksize = int(opt[0].value)
                self.debug(2,"Negotiated new blksize at %i" % self.blksize)
            self.last_packet = self.l3/TFTP_OACK()/TFTP_Options(options=opt)
            self.send(self.last_packet)
                

            

    @ATMT.condition(RECEIVED_RRQ)
    def file_in_store(self):
        if self.data is not None:
            self.blknb = len(self.data)/self.blksize+1
            raise self.SEND_FILE()

    @ATMT.condition(RECEIVED_RRQ)
    def file_not_found(self):
        if self.data is None:
            raise self.WAIT_RRQ()
    @ATMT.action(file_not_found)
    def send_error(self):
        self.send(self.l3/TFTP_ERROR(errorcode=1, errormsg=TFTP_Error_Codes[1]))

    @ATMT.state()
    def SEND_FILE(self):
        self.send(self.l3/TFTP_DATA(block=self.blk)/self.data[(self.blk-1)*self.blksize:self.blk*self.blksize])
        
    @ATMT.timeout(SEND_FILE, 3)
    def timeout_waiting_ack(self):
        raise self.SEND_FILE()
            
    @ATMT.receive_condition(SEND_FILE)
    def received_ack(self, pkt):
        if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.blk:
            raise self.RECEIVED_ACK()
    @ATMT.state()
    def RECEIVED_ACK(self):
        self.blk += 1

    @ATMT.condition(RECEIVED_ACK)
    def no_more_data(self):
        if self.blk > self.blknb:
            if self.serve_one:
                raise self.END()
            raise self.WAIT_RRQ()
    @ATMT.condition(RECEIVED_ACK, prio=2)
    def data_remaining(self):
        raise self.SEND_FILE()

    @ATMT.state(final=1)
    def END(self):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
    

        

########################
## Answering machines ##
########################

class ReferenceAM(type):
    def __new__(cls, name, bases, dct):
        o = super(ReferenceAM, cls).__new__(cls, name, bases, dct)
        if o.function_name:
            globals()[o.function_name] = lambda o=o,*args,**kargs: o(*args,**kargs)()
        return o


class AnsweringMachine(object):
    __metaclass__ = ReferenceAM
    function_name = ""
    filter = None
    sniff_options = { "store":0 }
    sniff_options_list = [ "store", "iface", "count", "promisc", "filter", "type", "prn" ]
    send_options = { "verbose":0 }
    send_options_list = ["iface", "inter", "loop", "verbose"]
    send_function = staticmethod(send)
    
    
    def __init__(self, **kargs):
        self.mode = 0
        if self.filter:
            kargs.setdefault("filter",self.filter)
        kargs.setdefault("prn", self.reply)
        self.optam1 = {}
        self.optam2 = {}
        self.optam0 = {}
        doptsend,doptsniff = self.parse_all_options(1, kargs)
        self.defoptsend = self.send_options.copy()
        self.defoptsend.update(doptsend)
        self.defoptsniff = self.sniff_options.copy()
        self.defoptsniff.update(doptsniff)
        self.optsend,self.optsniff = [{},{}]

    def __getattr__(self, attr):
        for d in [self.optam2, self.optam1]:
            if attr in d:
                return d[attr]
        raise AttributeError,attr
                
    def __setattr__(self, attr, val):
        mode = self.__dict__.get("mode",0)
        if mode == 0:
            self.__dict__[attr] = val
        else:
            [self.optam1, self.optam2][mode-1][attr] = val

    def parse_options(self):
        pass

    def parse_all_options(self, mode, kargs):
        sniffopt = {}
        sendopt = {}
        for k in kargs.keys():            
            if k in self.sniff_options_list:
                sniffopt[k] = kargs[k]
            if k in self.send_options_list:
                sendopt[k] = kargs[k]
            if k in self.sniff_options_list+self.send_options_list:
                del(kargs[k])
        if mode != 2 or kargs:
            if mode == 1:
                self.optam0 = kargs
            elif mode == 2 and kargs:
                k = self.optam0.copy()
                k.update(kargs)
                self.parse_options(**k)
                kargs = k 
            omode = self.__dict__.get("mode",0)
            self.__dict__["mode"] = mode
            self.parse_options(**kargs)
            self.__dict__["mode"] = omode
        return sendopt,sniffopt

    def is_request(self, req):
        return 1

    def make_reply(self, req):
        return req

    def send_reply(self, reply):
        self.send_function(reply, **self.optsend)

    def print_reply(self, req, reply):
        print "%s ==> %s" % (req.summary(),reply.summary())

    def reply(self, pkt):
        if not self.is_request(pkt):
            return
        reply = self.make_reply(pkt)
        self.send_reply(reply)
        if conf.verb >= 0:
            self.print_reply(pkt, reply)

    def run(self, *args, **kargs):
        log_interactive.warning("run() method deprecated. The intance is now callable")
        self(*args,**kargs)

    def __call__(self, *args, **kargs):
        optsend,optsniff = self.parse_all_options(2,kargs)
        self.optsend=self.defoptsend.copy()
        self.optsend.update(optsend)
        self.optsniff=self.defoptsniff.copy()
        self.optsniff.update(optsniff)

        try:
            self.sniff()
        except KeyboardInterrupt:
            print "Interrupted by user"
        
    def sniff(self):
        sniff(**self.optsniff)


class BOOTP_am(AnsweringMachine):
    function_name = "bootpd"
    filter = "udp and port 68 and port 67"
    send_function = staticmethod(sendp)
    def parse_options(self, pool=Net("192.168.1.128/25"), network="192.168.1.0/24",gw="192.168.1.1",
                      renewal_time=60, lease_time=1800):
        if type(pool) is str:
            poom = Net(pool)
        netw,msk = (network.split("/")+["32"])[:2]
        msk = itom(int(msk))
        self.netmask = ltoa(msk)
        self.network = ltoa(atol(netw)&msk)
        self.broadcast = ltoa( atol(self.network) | (0xffffffff&~msk) )
        self.gw = gw
        if isinstance(pool,Gen):
            pool = [k for k in pool if k not in [gw, self.network, self.broadcast]]
            pool.reverse()
        if len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases = {}

    def is_request(self, req):
        if not req.haslayer(BOOTP):
            return 0
        reqb = req.getlayer(BOOTP)
        if reqb.op != 1:
            return 0
        return 1

    def print_reply(self, req, reply):
        print "Reply %s to %s" % (reply.getlayer(IP).dst,reply.dst)

    def make_reply(self, req):        
        mac = req.src
        if type(self.pool) is list:
            if not self.leases.has_key(mac):
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool
            
        repb = req.getlayer(BOOTP).copy()
        repb.op="BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        del(repb.payload)
        rep=Ether(dst=mac)/IP(dst=ip)/UDP(sport=req.dport,dport=req.sport)/repb
        return rep


class DHCP_am(BOOTP_am):
    function_name="dhcpd"
    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP in req:
            dhcp_options = [(op[0],{1:2,3:5}.get(op[1],op[1]))
                            for op in req[DHCP].options
                            if type(op) is tuple  and op[0] == "message-type"]
            dhcp_options += [("router", self.gw),
                             ("name_server", self.gw),
                             ("broadcast_address", self.broadcast),
                             ("subnet_mask", self.netmask),
                             ("renewal_time", self.renewal_time),
                             ("lease_time", self.lease_time),
                             ]
            resp /= DHCP(options=dhcp_options)
        return resp
    


class DNS_am(AnsweringMachine):
    function_name="dns_spoof"
    filter = "udp port 53"

    def parse_options(self, joker="192.168.1.1", match=None):
        if match is None:
            self.match = {}
        else:
            self.match = match
        self.joker=joker

    def is_request(self, req):
        return req.haslayer(DNS) and req.getlayer(DNS).qr == 0
    
    def make_reply(self, req):
        ip = req.getlayer(IP)
        dns = req.getlayer(DNS)
        resp = IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)
        rdata = self.match.get(dns.qd.qname, self.joker)
        resp /= DNS(id=dns.id, qr=1, qd=dns.qd,
                    an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=rdata))
        return resp


class WiFi_am(AnsweringMachine):
    """Before using this, initialize "iffrom" and "ifto" interfaces:
iwconfig iffrom mode monitor
iwpriv orig_ifto hostapd 1
ifconfig ifto up
note: if ifto=wlan0ap then orig_ifto=wlan0
note: ifto and iffrom must be set on the same channel
ex:
ifconfig eth1 up
iwconfig eth1 mode monitor
iwconfig eth1 channel 11
iwpriv wlan0 hostapd 1
ifconfig wlan0ap up
iwconfig wlan0 channel 11
iwconfig wlan0 essid dontexist
iwconfig wlan0 mode managed
"""
    function_name = "airpwn"
    filter = None
    
    def parse_options(iffrom, ifto, replace, pattern="", ignorepattern=""):
        self.iffrom = iffrom
        self.ifto = ifto
        ptrn = re.compile(pattern)
        iptrn = re.compile(ignorepattern)
        
    def is_request(self, pkt):
        if not isinstance(pkt,Dot11):
            return 0
        if not pkt.FCfield & 1:
            return 0
        if not pkt.haslayer(TCP):
            return 0
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        pay = str(tcp.payload)
        if not self.ptrn.match(pay):
            return 0
        if self.iptrn.match(pay):
            return 0

    def make_reply(self, p):
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = str(tcp.payload)
        del(p.payload.payload.payload)
        p.FCfield="from-DS"
        p.addr1,p.addr2 = p.addr2,p.addr1
        p /= IP(src=ip.dst,dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq+len(pay),
                 flags="PA")
        q = p.copy()
        p /= self.replace
        q.ID += 1
        q.getlayer(TCP).flags="RA"
        q.getlayer(TCP).seq+=len(replace)
        return [p,q]
    
    def print_reply(self):
        print p.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%")

    def send_reply(self, reply):
        sendp(reply, iface=self.ifto, **self.optsend)

    def sniff(self):
        sniff(iface=self.iffrom, **self.optsniff)



class ARP_am(AnsweringMachine):
    function_name="farpd"
    filter = "arp"
    send_function = staticmethod(sendp)

    def parse_options(self, IP_addr=None, iface=None, ARP_addr=None):
        self.IP_addr=IP_addr
        self.iface=iface
        self.ARP_addr=ARP_addr

    def is_request(self, req):
        return (req.haslayer(ARP) and
                req.getlayer(ARP).op == 1 and
                (self.IP_addr == None or self.IP_addr == req.getlayer(ARP).pdst))
    
    def make_reply(self, req):
        ether = req.getlayer(Ether)
        arp = req.getlayer(ARP)
        iff,a,gw = conf.route.route(arp.psrc)
        if self.iface != None:
            iff = iface
        ARP_addr = self.ARP_addr
        IP_addr = arp.pdst
        resp = Ether(dst=ether.src,
                     src=ARP_addr)/ARP(op="is-at",
                                       hwsrc=ARP_addr,
                                       psrc=IP_addr,
                                       hwdst=arp.hwsrc,
                                       pdst=arp.pdst)
        return resp

    def sniff(self):
        sniff(iface=self.iface, **self.optsniff)


#############
## Fuzzing ##
#############


def fuzz(p, _inplace=0):
    if not _inplace:
        p = p.copy()
    q = p
    while not isinstance(q, NoPayload):
        for f in q.fields_desc:
            if isinstance(f, PacketListField):
                for r in getattr(q, f.name):
                    print "fuzzing", repr(r)
                    fuzz(r, _inplace=1)
            elif f.default is not None:
                rnd = f.randval()
                if rnd is not None:
                    q.default_fields[f.name] = rnd
        q = q.payload
    return p




###################
## Testing stuff ##
###################



def merge(x,y):
    if len(x) > len(y):
        y += "\x00"*(len(x)-len(y))
    elif len(x) < len(y):
        x += "\x00"*(len(y)-len(x))
    m = ""
    for i in range(len(x)/ss):
        m += x[ss*i:ss*(i+1)]+y[ss*i:ss*(i+1)]
    return  m
#    return  "".join(map(str.__add__, x, y))


def voip_play(s1,list=None,**kargs):
    FIFO="/tmp/conv1.%i.%%i" % os.getpid()
    FIFO1=FIFO % 1
    FIFO2=FIFO % 2
    
    os.mkfifo(FIFO1)
    os.mkfifo(FIFO2)
    try:
        os.system("soxmix -t .ul %s -t .ul %s -t ossdsp /dev/dsp &" % (FIFO1,FIFO2))
        
        c1=open(FIFO1,"w", 4096)
        c2=open(FIFO2,"w", 4096)
        fcntl.fcntl(c1.fileno(),fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(c2.fileno(),fcntl.F_SETFL, os.O_NONBLOCK)
    
    #    dsp,rd = os.popen2("sox -t .ul -c 2 - -t ossdsp /dev/dsp")
        def play(pkt,last=[]):
            if not pkt:
                return 
            if not pkt.haslayer(UDP):
                return 
            ip=pkt.getlayer(IP)
            if s1 in [ip.src, ip.dst]:
                if not last:
                    last.append(pkt)
                    return
                load=last.pop()
    #            x1 = load.load[12:]
                c1.write(load.load[12:])
                if load.getlayer(IP).src == ip.src:
    #                x2 = ""
                    c2.write("\x00"*len(load.load[12:]))
                    last.append(pkt)
                else:
    #                x2 = pkt.load[:12]
                    c2.write(pkt.load[12:])
    #            dsp.write(merge(x1,x2))
    
        if list is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in list:
                play(p)
    finally:
        os.unlink(FIFO1)
        os.unlink(FIFO2)



def voip_play1(s1,list=None,**kargs):

    
    dsp,rd = os.popen2("sox -t .ul - -t ossdsp /dev/dsp")
    def play(pkt):
        if not pkt:
            return 
        if not pkt.haslayer(UDP):
            return 
        ip=pkt.getlayer(IP)
        if s1 in [ip.src, ip.dst]:
            dsp.write(pkt.getlayer(Raw).load[12:])
    try:
        if list is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in list:
                play(p)
    finally:
        dsp.close()
        rd.close()

def voip_play2(s1,**kargs):
    dsp,rd = os.popen2("sox -t .ul -c 2 - -t ossdsp /dev/dsp")
    def play(pkt,last=[]):
        if not pkt:
            return 
        if not pkt.haslayer(UDP):
            return 
        ip=pkt.getlayer(IP)
        if s1 in [ip.src, ip.dst]:
            if not last:
                last.append(pkt)
                return
            load=last.pop()
            x1 = load.load[12:]
#            c1.write(load.load[12:])
            if load.getlayer(IP).src == ip.src:
                x2 = ""
#                c2.write("\x00"*len(load.load[12:]))
                last.append(pkt)
            else:
                x2 = pkt.load[:12]
#                c2.write(pkt.load[12:])
            dsp.write(merge(x1,x2))
            
    sniff(store=0, prn=play, **kargs)

def voip_play3(lst=None,**kargs):
    dsp,rd = os.popen2("sox -t .ul - -t ossdsp /dev/dsp")
    try:
        def play(pkt, dsp=dsp):
            if pkt and pkt.haslayer(UDP) and pkt.haslayer(Raw):
                dsp.write(pkt.getlayer(RTP).load)
        if lst is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in lst:
                play(p)
    finally:
        try:
            dsp.close()
            rd.close()
        except:
            pass


def IPID_count(lst, funcID=lambda x:x[1].id, funcpres=lambda x:x[1].summary()):
    idlst = map(funcID, lst)
    idlst.sort()
    classes = [idlst[0]]+map(lambda x:x[1],filter(lambda (x,y): abs(x-y)>50, map(lambda x,y: (x,y),idlst[:-1], idlst[1:])))
    lst = map(lambda x:(funcID(x), funcpres(x)), lst)
    lst.sort()
    print "Probably %i classes:" % len(classes), classes
    for id,pr in lst:
        print "%5i" % id, pr
    
    
    
            

last=None


def tethereal(*args,**kargs):
    sniff(prn=lambda x: x.display(),*args,**kargs)

def etherleak(target, **kargs):
    return srpflood(Ether()/ARP(pdst=target), prn=lambda (s,r): Padding in r and hexstr(r[Padding].load),
                    filter="arp", **kargs)


def fragleak(target,sport=123, dport=123, timeout=0.2, onlyasc=0):
    load = "XXXXYYYYYYYYYY"
#    getmacbyip(target)
#    pkt = IP(dst=target, id=RandShort(), options="\x22"*40)/UDP()/load
    pkt = IP(dst=target, id=RandShort(), options="\x00"*40, flags=1)/UDP(sport=sport, dport=sport)/load
    s=conf.L3socket()
    intr=0
    found={}
    try:
        while 1:
            try:
                if not intr:
                    s.send(pkt)
                sin,sout,serr = select([s],[],[],timeout)
                if not sin:
                    continue
                ans=s.recv(1600)
                if not isinstance(ans, IP): #TODO: IPv6
                    continue
                if not isinstance(ans.payload, ICMP):
                    continue
                if not isinstance(ans.payload.payload, IPerror):
                    continue
                if ans.payload.payload.dst != target:
                    continue
                if ans.src  != target:
                    print "leak from", ans.src,


#                print repr(ans)
                if not ans.haslayer(Padding):
                    continue

                
#                print repr(ans.payload.payload.payload.payload)
                
#                if not isinstance(ans.payload.payload.payload.payload, Raw):
#                    continue
#                leak = ans.payload.payload.payload.payload.load[len(load):]
                leak = ans.getlayer(Padding).load
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak, onlyasc=onlyasc)
            except KeyboardInterrupt:
                if intr:
                    raise
                intr=1
    except KeyboardInterrupt:
        pass

def fragleak2(target, timeout=0.4, onlyasc=0):
    found={}
    try:
        while 1:
            p = sr1(IP(dst=target, options="\x00"*40, proto=200)/"XXXXYYYYYYYYYYYY",timeout=timeout,verbose=0)
            if not p:
                continue
            if Padding in p:
                leak  = p[Padding].load
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak,onlyasc=onlyasc)
    except:
        pass
    


plst=[]
def get_toDS():
    global plst
    while 1:
        p,=sniff(iface="eth1",count=1)
        if not isinstance(p,Dot11):
            continue
        if p.FCfield & 1:
            plst.append(p)
            print "."


#    if not ifto.endswith("ap"):
#        print "iwpriv %s hostapd 1" % ifto
#        os.system("iwpriv %s hostapd 1" % ifto)
#        ifto += "ap"
#        
#    os.system("iwconfig %s mode monitor" % iffrom)
#    

def airpwn(iffrom, ifto, replace, pattern="", ignorepattern=""):
    """Before using this, initialize "iffrom" and "ifto" interfaces:
iwconfig iffrom mode monitor
iwpriv orig_ifto hostapd 1
ifconfig ifto up
note: if ifto=wlan0ap then orig_ifto=wlan0
note: ifto and iffrom must be set on the same channel
ex:
ifconfig eth1 up
iwconfig eth1 mode monitor
iwconfig eth1 channel 11
iwpriv wlan0 hostapd 1
ifconfig wlan0ap up
iwconfig wlan0 channel 11
iwconfig wlan0 essid dontexist
iwconfig wlan0 mode managed
"""
    
    ptrn = re.compile(pattern)
    iptrn = re.compile(ignorepattern)
    def do_airpwn(p, ifto=ifto, replace=replace, ptrn=ptrn, iptrn=iptrn):
        if not isinstance(p,Dot11):
            return
        if not p.FCfield & 1:
            return
        if not p.haslayer(TCP):
            return
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = str(tcp.payload)
#        print "got tcp"
        if not ptrn.match(pay):
            return
#        print "match 1"
        if iptrn.match(pay):
            return
#        print "match 2"
        del(p.payload.payload.payload)
        p.FCfield="from-DS"
        p.addr1,p.addr2 = p.addr2,p.addr1
        q = p.copy()
        p /= IP(src=ip.dst,dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq+len(pay),
                 flags="PA")
        q = p.copy()
        p /= replace
        q.ID += 1
        q.getlayer(TCP).flags="RA"
        q.getlayer(TCP).seq+=len(replace)
        
        sendp([p,q], iface=ifto, verbose=0)
#        print "send",repr(p)        
#        print "send",repr(q)
        print p.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%")

    sniff(iface=iffrom,prn=do_airpwn)

            
        
    
##################
## Color themes ##
##################

class Color:
    normal = "\033[0m"
    black = "\033[30m"
    red = "\033[31m"
    green = "\033[32m"
    yellow = "\033[33m"
    blue = "\033[34m"
    purple = "\033[35m"
    cyan = "\033[36m"
    grey = "\033[37m"

    bold = "\033[1m"
    uline = "\033[4m"
    blink = "\033[5m"
    invert = "\033[7m"
        

class ColorTheme:
    def __repr__(self):
        return "<%s>" % self.__class__.__name__
    def __getattr__(self, attr):
        return lambda x:x
        

class NoTheme(ColorTheme):
    pass


class AnsiColorTheme(ColorTheme):
    def __getattr__(self, attr):
        if attr.startswith("__"):
            raise AttributeError(attr)
        s = "style_%s" % attr 
        if s in self.__class__.__dict__:
            before = getattr(self, s)
            after = self.style_normal
        else:
            before = after = ""

        def do_style(val, fmt=None, before=before, after=after):
            if fmt is None:
                if type(val) is not str:
                    val = str(val)
            else:
                val = fmt % val
            return before+val+after
        return do_style
        
        
    style_normal = ""
    style_prompt = ""
    style_punct = ""
    style_id = ""
    style_not_printable = ""
    style_layer_name = ""
    style_field_name = ""
    style_field_value = ""
    style_emph_field_name = ""
    style_emph_field_value = ""
    style_packetlist_name = ""
    style_packetlist_proto = ""
    style_packetlist_value = ""
    style_fail = ""
    style_success = ""
    style_odd = ""
    style_even = ""
    style_opening = ""
    style_active = ""
    style_closed = ""
    style_left = ""
    style_right = ""

class BlackAndWhite(AnsiColorTheme):
    pass

class DefaultTheme(AnsiColorTheme):
    style_normal = Color.normal
    style_prompt = Color.blue+Color.bold
    style_punct = Color.normal
    style_id = Color.blue+Color.bold
    style_not_printable = Color.grey
    style_layer_name = Color.red+Color.bold
    style_field_name = Color.blue
    style_field_value = Color.purple
    style_emph_field_name = Color.blue+Color.uline+Color.bold
    style_emph_field_value = Color.purple+Color.uline+Color.bold
    style_packetlist_name = Color.red+Color.bold
    style_packetlist_proto = Color.blue
    style_packetlist_value = Color.purple
    style_fail = Color.red+Color.bold
    style_success = Color.blue+Color.bold
    style_even = Color.black+Color.bold
    style_odd = Color.black
    style_opening = Color.yellow
    style_active = Color.black
    style_closed = Color.grey
    style_left = Color.blue+Color.invert
    style_right = Color.red+Color.invert
    
class BrightTheme(AnsiColorTheme):
    style_normal = Color.normal
    style_punct = Color.normal
    style_id = Color.yellow+Color.bold
    style_layer_name = Color.red+Color.bold
    style_field_name = Color.yellow+Color.bold
    style_field_value = Color.purple+Color.bold
    style_emph_field_name = Color.yellow+Color.bold
    style_emph_field_value = Color.green+Color.bold
    style_packetlist_name = Color.red+Color.bold
    style_packetlist_proto = Color.yellow+Color.bold
    style_packetlist_value = Color.purple+Color.bold
    style_fail = Color.red+Color.bold
    style_success = Color.blue+Color.bold
    style_even = Color.black+Color.bold
    style_odd = Color.black
    style_left = Color.cyan+Color.invert
    style_right = Color.purple+Color.invert


class RastaTheme(AnsiColorTheme):
    style_normal = Color.normal+Color.green+Color.bold
    style_prompt = Color.yellow+Color.bold
    style_punct = Color.red
    style_id = Color.green+Color.bold
    style_not_printable = Color.green
    style_layer_name = Color.red+Color.bold
    style_field_name = Color.yellow+Color.bold
    style_field_value = Color.green+Color.bold
    style_emph_field_name = Color.green
    style_emph_field_value = Color.green
    style_packetlist_name = Color.red+Color.bold
    style_packetlist_proto = Color.yellow+Color.bold
    style_packetlist_value = Color.green+Color.bold
    style_fail = Color.red
    style_success = Color.red+Color.bold
    style_even = Color.yellow
    style_odd = Color.green
    style_left = Color.yellow+Color.invert
    style_right = Color.red+Color.invert


class FormatTheme(ColorTheme):
    def __getattr__(self, attr):
        if attr.startswith("__"):
            raise AttributeError(attr)
        col = self.__class__.__dict__.get("style_%s" % attr, "%s")
        def do_style(val, fmt=None, col=col):
            if fmt is None:
                if type(val) is not str:
                    val = str(val)
            else:
                val = fmt % val
            return col % val
        return do_style
        

class LatexTheme(FormatTheme):
    style_prompt = r"\textcolor{blue}{%s}"
    style_not_printable = r"\textcolor{gray}{%s}"
    style_layer_name = r"\textcolor{red}{\bf %s}"
    style_field_name = r"\textcolor{blue}{%s}"
    style_field_value = r"\textcolor{purple}{%s}"
    style_emph_field_name = r"\textcolor{blue}{\underline{%s}}" #ul
    style_emph_field_value = r"\textcolor{purple}{\underline{%s}}" #ul
    style_packetlist_name = r"\textcolor{red}{\bf %s}"
    style_packetlist_proto = r"\textcolor{blue}{%s}"
    style_packetlist_value = r"\textcolor{purple}{%s}"
    style_fail = r"\textcolor{red}{\bf %s}"
    style_success = r"\textcolor{blue}{\bf %s}"
    style_left = r"\textcolor{blue}{%s}"
    style_right = r"\textcolor{red}{%s}"
#    style_even = r"}{\bf "
#    style_odd = ""

class LatexTheme2(FormatTheme):
    style_prompt = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_not_printable = r"@`@textcolor@[@gray@]@@[@%s@]@"
    style_layer_name = r"@`@textcolor@[@red@]@@[@@`@bfseries@[@@]@%s@]@"
    style_field_name = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_field_value = r"@`@textcolor@[@purple@]@@[@%s@]@"
    style_emph_field_name = r"@`@textcolor@[@blue@]@@[@@`@underline@[@%s@]@@]@" 
    style_emph_field_value = r"@`@textcolor@[@purple@]@@[@@`@underline@[@%s@]@@]@" 
    style_packetlist_name = r"@`@textcolor@[@red@]@@[@@`@bfseries@[@@]@%s@]@"
    style_packetlist_proto = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_packetlist_value = r"@`@textcolor@[@purple@]@@[@%s@]@"
    style_fail = r"@`@textcolor@[@red@]@@[@@`@bfseries@[@@]@%s@]@"
    style_success = r"@`@textcolor@[@blue@]@@[@@`@bfserices@[@@]@%s@]@"
    style_even = r"@`@textcolor@[@gray@]@@[@@`@bfseries@[@@]@%s@]@"
#    style_odd = r"@`@textcolor@[@black@]@@[@@`@bfseries@[@@]@%s@]@"
    style_left = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_right = r"@`@textcolor@[@red@]@@[@%s@]@"

class HTMLTheme(FormatTheme):
    style_prompt = "<span class=prompt>%s</span>"
    style_not_printable = "<span class=not_printable>%s</span>"
    style_layer_name = "<span class=layer_name>%s</span>"
    style_field_name = "<span class=field_name>%s</span>"
    style_field_value = "<span class=field_value>%s</span>"
    style_emph_field_name = "<span class=emph_field_name>%s</span>"
    style_emph_field_value = "<span class=emph_field_value>%s</span>"
    style_packetlist_name = "<span class=packetlist_name>%s</span>"
    style_packetlist_proto = "<span class=packetlist_proto>%s</span>"
    style_packetlist_value = "<span class=packetlist_value>%s</span>"
    style_fail = "<span class=fail>%s</span>"
    style_success = "<span class=success>%s</span>"
    style_even = "<span class=even>%s</span>"
    style_odd = "<span class=odd>%s</span>"
    style_left = "<span class=left>%s</span>"
    style_right = "<span class=right>%s</span>"

class HTMLTheme2(HTMLTheme):
    style_prompt = "#[#span class=prompt#]#%s#[#/span#]#"
    style_not_printable = "#[#span class=not_printable#]#%s#[#/span#]#"
    style_layer_name = "#[#span class=layer_name#]#%s#[#/span#]#"
    style_field_name = "#[#span class=field_name#]#%s#[#/span#]#"
    style_field_value = "#[#span class=field_value#]#%s#[#/span#]#"
    style_emph_field_name = "#[#span class=emph_field_name#]#%s#[#/span#]#"
    style_emph_field_value = "#[#span class=emph_field_value#]#%s#[#/span#]#"
    style_packetlist_name = "#[#span class=packetlist_name#]#%s#[#/span#]#"
    style_packetlist_proto = "#[#span class=packetlist_proto#]#%s#[#/span#]#"
    style_packetlist_value = "#[#span class=packetlist_value#]#%s#[#/span#]#"
    style_fail = "#[#span class=fail#]#%s#[#/span#]#"
    style_success = "#[#span class=success#]#%s#[#/span#]#"
    style_even = "#[#span class=even#]#%s#[#/span#]#"
    style_odd = "#[#span class=odd#]#%s#[#/span#]#"
    style_left = "#[#span class=left#]#%s#[#/span#]#"
    style_right = "#[#span class=right#]#%s#[#/span#]#"


class ColorPrompt:
    __prompt = ">>> "
    def __str__(self):
        try:
            ct = conf.color_theme
            if isinstance(ct, AnsiColorTheme):
                ## ^A and ^B delimit invisible caracters for readline to count right
                return "\001%s\002" % ct.prompt("\002"+conf.prompt+"\001")
            else:
                return ct.prompt(conf.prompt)
        except:
            return self.__prompt

############
## Config ##
############

class ConfClass:
    def configure(self, cnf):
        self.__dict__ = cnf.__dict__.copy()
    def __repr__(self):
        return str(self)
    def __str__(self):
        s="Version    = %s\n" % VERSION
        keys = self.__class__.__dict__.copy()
        keys.update(self.__dict__)
        keys = keys.keys()
        keys.sort()
        for i in keys:
            if i[0] != "_":
                s += "%-10s = %s\n" % (i, repr(getattr(self, i)))
        return s[:-1]
    
class ProgPath(ConfClass):
    pdfreader = "acroread"
    psreader = "gv"
    dot = "dot"
    display = "display"
    tcpdump = "tcpdump"
    tcpreplay = "tcpreplay"
    hexedit = "hexer"
    wireshark = "wireshark"
    
class Resolve:
    def __init__(self):
        self.fields = {}
    def add(self, *flds):
        for fld in flds:
            self.fields[fld]=None
    def remove(self, *flds):
        for fld in flds:
            if fld in self.fields:
                del(self.fields[fld])
    def __contains__(self, elt):
        return elt in self.fields
    def __repr__(self):
        return "<Resolve [%s]>" %  " ".join(str(x) for x in self.fields)
    
        


class Conf(ConfClass):
    """This object contains the configuration of scapy.
session  : filename where the session will be saved
stealth  : if 1, prevents any unwanted packet to go out (ARP, DNS, ...)
checkIPID: if 0, doesn't check that IPID matches between IP sent and ICMP IP citation received
           if 1, checks that they either are equal or byte swapped equals (bug in some IP stacks)
           if 2, strictly checks that they are equals
checkIPsrc: if 1, checks IP src in IP and ICMP IP citation match (bug in some NAT stacks)
check_TCPerror_seqack: if 1, also check that TCP seq and ack match the ones in ICMP citation
iff      : selects the default output interface for srp() and sendp(). default:"eth0")
verb     : level of verbosity, from 0 (almost mute) to 3 (verbose)
promisc  : default mode for listening socket (to get answers if you spoof on a lan)
sniff_promisc : default mode for sniff()
filter   : bpf filter added to every sniffing socket to exclude traffic from analysis
histfile : history file
padding  : includes padding in desassembled packets
except_filter : BPF filter for packets to ignore
debug_match : when 1, store received packet that are not matched into debug.recv
route    : holds the Scapy routing table and provides methods to manipulate it
warning_threshold : how much time between warnings from the same place
ASN1_default_codec: Codec used by default for ASN1 objects
mib      : holds MIB direct access dictionnary
resolve   : holds list of fields for which resolution should be done
noenum    : holds list of enum fields for which conversion to string should NOT be done
AS_resolver: choose the AS resolver class to use
"""
    session = ""  
    stealth = "not implemented"
    iface = get_working_if()
    checkIPID = 0
    checkIPsrc = 1
    checkIPaddr = 1
    check_TCPerror_seqack = 0
    verb = 2
    prompt = ">>> "
    promisc = 1
    sniff_promisc = 1
    L3socket = L3PacketSocket
    L2socket = L2Socket
    L2listen = L2ListenSocket
    BTsocket = BluetoothL2CAPSocket
    histfile = os.path.join(os.environ["HOME"], ".scapy_history")
    padding = 1
    p0f_base ="/etc/p0f/p0f.fp"
    queso_base ="/etc/queso.conf"
    nmap_base ="/usr/share/nmap/nmap-os-fingerprints"
    IPCountry_base = "GeoIPCountry4Scapy.gz"
    countryLoc_base = "countryLoc.csv"
    gnuplot_world = "world.dat"
    except_filter = ""
    debug_match = 0
    route = Route()
    wepkey = ""
    auto_fragment = 1
    debug_dissector = 0
    color_theme = DefaultTheme()
    warning_threshold = 5
    ASN1_default_codec = ASN1_Codecs.BER
    mib = MIBDict(_name="MIB")
    prog = ProgPath()
    resolve = Resolve()
    noenum = Resolve()
    ethertypes = ETHER_TYPES
    protocols = IP_PROTOS
    services_tcp = TCP_SERVICES
    services_udp = UDP_SERVICES
    manufdb = MANUFDB
    AS_resolver = AS_resolver_multi() 
        

conf=Conf()

betteriface = conf.route.route("0.0.0.0", verbose=0)[0]
if betteriface != "lo": #XXX linux specific...
    conf.iface = betteriface
del(betteriface)

if PCAP:
    conf.L2listen=L2pcapListenSocket
    if DNET:
        conf.L3socket=L3dnetSocket
        conf.L2socket=L2dnetSocket


p0f_kdb = p0fKnowledgeBase(conf.p0f_base)
queso_kdb = QuesoKnowledgeBase(conf.queso_base)
nmap_kdb = NmapKnowledgeBase(conf.nmap_base)
IP_country_kdb = IPCountryKnowledgeBase(conf.IPCountry_base)
country_loc_kdb = CountryLocKnowledgeBase(conf.countryLoc_base)


#########################
##### Autorun stuff #####
#########################


class ScapyAutorunInterpreter(code.InteractiveInterpreter):
    def __init__(self, *args, **kargs):
        code.InteractiveInterpreter.__init__(self, *args, **kargs)
        self.error = 0
    def showsyntaxerror(self, *args, **kargs):
        self.error = 1
        return code.InteractiveInterpreter.showsyntaxerror(self, *args, **kargs)
    def showtraceback(self, *args, **kargs):
        self.error = 1
        return code.InteractiveInterpreter.showtraceback(self, *args, **kargs)


def autorun_commands(cmds,my_globals=None,verb=0):
    sv = conf.verb
    import __builtin__
    try:
        if my_globals is None:
            my_globals = globals()
        conf.verb = verb
        interp = ScapyAutorunInterpreter(my_globals)
        cmd = ""
        cmds = cmds.splitlines()
        cmds.append("") # ensure we finish multiline commands
        cmds.reverse()
        __builtin__.__dict__["_"] = None
        while 1:
            if cmd:
                sys.stderr.write(sys.__dict__.get("ps2","... "))
            else:
                sys.stderr.write(str(sys.__dict__.get("ps1",ColorPrompt())))
                
            l = cmds.pop()
            print l
            cmd += "\n"+l
            if interp.runsource(cmd):
                continue
            if interp.error:
                return 0
            cmd = ""
            if len(cmds) <= 1:
                break
    finally:
        conf.verb = sv
    return _

def autorun_get_interactive_session(cmds, **kargs):
    class StringWriter:
        def __init__(self):
            self.s = ""
        def write(self, x):
            self.s += x
            
    sw = StringWriter()
    sstdout,sstderr = sys.stdout,sys.stderr
    try:
        sys.stdout = sys.stderr = sw
        res = autorun_commands(cmds, **kargs)
    finally:
        sys.stdout,sys.stderr = sstdout,sstderr
    return sw.s,res

def autorun_get_text_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = NoTheme()
        s,res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s,res

def autorun_get_ansi_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = DefaultTheme()
        s,res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s,res

def autorun_get_html_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = HTMLTheme2()
        s,res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    
    s = s.replace("<","&lt;").replace(">","&gt;").replace("#[#","<").replace("#]#",">")
    return s,res

def autorun_get_latex_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = LatexTheme2()
        s,res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    s = tex_escape(s)
    s = s.replace("@[@","{").replace("@]@","}").replace("@`@","\\")
    return s,res


################
##### Main #####
################

def scapy_write_history_file(readline):
    if conf.histfile:
        try:
            readline.write_history_file(conf.histfile)
        except IOError,e:
            try:
                warning("Could not write history to [%s]\n\t (%s)" % (conf.histfile,e))
                tmp = os.tempnam("","scapy")
                readline.write_history_file(tmp)
                warning("Wrote history to [%s]" % tmp)
            except:
                warning("Cound not write history to [%s]. Discarded" % tmp)


def interact(mydict=None,argv=None,mybanner=None,loglevel=1):
    import code,sys,cPickle,types,os,imp,getopt,logging

    logging.getLogger("scapy").setLevel(loglevel)

    the_banner = "Welcome to Scapy (%s)"
    if mybanner is not None:
        the_banner += "\n"
        the_banner += mybanner

    if argv is None:
        argv = sys.argv

#    scapy_module = argv[0][argv[0].rfind("/")+1:]
#    if not scapy_module:
#        scapy_module = "scapy"
#    else:
#        if scapy_module.endswith(".py"):
#            scapy_module = scapy_module[:-3]
#
#    scapy=imp.load_module("scapy",*imp.find_module(scapy_module))
    
    
    import __builtin__
#    __builtin__.__dict__.update(scapy.__dict__)
    __builtin__.__dict__.update(globals())
    if mydict is not None:
        __builtin__.__dict__.update(mydict)


    import re, atexit
    try:
        import rlcompleter,readline
    except ImportError:
        log_loading.info("Can't load Python libreadline or completer")
        READLINE=0
    else:
        READLINE=1
        class ScapyCompleter(rlcompleter.Completer):
            def global_matches(self, text):
                matches = []
                n = len(text)
                for lst in [dir(__builtin__), session.keys()]:
                    for word in lst:
                        if word[:n] == text and word != "__builtins__":
                            matches.append(word)
                return matches
        
    
            def attr_matches(self, text):
                m = re.match(r"(\w+(\.\w+)*)\.(\w*)", text)
                if not m:
                    return
                expr, attr = m.group(1, 3)
                try:
                    object = eval(expr)
                except:
                    object = eval(expr, session)
                if isinstance(object, Packet) or isinstance(object, Packet_metaclass):
                    words = filter(lambda x: x[0]!="_",dir(object))
                    words += [x.name for x in object.fields_desc]
                else:
                    words = dir(object)
                    if hasattr( object,"__class__" ):
                        words = words + rlcompleter.get_class_members(object.__class__)
                matches = []
                n = len(attr)
                for word in words:
                    if word[:n] == attr and word != "__builtins__":
                        matches.append("%s.%s" % (expr, word))
                return matches
    
        readline.set_completer(ScapyCompleter().complete)
        readline.parse_and_bind("C-o: operate-and-get-next")
        readline.parse_and_bind("tab: complete")
    
    
    session=None
    session_name=""
    CONFIG_FILE = DEFAULT_CONFIG_FILE

    iface = None
    try:
        opts=getopt.getopt(argv[1:], "hs:Cc:")
        for opt, parm in opts[0]:
            if opt == "-h":
                usage()
            elif opt == "-s":
                session_name = parm
            elif opt == "-c":
                CONFIG_FILE = parm
            elif opt == "-C":
                CONFIG_FILE = None
        
        if len(opts[1]) > 0:
            raise getopt.GetoptError("Too many parameters : [%s]" % string.join(opts[1]),None)


    except getopt.GetoptError, msg:
        log_loading.error(msg)
        sys.exit(1)


    if CONFIG_FILE:
        read_config_file(CONFIG_FILE)
        
    if session_name:
        try:
            os.stat(session_name)
        except OSError:
            log_loading.info("New session [%s]" % session_name)
        else:
            try:
                try:
                    session = cPickle.load(gzip.open(session_name,"rb"))
                except IOError:
                    session = cPickle.load(open(session_name,"rb"))
                log_loading.info("Using session [%s]" % session_name)
            except EOFError:
                log_loading.error("Error opening session [%s]" % session_name)
            except AttributeError:
                log_loading.error("Error opening session [%s]. Attribute missing" %  session_name)

        if session:
            if "conf" in session:
                conf.configure(session["conf"])
                session["conf"] = conf
        else:
            conf.session = session_name
            session={"conf":conf}
            
    else:
        session={"conf": conf}

    __builtin__.__dict__["scapy_session"] = session


    if READLINE:
        if conf.histfile:
            try:
                readline.read_history_file(conf.histfile)
            except IOError:
                pass
        atexit.register(scapy_write_history_file,readline)
    
    sys.ps1 = ColorPrompt()
    code.interact(banner = the_banner % (VERSION), local=session)

    if conf.session:
        save_session(conf.session, session)
    
    sys.exit()


def read_config_file(configfile):
    try:
        execfile(configfile)
    except IOError,e:
        log_loading.warning("Cannot read config file [%s] [%s]" % (configfile,e))
    except Exception,e:
        log_loading.exception("Error during evaluation of config file [%s]" % configfile)
        

if __name__ == "__main__":
    interact()
else:
    if DEFAULT_CONFIG_FILE:
        read_config_file(DEFAULT_CONFIG_FILE)
