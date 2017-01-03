import optparse
from socket import *
from threading import *
screenLock = Semaphore(value=1)

def connScan(tgtHost,tgtPort):
    try:
        connSkt = socket(AF_INET,SOCK_STREAM)
        connSkt.connect((tgtHost,tgtPort))
        connSkt.send('Hello and have a nice day\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print '[+]%d/tcp open'% tgtPort
        print '[+] ' + str(results)
    except:
        screenLock.acquire()
        print '[-]%d/tcp closed'% tgtPort
    finally:
        screenLock.release()
        connSkt.close()

def connScanL(tgtHost,tgtPort):
    try:
        connSkt = socket(AF_INET,SOCK_STREAM)
        connSkt.connect((tgtHost,tgtPort))
        connSkt.send('Hello and have a nice day\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print '[+]%d/tcp open'% tgtPort
        print '[+] ' + str(results)
    except:
        screenLock.acquire()
    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost,tgtPorts):
    try:
        tgtIP =gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host"%tgtHost
        return
    try:
        tgtName =gethostbyaddr(tgtIP)
        print '\n[+] Scan Results for: ' + tgtName[0]
    except:
        print '\n[+] Scan Results for: ' + tgtIP
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost,int(tgtPort)))
        t.start()

def portScanA(tgtHost):
    try:
        tgtIP =gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host"%tgtHost
        return
    try:
        tgtName =gethostbyaddr(tgtIP)
        print '\n[+] Scan Results for: ' + tgtName[0]
    except:
        print '\n[+] Scan Results for: ' + tgtIP
    setdefaulttimeout(1)
    print 'Scanning all ports.'
    for tgtPort in range(0,65535):
        t = Thread(target=connScanL, args=(tgtHost,int(tgtPort)))
        t.start()

def main():
    parser = optparse.OptionParser("usage%prog "+" -H <target host> -p <target port> or None (Scan all ports)")
    parser.add_option('-H',dest = 'tgtHost',type='string',help='specify target post')
    parser.add_option('-p',dest='tgtPort',type='string',help='specify target port[s] separated by comma',default='ALL')
    (options,args)=parser.parse_args()
    tgtHost =options.tgtHost
    tgtPorts =str(options.tgtPort).split(',')
    if(tgtHost ==None) or (tgtPorts[0] ==None):
        print parser.usage
        exit(0)
    elif (tgtHost != None) and (tgtPorts[0] =='ALL'):
        portScanA(tgtHost)
        exit(0)
    else:
        portScan(tgtHost,tgtPorts)

if __name__ == '__main__':
    main()