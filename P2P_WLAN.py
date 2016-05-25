import sys
import time
import logging
from logging.config import fileConfig
from lib.TC_Naples_LA import NapelsTestCase

LOGGING_CONFIG_FILE = 'logging_v2.ini'
fileConfig(LOGGING_CONFIG_FILE)
log = logging.getLogger()

class SNSTestCase(NapelsTestCase):
    def init(self):
        print "init test with var {}".format(self.var)
        
    def teardown(self):
        print "test cleanup!"
        
    def test_p2p(self, count):
        for i in range(1, count):
            print "p2p {}".format(i)
            time.sleep(1)
        print "p2p done!"
        
    def test_bt(self, count):
        for i in range(1, count):
            print "bt {}".format(i)
            time.sleep(1)
        print "bt done!"
     
    def test(self):
        print "p2p {} and sleep {}!".format(self.var['p2p_action'], self.var['scan_interval'])
        self.dcmd("ifconfig")
        self.download("/etc/ifconfig")
        self.upload("a.ini", "/etc/ifconfig")
        self.TA('ENABLE_WIFI', 'wlan1')
        self.concurrent((self.test_bt, (10,)), (self.test_p2p, (5,)))
        self.cmd("echo 127.0.0.1 $p2p_action")
        self.cmd("ping 127.0.0.1")
        input = raw_input("input=")
        print "done!"
        sleep = 3
        while sleep > 0:
            print "\rRemain {}".format(sleep),
            time.sleep(1)
            sleep -= 1
            
if __name__ == '__main__':
    try:
        tc = SNSTestCase(*sys.argv[1:])
        tc.start_log(__file__)
        log.debug("Start to run {}...".format(__file__))
        tc.run()
    except Exception as err:
        log.error("Critical exception: {}".format(err))
        raw_input("pause...")