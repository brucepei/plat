import sys
import time
import logging
from logging.config import fileConfig
from lib.TC_base_v2 import TestCase

LOGGING_CONFIG_FILE = 'logging_v2.ini'
fileConfig(LOGGING_CONFIG_FILE)
log = logging.getLogger()

class SNSTestCase(TestCase):
    def init(self):
        print "init test with var {}".format(self.var)
        
    def teardown(self):
        print "test cleanup!"
        
    def test(self):
        # input = raw_input("input=")
        print "reboot {} and sleep {}!".format(self.var['reboot_action'], self.var['reboot_interval'])
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
        log.debug("Start to run...")
        tc.run()
    except Exception as err:
        log.error("Critical exception: {}".format(err))
        raw_input("pause...")