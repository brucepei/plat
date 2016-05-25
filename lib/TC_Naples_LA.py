import logging
from lib.TC_base_v2 import TestCase

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

log = logging.getLogger(__name__)
log.addHandler(NullHandler())

DEFAULT_COMMAND_TIMEOUT = 30

class NapelsTestCase(TestCase):
    def upload(self, src, dst):
        log.debug("Upload files to dut: from {} to {}!".format(src, dst))
        return self._adb_push(src, dst)
        
    def download(self, src, dst=None):
        log.debug("Download files from dut: from {} to {}!".format(src, dst))
        return self._adb_pull(src, dst)
        
    def dcmd(self, command, timeout=DEFAULT_COMMAND_TIMEOUT):
        log.debug("Run dut cmd '{}'".format(command))
        return self._adb_shell(command, timeout)
        
    def ENABLE_WIFI(self, intf):
        output, error = self.dcmd('ifconfig {}'.format(intf))
        print "enable wifi {}:\nOutput: {}\nError:{}".format(intf, output, error)
        if error:
            return False
        return True
        
if __name__ == '__main__':
    pass
    
