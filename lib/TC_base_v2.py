import os
import logging
import base64
import json
import time
import datetime
import threading
from collections import defaultdict, OrderedDict
import ConfigParser
from lib.TC_base import get_ip, get_config_file, Runner, subs_var as subs_var_v1
from random import randint
from subprocess import Popen, CREATE_NEW_CONSOLE

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

log = logging.getLogger(__name__)
log.addHandler(NullHandler())

GLOBAL_INI_SECTION = 'Global_Var'
DEFAULT_COMMAND_TIMEOUT = 30

class Manager(object):
    def __init__(self, config_file):
        self.config_file = config_file
        global_config = read_ini(config_file)
        local_config_file = find_local_ini(global_config)
        self.config = read_ini(local_config_file, global_config)
        self.global_config = self.config[GLOBAL_INI_SECTION]
        self.dut_set = construct_dut(self.config)
        
    def run(self):
        while True:
            log.debug("*"*20 + "Check Running Case" + "*"*20)
            for dut_addr, dut in self.dut_set.items():
                case = dut.next_case()
                case_list = dut.get_case_list(case)
                log.debug("Dut {} need to run cases: {}!".format(dut_addr, [c[0] for c in case_list]))
                dut.run_cases(case_list)
            time.sleep(2)

class TestCase(object):
    def __init__(self, attrs, *args):
        if isinstance(attrs, dict):
            self.var = attrs
        else:
            try:
                self.var = json.loads(base64.b64decode(attrs))
            except Exception as err:
                err_msg = "Failed to load json attributes: {}".format(err)
                log.fatal(err_msg)
                raise ValueError(err_msg)
    
    def _adb_detect(self, ip):
        output, error = self.cmd("adb devices")
        lines = output.split("\n")
        connected_ip = None
        for line in lines:
            if line.startswith(ip):
                if 'offline' in line:
                    raise ValueError("detect {} = offline, ignore it!".format(ip))
                connected_ip = line.split()[0]
                break
        return connected_ip
                
    def _adb_connect(self, ip):
        try:
            connected_ip = self._adb_detect(ip)
        except Exception as err:
            log.error("Detect raise error: {}, give up connection!".format(err))
            return None
        retry = 0
        while connected_ip is None:
            if retry > 1:
                self.cmd("adb kill-server")
            if retry > 3:
                log.error("Failed to connect {} more than {} times!".format(ip, retry))
                break
            retry += 1
            self.cmd("adb connect {}".format(ip))
            try:
                connected_ip = self._adb_detect(ip)
            except Exception as err:
                log.error("Detect raise error: {}, give up connection!".format(err))
                return None
        adb_root_detection = "adb -s {} root".format(connected_ip)
        try:
            output, err = Runner.fork(adb_root_detection, timeout=5)
            log.debug("Adb root: output: {}, stderr:{}!")
        except Exception as err:
            log.error("cmd '{}' exception: {}!".format(adb_root_detection, err))
            return None
        return connected_ip
            
    def _adb_shell(self, command, timeout=DEFAULT_COMMAND_TIMEOUT):
        connected_ip = self._adb_connect(self.var['dut_addr'])
        if not connected_ip:
            log.error("Failed to run {}, because cannot connect to {}!".format(command, self.var['dut_addr']))
            return (None, None)
        return self.cmd("adb -s {} shell {}".format(connected_ip, command), timeout)
    
    def _adb_pull(self, src, dst=None):
        connected_ip = self._adb_connect(self.var['dut_addr'])
        if not connected_ip:
            log.error("Failed to pull {}, because cannot connect to {}!".format(src, self.var['dut_addr']))
            return (None, None)
        if dst:
            return self.cmd("adb -s {} pull {} {}".format(connected_ip, src, dst))
        else:
            return self.cmd("adb -s {} pull {}".format(connected_ip, src))
    
    def _adb_push(self, src, dst):
        connected_ip = self._adb_connect(self.var['dut_addr'])
        if not connected_ip:
            log.error("Failed to push {}, because cannot connect to {}!".format(src, self.var['dut_addr']))
            return (None, None)
        return self.cmd("adb -s {} push {} {}".format(connected_ip, src, dst))
        
    def start_log(self, log_file, level='DEBUG'):
        file_path, file_name = os.path.split(log_file)
        file_name, file_ext = os.path.splitext(file_name)
        dut_addr = self.var['dut_addr']
        log_file_name = "DUT_{}_Case_{}_{}.log".format(dut_addr, file_name, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
        handler = logging.FileHandler(filename=log_file_name, mode='a')
        handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(funcName)s %(levelname)-8s %(lineno)d %(message)s'))
        handler.setLevel(level)
        logging.getLogger().addHandler(handler)
              
    def init(self):
        log.debug("Not implement user init test case!")
        
    def teardown(self):
        log.debug("Not implement user teardown test case!")
        
    def test(self):
        log.debug("Not implement user test case!")
        
    def run(self):
        self.init()
        self.test()
        self.teardown()
        
    def cmd(self, command, timeout=DEFAULT_COMMAND_TIMEOUT):
        command = subs_var_v1(command, self.var)
        log.debug("cmd '{}'({}) begin!".format(command, timeout))
        try:
            output, err = Runner.fork(command, timeout=timeout)
        except Exception as err:
            log.error("cmd '{}' exception: {}!".format(command, err))
            return
        if err:
            log.debug("cmd '{}' done with stderr: {}!".format(command, err))
        if output:
            log.debug("cmd '{}' done with stdout: {}!".format(command, output))
        if not (err or output):
            log.debug("cmd '{}' done without output/error!".format(command))
        return (output, err)
        
    def TA(self, action_name, *args, **kvargs):
        if hasattr(self, action_name):
            method = getattr(self, action_name)
            if callable(method):
                log.debug("Begin to run TA '{}'!".format(action_name))
                try:
                    result = method(*args, **kvargs)
                except Exception as err:
                    log.error("Abort TA '{}' with error: {}".format(action_name, err))
                    return
                if result:
                    log.debug("TA '{}' pass!".format(action_name))
                else:
                    log.debug("TA '{}' fail!".format(action_name))
                return result
        log.error("TA '{}' not found!".format(action_name))
        return
    
    def concurrent(self, *func_list):
        thread_list = []
        for func_argument in func_list:
            func = func_argument[0] if len(func_argument) > 0 else None
            args = func_argument[1] if len(func_argument) > 1 else ()
            kwargs = func_argument[2] if len(func_argument) > 2 else {}
            if callable(func):
                t = threading.Thread(target=func, args=args, kwargs=kwargs)
                thread_list.append(t)
                log.debug("Ready to run concurrent func: {}, args={}, kwargs={}!".format(func, args, kwargs))
                t.start()
            else:
                log.error("'{}' is not callable!".format(func))
        while True:
            is_done = 1
            for t in thread_list:
                if t.is_alive():
                    is_done = 0
                    break
            if is_done:
                log.debug("All concurrent funcs have been done!")
                break
            else:
                time.sleep(2)
    
    def upload(self, src, dst):
        log.error("'upload' should be implement in sub class!")
        
    def download(self, src, dst=None):
        log.error("'download' should be implement in sub class!")
        
    def dcmd(self, command, timeout=DEFAULT_COMMAND_TIMEOUT):
        log.error("'dcmd' should be implement in sub class!")
        
class Dut(object):
    CASE_MAP = set(['fix', 'loop', 'random', 'weight'])
    FIX_CASE_INDEX = 0
    def __init__(self, address, case_map, cases):
        if case_map in self.CASE_MAP:
            self.addr = address
            self.case_map = case_map
            self.cases = cases
            self.cur_case = None
            self.loop_case_index  = 0
            self.total_cases = len(cases)
            self.running_process = defaultdict(dict)
        else:
            raise ValueError("case_map should be one of {}!".format(self.CASE_MAP))
    
    def get_case(self, name):
        target_case = None
        for case in self.cases:
            if case['name'] == name:
                target_case = case
                break
        return target_case
    
    def get_case_list(self, case):
        case_list = []
        case_name = case['name']
        case_list.append((case_name, case))
        concurrent_case = case.get('concurrent_case', None)
        if concurrent_case:
            for conc_case_name in concurrent_case.split(';'):
                if conc_case_name.startswith('Case_'):
                    conc_case_name = conc_case_name[5:]
                conc_case = self.get_case(conc_case_name)
                if conc_case:
                    case_list.append((conc_case_name, conc_case))
        return case_list
        
    def next_case(self):
        if self.case_map == 'fix':
            if not self.cur_case:
                if Dut.FIX_CASE_INDEX >= self.total_cases:
                    Dut.FIX_CASE_INDEX = 0
                self.cur_case = self.cases[Dut.FIX_CASE_INDEX]
                Dut.FIX_CASE_INDEX += 1
        elif self.case_map == 'loop':
            if self.loop_case_index >= self.total_cases:
                self.loop_case_index = 0
            self.cur_case = self.cases[self.loop_case_index]
            self.loop_case_index += 1
        elif self.case_map == 'random':
            random_index = randint(0, self.total_cases - 1)
            self.cur_case = self.cases[random_index]
        elif self.case_map == 'weight':
            raise ValueError("Not support dut case map: 'weight'!")
        return self.cur_case

    def stop_cases(self, case_name=None):
        if case_name:
            if case_name in self.running_process:
                if self.running_process[case_name]:
                    self.running_process[case_name].terminate()
                # del self.running_process[case_name] #maybe fail to terminate
            else:
                log.warn("Not find running case with name '{}'".format(case_name))
        else:
            for name in self.running_process:
                if self.running_process[name]:
                    self.running_process[name].terminate()
                # del self.running_process[name]
                
    def run_cases(self, case_list):
        for case_name, case in case_list:
            if case_name in self.running_process:
                process = self.running_process[case_name]
                if process:
                    if process.poll() is None:
                        log.debug("Dut {} case {} has NOT terminated, waiting for it!".format(self.addr, case_name))
                        continue
                del self.running_process[case_name]
                log.debug("Dut {} case {} has terminated, try to restart it!".format(self.addr, case_name))
            case_file = '{}.py'.format(case_name)
            if os.path.isfile(case_file):
                case['dut_addr'] = self.addr
                cmd_line = 'python {} {}'.format(case_file, base64.b64encode(json.dumps(case)))
                log.debug("Dut {} start to run {} with args={}!".format(self.addr, case_file, case))
                self.running_process[case_name] = Popen(cmd_line, creationflags=CREATE_NEW_CONSOLE)
            else:
                log.error("Dut {} Failed to find case {}!".format(self.addr, case_file))
                        
def read_ini(config_file, config=None):
    parser = ConfigParser.ConfigParser()
    parser.read(config_file)
    if config is None:
        config = OrderedDict()
    for section in parser.sections():
        if section not in config:
            config[section] = {}
        for option in parser.options(section):
            val = parser.get(section, option)
            config[section][option] = val
    log.debug("parsed config file = {}".format(config))
    return config
    
def find_local_ini(global_config):
    ip_prefix_list = []
    ip_prefix_index = range(1,20)
    ip_prefix_index.insert(0, '')
    for index in ip_prefix_index:
        ip_prefix = 'ip_prefix{}'.format(index)
        if ip_prefix in global_config[GLOBAL_INI_SECTION]:
            ip_prefix_list.append(global_config[GLOBAL_INI_SECTION][ip_prefix])
    log.debug("Got IP prefix list {}".format(ip_prefix_list))
    ip_addr = get_ip(*ip_prefix_list)
    log.debug("Got expected IP {}".format(ip_prefix_list))
    if ip_addr is None:
        raise ValueError("Failed to get IP address with ip prefix list {}!".format(ip_prefix_list))
    config_file = get_config_file(ip_addr)
    if config_file is None:
        raise ValueError("Failed to get local config file name which matched ip address {}!".format(ip_addr))
    log.debug("Get local ini file name={}".format(config_file))
    return config_file 

def construct_dut(config):
    dut_list = config[GLOBAL_INI_SECTION]['dut_list'].split(';')
    dut_case_map = config[GLOBAL_INI_SECTION]['dut_case_map']
    cases = []
    for section in config:
        if len(section) > 5 and section.startswith('Case_'):
            case = dict(config[GLOBAL_INI_SECTION])
            case.update(config[section])
            case['name'] = section[5:]
            cases.append(case)
            log.debug("Add case={}".format(case['name']))
    duts = OrderedDict()
    for dut in dut_list:
        duts[dut] = Dut(dut, dut_case_map, cases)
        log.debug("construct dut {}".format(dut))
    return duts

if __name__ == '__main__':
    pass
    
