import sys
import re
import os
import logging
import logging.handlers
from random import randint, sample, shuffle
import Queue
import multiprocessing
import socket
from requests import Session
from subprocess import Popen, PIPE, check_output
import time
import datetime
import inspect
# from pysnmp.hlapi import *

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

log = logging.getLogger(__name__)
log.addHandler(NullHandler())
check_crash_file = r'check_mdm_crash.pl.crash'
default_timeout = 60
global_config = None
cur_abs_path = os.path.split(inspect.getfile(inspect.currentframe()))[0]
global_config_file = os.path.abspath(os.path.join(cur_abs_path, '..', 'ac.ini'))
config_file = None
IP_ADDR = None
global_regex = re.compile(r'^\s*\[Global_Var\]\s*')
ini_item_regex = re.compile(r'^\s*(\w+)\s*=(.*)')

def init():
    global config_file, global_config, IP_ADDR
    global_config = read_config(global_config_file)
    # print "Get global config: {}".format(global_config)
    ip_prefix_list = [global_config['global_var']['ip_prefix']]
    for index in range(1,20):
        ip_prefix = 'ip_prefix{}'.format(index)
        if ip_prefix in global_config['global_var']:
            ip_prefix_list.append(global_config['global_var'][ip_prefix])
    # print "Got IP prefix list {}".format(ip_prefix_list)
    IP_ADDR = get_ip(*ip_prefix_list)
    if IP_ADDR is None:
        raise ValueError("Failed to get IP address with ip prefix list {}!".format(ip_prefix_list))
    config_file = get_config_file(IP_ADDR)
    if config_file is None:
        raise ValueError("Failed to get local config file name which matched ip address {}!".format(IP_ADDR))

def test_case():
    log.debug("Do nothing!")

def add_stderr_logger(level=logging.DEBUG, logger_name=__name__):
    # This method needs to be in this __init__.py to get the __name__ correct
    logger = logging.getLogger(logger_name)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(lineno)d %(message)s'))
    logger.addHandler(handler)
    logger.setLevel(level)
    # logger.debug('Added a stderr logging handler to logger: %s' % logger_name)
    return logger

def add_file_logger(filename='test_case_py.log', level=logging.DEBUG, logger_name=__name__):
    # This method needs to be in this __init__.py to get the __name__ correct
    logger = logging.getLogger(logger_name)
    handler = logging.FileHandler(filename=filename, mode='a')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(lineno)d %(message)s'))
    handler.setLevel(level)
    logger.addHandler(handler)
    # logger.debug('Added a file %s logging handler to logger: %s' % (filename, logger_name))
    return logger

def enable_log(log_level, logger_name, log_file):
    add_stderr_logger(log_level)
    add_stderr_logger(log_level, logger_name)
    file_path, file_name = os.path.split(log_file)
    file_name, file_ext = os.path.splitext(file_name)
    log_file_name = "{}_{}.log".format(file_name, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    add_file_logger(log_file_name, log_level)
    add_file_logger(log_file_name, log_level, logger_name)
    
def update_test(is_crash=0):
    config = merge_config()
    sess = Session()
    url = "{}/project/td".format(config['tbd_server'])
    post_params={
        'host_name': socket.gethostname(),
        'ip_addr': IP_ADDR,
        'tc_name': config['tc_name'],
        'test_client': config['monitor_client'],
        'build_verion': config['build_version'],
        'is_crash': is_crash,
        'ta_name': None,
        'tc_result': None,
        'ta_result': None,
    }
    resp = sess.post(url, data=post_params)
    log.debug("Post to {} with parameters {}".format(url, post_params))
    try:
        result = resp.json()
        if result['code']:
            log.error("update test data failed: {}!".format(result['result']))
        else:
            result = result['result']
            log.debug("update test data successfully: {}".format(result))
    except Exception as err:
        log.error("Failed to parse json result: {}!".format(err))
        
def check_crash(crash_info):
    if os.path.isfile(crash_info):
        log.debug("Found crash info file {}, and try to copy log files!".format(crash_info))
        crash_path = None
        try:
            with open(crash_info, 'r') as fh:
                crash_path = fh.readline()
                crash_path = crash_path.strip()
                log.debug("Got crash path '{}' from crash info files!".format(crash_path))
        except Exception as err:
            log.error("Failed to open {}: {}!".format(crash_info, err))
        if crash_path and os.path.isdir(crash_path):
            update_test(1)
            log.debug("Found crash dir, try to copy log files into it!")
            cmd(r"copy /y *.log {}".format(crash_path), timeout=300, skip_check=1)
            cmd("del /s /q *.log", timeout=300, skip_check=1)
            cmd(r"copy /y *.log.* {}".format(crash_path), timeout=300, skip_check=1)
            cmd("del /s /q *.log.*", timeout=300, skip_check=1)
            cmd("copy /y log\\*.* {}".format(crash_path), timeout=300, skip_check=1)
            cmd("del /s /q log\\*.*", timeout=300, skip_check=1)
            log.debug("Copy log files done, restart test case!".format(crash_info))
        else:
            log.debug("Not found crash dir, so just restart test case!")
        log.debug("Delete crash info file {} before exit.".format(crash_info))
        os.unlink(crash_info)
        sys.exit()

def merge_config():
    local_config = read_config(config_file)
    # print "Get local_config: {}".format(local_config)
    config = global_config['global_var'].copy()
    # print "Copy global config: {}".format(config)
    config.update(local_config['global_var'])
    # print "updated local_config: {}".format(config)
    if 'build_file' in config and os.path.isfile(config['build_file']):
        build_config = get_build_config(config['build_file'])
        config.update(build_config)
    config['ip_addr'] = IP_ADDR
    return config
        
def subs_var(string, config=None):
    if config is None:
        config = merge_config()
    for k in sorted(config.keys(), reverse=True):
        v = config[k]
        # log.debug("Try to replace ${} with {} in {}.".format(k, v, string))
        string = string.replace('$'+k, v)
    return string

def get_build_config(build_config):
    tbd_regex = re.compile(r'TBD_Server\s*\s*=\s*(.+)')
    project_regex = re.compile(r'Project_Name\s*\s*=\s*(.+)')
    build_regex = re.compile(r'Build_Version\s*\s*=\s*(.+)')
    meta_regex = re.compile(r'ACS_MetaBuild\s*\s*=\s*(.+)')
    crash_path_regex = re.compile(r'APS_USB_Upload_Root_Directory\s*\s*=\s*(.+)')
    match_regex = (tbd_regex, project_regex, build_regex, meta_regex, crash_path_regex)
    match_result = {}
    try:
        with open(build_config, 'r') as fh:
            while True:
                line = fh.readline()
                if not line:
                    break
                for regex in match_regex:
                    m = regex.match(line)
                    if m:
                        if regex == tbd_regex:
                            match_result['tbd_server'] = m.group(1)
                        elif regex == project_regex:
                            match_result['project_name'] = m.group(1)
                        elif regex == build_regex:
                            match_result['build_version'] = m.group(1)
                        elif regex == meta_regex:
                            match_result['meta_path'] = m.group(1)
                        elif regex == crash_path_regex:
                            match_result['crash_path'] = m.group(1)
                            if not os.path.isdir(match_result['crash_path']):
                                os.makedirs(match_result['crash_path'])
                        break
    except Exception as err:
        raise ValueError("Failed to open {} to read: {}".format(build_config, err))
    # if not (match_result.get('tbd_server', None) and match_result.get('project_name', None) and match_result.get('build_version', None) \
            # and match_result.get('meta_path', None) and match_result.get('crash_path', None))
        # raise ValueError("Need mandatory configuration in {}".format(config_file))
    return match_result
    
def read_config(conf_file):
    global_var = False
    config = {'global_var': {}}
    # log.debug("Try to open config file {}".format(conf_file))
    try:
        with open(conf_file, 'r') as fh:
            while True:
                line = fh.readline()
                if not line:
                    break
                if global_regex.match(line):
                    global_var = True
                    continue
                if global_var:
                    m = ini_item_regex.match(line)
                    if m:
                        (k, v) = (m.group(1), m.group(2))
                        v = v.strip()
                        config['global_var'][k] = v
                        continue
    except Exception as err:
        log.error("Failed to open config '{}' to read: {}".format(conf_file, err))
    # log.debug("read config: {}".format(config))
    return config

def cmd(command, timeout=default_timeout, skip_check=0):
    command = subs_var(command)
    if not skip_check:
        check_crash(check_crash_file)
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

def get_ip(*ip_prefix_list):
    ip_output = None
    local_ip = None
    try:
        ip_output = check_output('ipconfig')
    except Exception as err:
        log.error("Failed to run ipconfig to get ip: {}".format(err))
        return None
    for ip_prefix in ip_prefix_list:
        ip_regex = re.compile(r'IPv4\s+Address.*({}\S*)'.format(ip_prefix.replace('.', r'\.')))
        for m in ip_regex.finditer(ip_output):
            if local_ip:
                log.debug("Find more than one IP address: {}, {}, ignore the later one!".format(local_ip, m.group(1)))
            else:
                local_ip = m.group(1)
        if local_ip:
            break
        else:
            log.error("Failed to find any IP address with prefix '{}'!".format(ip_prefix))
    return local_ip

def get_config_file(local_ip):
    ip_index_regex = re.compile(r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$')
    ip_index = None
    config_file = None
    if local_ip:
        m = ip_index_regex.search(local_ip)
        if m:
            ip_parts = m.groups()
    if ip_parts:
        for index in range(0,4):
            ip_index = '.'.join(ip_parts[index:4])
            config_file = "ac_{}.ini".format(ip_index)
            log.debug("Get ip index {}, so try to find config {}.".format(ip_index, config_file))
            config_file = os.path.abspath(os.path.join(cur_abs_path, '..', config_file))
            # print "Try to find local config file {}".format(config_file)
            if os.path.isfile(config_file):
                log.debug("Find user config file {}. so use it!".format(config_file))
                break
            else:
                config_file = None
    else:
        log.error("Cannot get ip index, so failed to get config file!")
    return config_file

def sleep(sec, max_sec=None):
    sleep_sec = sec
    if max_sec is not None:
        sleep_sec = randint(sec, max_sec)
    log.debug("Sleep {} seconds...".format(sleep_sec))
    time.sleep(sleep_sec)

def arrange_internet_group(client_for_ap, aps_internet, internet_server_set):
    internet_group = {}
    if aps_internet and internet_server_set:
        aps_internet_num = len(aps_internet)
        internet_server_num = len(internet_server_set)
        aps_internet_sample = None
        internet_server_sample = sample(internet_server_set, internet_server_num)
        if aps_internet_num > internet_server_num:
            aps_internet_sample = sample(aps_internet, internet_server_num)
        else:
            aps_internet_sample = sample(aps_internet, aps_internet_num)
        index = 0
        for ap in aps_internet_sample:
            use_internet_server = internet_server_sample[index]
            if ap in client_for_ap:
                internet_group[use_internet_server] = client_for_ap[ap]
            index += 1
    return internet_group
            
def arrange_traffic_group(client_for_ap, aps_pair=None):
    traffic_group = []
    used_ap = {}
    if aps_pair:
        for pair in aps_pair:
            combine_clients = []
            for ap in pair:
                if ap in client_for_ap:
                    combine_clients.extend(client_for_ap[ap])
                    used_ap[ap] = 1
            if combine_clients:
                shuffle(combine_clients)
                traffic_group.append(combine_clients)
    for ap, ap_clients in client_for_ap.items():
        if ap not in used_ap:
            traffic_group.append(ap_clients)
    log.debug("Got traffic group: {}".format(traffic_group))
    return traffic_group
                    
def allocate_random_client(aps_set, clients_set):
    ap_num = len(aps_set)
    client_num = len(clients_set)
    group_num = min(ap_num, client_num/2)
    if group_num <= 0:
        raise ValueError("Group number is {}, your ap or client number is not reasonable!".format(group_num))
    log.debug("Test {} APs set: {}!".format(ap_num, aps_set))
    log.debug("Test {} clients set: {}!".format(client_num, clients_set))
    log.debug("It will use {} group to connect different APs!".format(group_num))
    extra_client_num = client_num - group_num * 2
    random_ap_list = sample(aps_set, group_num)
    random_client_num_for_ap = {ap:2 for ap in random_ap_list}
    random_client_for_ap = {}
    if extra_client_num > 0:
        log.debug("Clients number is enough and some groups would own more than 2 clients")
        for ap in random_ap_list:
            get_extra = randint(0, extra_client_num)
            random_client_num_for_ap[ap] += get_extra
            extra_client_num = extra_client_num - get_extra
            if extra_client_num <= 0:
                break
        if extra_client_num > 0:
            get_extra_bonus = randint(0, group_num - 1)
            random_client_num_for_ap[random_ap_list[get_extra_bonus]] += extra_client_num
    random_clients = clients_set[:]
    shuffle(clients_set)
    log.debug("shuffle clients to get random client list: {}".format(clients_set))
    client_offset = 0
    for ap in random_ap_list:
        client_start_index = client_offset
        client_offset = client_start_index + random_client_num_for_ap[ap]
        random_client_for_ap[ap] = random_clients[client_start_index:client_offset]
        log.debug("Get clients for {} from random duration [{},{}]: {}".format(ap, client_start_index, client_offset, random_client_for_ap[ap]))
    return random_client_for_ap
    
class Runner(object):
    default_timeout = default_timeout
    
    @classmethod
    def fork(cls, cmd, input=None, timeout=default_timeout):
        # log.debug("current pid {}".format(os.getpid()))
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=cls.popen, args=(q, cmd, input))
        p.start()
        # log.debug("fork child process pid {}".format(p.pid))
        # log.debug("join child process pid {} with timeout {}".format(p.pid, timeout))
        p.join(timeout)
        while p.is_alive():
            log.error("Process {} timeout! Terminating...".format(p.pid))
            p.terminate()
            p.join(1)
            raise ValueError("child process timeout {}".format(timeout))
        out, err = (None, None)
        try:
            out, err = q.get_nowait()
        except Queue.Empty:
            log.error("Cannot get stdout/stderr: no response until exit!")
        # log.debug("fork return output: {}".format(out))
        if err:
            log.error("fork return error: {}!".format(err))
        # log.debug("Process has been done!")
        return (out, err)
        
    @classmethod
    def popen(cls, q, cmd, input=None):
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate(input)
        if err:
            log = add_stderr_logger()
            log.error("popen error: {}".format(err))
        q.put((out, err))

init()

if __name__ == '__main__':
    add_stderr_logger()
    test_case()
    
