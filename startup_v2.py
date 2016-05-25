import os
import re
import logging
from logging.config import fileConfig
from subprocess import check_call
from lib.TC_base_v2 import Manager

STARTUP_NON_BLOCK_LOADER = r'cmd /c start'
STARTUP_MAP = {
    '.exe': '',
    '.bat': '',
    '.py': 'python',
    '.pl': 'perl',
    '.tcl': 'tclsh',
}
GLOBAL_CONFIG_FILE = 'ac.ini'
LOGGING_CONFIG_FILE = 'logging_v2.ini'
STARTUP_FILE_REGEX = re.compile(r'\s*([^()]+)(?:\(\s*([^()]*)\)\s*)?')
PARAM_REGEX = re.compile(r'\s*([^(),]+)\s*\,?')

fileConfig(LOGGING_CONFIG_FILE)
log = logging.getLogger()

if __name__ == "__main__":
    manager = Manager(GLOBAL_CONFIG_FILE)
    
    startup_scripts = manager.global_config['startup_scripts']
    startup_scripts = startup_scripts.split(';')
    log.debug("Startup={}".format(startup_scripts))
    for script in startup_scripts:
        m = STARTUP_FILE_REGEX.match(script)
        param_list = []
        if m:
            script_file, params_string = m.groups()
            if params_string:
                index = 0
                for m_param in PARAM_REGEX.finditer(params_string):
                    param = m_param.group(1)
                    if param in manager.global_config:
                        param = manager.global_config[param]
                    param_list.append(param)
                    log.debug("\tparam{}={}".format(index, param))
                    index += 1
        else:
            log.error("Invalid format for startup file: {}, ignore it!".format(script))
            continue
        dir, full_name = os.path.split(script_file)
        name, ext = os.path.splitext(full_name)
        log.debug("Try to start '{}{}' with params {} in dir '{}'".format(name, ext, param_list, dir))
        if ext not in STARTUP_MAP:
            log.error("Not support startup script type {}, ignore it!".format(ext))
            continue
        interpreter = STARTUP_MAP[ext]
        cmd = "{} {} {} {}".format(STARTUP_NON_BLOCK_LOADER, interpreter, script_file, ' '.join(param_list))
        log.debug("Ready to start program: {}".format(cmd))
        try:
            check_call(cmd)
        except Exception as err:
            log.error("Failed to run {} with error: {}".format(cmd, err))
        
    manager.run()
