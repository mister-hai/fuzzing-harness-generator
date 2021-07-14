# -*- coding: utf-8 -*-
#!/usr/bin/python3.9
################################################################################
##       Automated Fuzzing Harness Generator - Vintage 2021 Python 3.9        ##
################################################################################                
# Licenced under GPLv3                                                        ##
# https://www.gnu.org/licenses/gpl-3.0.en.html                                ##
#                                                                             ##
# The above copyright notice and this permission notice shall be included in  ##
# all copies or substantial portions of the Software.                         ##
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
################################################################################
TESTING = True
"""
"""
################################################################################
##############                      IMPORTS                    #################
################################################################################
import cpp
import lief
import gzip
import sys,os
import logging
import inspect
import argparse
import traceback
import threading
import subprocess
import pandas as pd
from pathlib import Path
from datetime import date
from os import _exit as exit
from ast import literal_eval
from signal import SIGINT, signal
from subprocess import DEVNULL, STDOUT

TESTING = True
################################################################################
# Terminal Colorication Imports
################################################################################

try:
    import colorama
    from colorama import init
    init()
    from colorama import Fore, Back, Style
    if TESTING == True:
        COLORMEQUALIFIED = True
except ImportError as derp:
    print("[-] NO COLOR PRINTING FUNCTIONS AVAILABLE, Install the Colorama Package from pip")
    COLORMEQUALIFIED = False

print("[+] Basic imports completed")

###############################################################################
#   LOGGING
################################################################  ###############
log_file            = 'LOGGING LOGGER LOG'
logging.basicConfig(filename=log_file, format='%(asctime)s %(message)s', filemode='w')
logger              = logging.getLogger()
script_cwd          = Path().absolute()
script_osdir        = Path(__file__).parent.absolute()
###############################################################################
#   Lambdas
###############################################################################
redprint          = lambda text: print(Fore.RED + ' ' +  text + ' ' + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
blueprint         = lambda text: print(Fore.BLUE + ' ' +  text + ' ' + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
greenprint        = lambda text: print(Fore.GREEN + ' ' +  text + ' ' + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
yellowboldprint = lambda text: print(Fore.YELLOW + Style.BRIGHT + ' {} '.format(text) + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
makeyellow        = lambda text: Fore.YELLOW + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else text
makered           = lambda text: Fore.RED + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else None
makegreen         = lambda text: Fore.GREEN + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else None
makeblue          = lambda text: Fore.BLUE + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else None
debugmessage     = lambda message: logger.debug(blueprint(message)) 
info_message      = lambda message: logger.info(greenprint(message))   
warning_message   = lambda message: logger.warning(yellowboldprint(message)) 
error_message     = lambda message: logger.error(redprint(message)) 
critical_message  = lambda message: logger.critical(yellowboldprint(message))
 
gzcompress = lambda inputdata: {"data" : gzip.compress(inputdata)}

scanfilesbyextension = lambda directory,extension: [f for f in os.listdir(directory) if f.endswith(extension)]
################################################################################
##############           SYSTEM AND ENVIRONMENT                #################
################################################################################

def error_printer(message):
    exc_type, exc_value, exc_tb = sys.exc_info()
    trace = traceback.TracebackException(exc_type, exc_value, exc_tb) 
    try:
        redprint( message + ''.join(trace.format_exception_only()))
        #traceback.format_list(trace.extract_tb(trace)[-1:])[-1]
        blueprint('LINE NUMBER >>>' + str(exc_tb.tb_lineno))
    except Exception:
        yellowboldprint("EXCEPTION IN ERROR HANDLER!!!")
        redprint(message + ''.join(trace.format_exception_only()))

class GenPerpThreader():
    '''
    General Purpose threading implementation that accepts a generic programmatic entity
    '''
    def __init__(self,function_to_thread):
        self.thread_function = function_to_thread
        self.function_name   = getattr(self.thread_function.__name__)
        self.threader(self.thread_function,self.function_name)

    def threader(self, thread_function, name):
        info_message("Thread {}: starting".format(self.function_name))
        thread = threading.Thread(None,self.thread_function, self.function_name)
        thread.start()
        info_message("Thread {}: finishing".format(name))

################################################################################
##############                        CORE                     #################
################################################################################

class Command():
    def __init__(self, cmd_name , command_struct):
        '''init stuff
        ONLY ONE COMMAND, WILL THROW ERROR IF NOT TO SPEC
        '''
        self.name                = cmd_name
        try:
            self.cmd_line        = command_struct.get("command")
            self.info_message    = command_struct.get("info_message")
            self.success_message = command_struct.get("success_message")
            self.failure_message = command_struct.get("failure_message")
        except Exception:
            error_printer("[-] JSON Input Failed to MATCH SPECIFICATION!\n\n    ")

    def __repr__(self):
        greenprint("Command:")
        print(self.name)
        greenprint("Command String:")
        print(self.cmd_line)

class ExecutionPool():
    def __init__(self):
        '''todo : get shell/environ setup and CLEAN THIS SHIT UP MISTER'''
        self.set_actions = {}

    def get_actions_from_set(self, command_set : CommandSet):
        for attribute in command_set.items():
            if attribute.startswith("__") != True:
                self.set_actions.update({attribute : getattr(command_set,attribute)})

    def run_set(self, command_set : CommandSet):
        for field_name, field_object in command_set.items:
            if field_name in basic_items:
                command_line    = getattr(field_object,'cmd_line')
                success_message = getattr(field_object,'success_message')
                failure_message = getattr(field_object,'failure_message')
                info_message    = getattr(field_object,'info_message')
                yellow_bold_print(info_message)
                try:
                    self.exec_command(command_line)
                    print(success_message)
                except Exception:
                    error_printer(failure_message)

    def run_function(self,command_set, function_to_run ):
        '''
        '''
        try:
            #requesting a specific Command()
            command_object  = command_set.command_list.get(function_to_run)
            command_line    = getattr(command_object,'cmd_line')
            success_message = getattr(command_object,'success_message')
            failure_message = getattr(command_object,'failure_message')
            info_message    = getattr(command_object,'info_message')
            yellow_bold_print(info_message)
            try:
                self.exec_command(command_line)
                print(success_message)
            except Exception:
                error_printer(failure_message)
            # running the whole CommandSet()
        except Exception:
            error_printer(failure_message)

    def exec_command(self, command, blocking = True, shell_env = True):
        '''TODO: add formatting'''
        try:
            if blocking == True:
                step = subprocess.Popen(command,shell=shell_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                output, error = step.communicate()
                for output_line in output.decode().split('\n'):
                    info_message(output_line)
                for error_lines in error.decode().split('\n'):
                    critical_message(error_lines)
                return step
            elif blocking == False:
                # TODO: not implemented yet                
                pass
        except Exception as derp:
            yellow_bold_print("[-] Interpreter Message: exec_command() failed!")
            return derp

class PybashyRunFunction():
    ''' 
    This is the class you should use to run one off functions, established inline,
    deep in a complex structure that you do not wish to pick apart
    The function should contain only a "steps" variable and format()
    ''' 
    def __init__(self, FunctionToRun):
        NewFunctionSet       = FunctionSet()
        #get name of function
        new_function.name  = getattr(FunctionToRun, "__name__")
        steps              = getattr(FunctionToRun, "steps")
        #itterate over the steps to get each individual action/command
        # added to the FunctionSet as a Command() via the 
        for step in steps:
            for command_name in step.keys():
                cmd_dict = step.get(command_name)
                #add the step to the functionset()
                NewFunctionSet.AddCommandDict(command_name,cmd_dict)

class PybashyRunSingleJSON():
    ''' 
    This is the class you should use to run one off commands, established inline,
    deep in a complex structure that you do not wish to pick apart
    The input should contain only a single json Command() item and format()
    {   
        "IPTablesAcceptNAT": {
            "command"         : "iptables -t nat -I PREROUTING 1 -s {} -j ACCEPT".format(self.remote_IP),
            "info_message"    : "[+] Accept All Incomming On NAT Subnet",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
        }
    }
    ''' 
    def __init__(self, JSONCommandToRun:dict):
        # grab the name
        NewCommandName = JSONCommandToRun.keys[0]
        # craft the command
        NewCommand = Command(NewCommandName,JSONCommandToRun)
        # init an execution pool to run commands
        execpool   = ExecutionPool()
        # run the command in a new thread
        GenPerpThreader(execpool.exec_command(NewCommand))
        # huh... I hope that really is all it takes... that seemed simple!

################################################################################
##############             COMMAND LINE ARGUMENTS              #################
################################################################################

parser = argparse.ArgumentParser(description="""\

A program to help you to automatically create fuzzing harnesses.         
""")
parser.add_argument('--librarypath',
                        dest = 'library',
                        action  = "store" ,
                        default = "/workspace" ,
                        help = "path to lib",
                        required=True
                        )
parser.add_argument('--codeqlpath',
                        dest = 'codeqlpath',
                        action  = "store",
                        default = "" ,
                        help = "path to codeql modules, database, and binary",
                        required=True
                        )
parser.add_argument('--database',
                        dest = 'database',
                        action  = "store",
                        default = "" ,
                        help = "Codeql database",
                        required=True
                        )
parser.add_argument('--multiharness',
                        dest = 'multiharness',
                        action  = "store_true",
                        default = False ,
                        help = " use this flag for multiple argument harnesses",
                        required=False
                        )

parser.add_argument('--outputdir', 
                        dest = 'outputdir',
                        action  = "store",
                        default = False ,
                        help = "Output directory",
                        required=True
                        )
parser.add_argument('--compilerflags',
                        dest = 'compilerflags',
                        action  = "store",
                        default = False ,
                        help = "compiler flags (include)",
                        required=False
                        )
parser.add_argument('--headers',
                        dest = 'headers',
                        action  = "store",
                        default = False ,
                        help = "header files, CSV string",
                        required=False)
parser.add_argument('--debug',
                        dest = 'debug',
                        action  = "store_true",
                        default = False ,
                        help = "display debugging information"
                        )
parser.add_argument('--detection', 
                        dest = 'detection',
                        action  = "store",
                        default = 'headers' ,
                        help = "'headers' to Auto-detect headers \n\
                            'functions' for function definitions? what is this dogin?.", required=True)
arguments = parser.parse_args()

cwd = lambda : os.getcwd()

def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)

def writecodeql(scanoperation:dict):
    '''feed a dict formed as thus
    {'name': str, 'filedata' : textblock }
'''
    filehandle = open(scanoperation['name'])
    filehandle.write(scanoperation['filedata'])
    filehandle.close()
################################################################################
##############                  CODE SCANNER                   #################
################################################################################

#commands, top down

# if automatic detection of headers

#SEG2
#elif int(arguments.detection) == 1:
#"cp " + cwd + "/oneargfunc.ql " + arguments.ql, shell=True)
#            subprocess.check_output("cd "+ arguments.ql + ";" +arguments.ql+ "codeql query run oneargfunc.ql -o " + arguments.output + "onearg.bqrs -d " + arguments.ql + arguments.database +";" + arguments.ql + "codeql bqrs decode --format=csv " + arguments.output + "onearg.bqrs -o " + arguments.output + "onearg.csv", shell=True)

class Scanner(object):
    def __init__(self,mode:str):#,arguments):
        #false for single arg harness
        self.multiharnessbool = arguments.multiharness
        self.projectroot = arguments.librarypath
        self.codeqlroot  = "./codeql/"
        self.harnessoutputdirectory = "./harnesses/"
        self.codeqloutputdir = "./codeqloutput/"
        self.bqrsoutputdirectory = "./bqrsfiles/"
        self.oneargoutputname = "onearg.csv"
        self.detectionmode = mode

    def codeqlquery(self,query):
        self.queryoutputfilename = lambda filename: '{}.bqrs'.format(filename)
        self.codeqlquery = 'codeql query run {} -o {} {} -d {} {databaseb}'.format( 
                query,
                self.queryoutputfilename
                self.codeqloutputdir,
                self.codeqlroot
                )
        #SEG1
    if self.detection == 'headers':
        #"cp {}/{} {}".format(currworkdir, onearglocation,arguments.ql)
        '''codeql query run {} -o {output} onearg.bqrs -d {ql} {db} ;\
{ql} codeql bqrs decode --format=csv {output} onearg.bqrs -o {arguments.output} {outputcsv}\
'''.format(ql = arguments.ql, db = arguments.database, onearglocation, arguments.output, outputcsv = oneargoutputname)

        if not self.multiharnessbool:
            self.scanner.shared_objects = []
            self.object_functions    = {"output":[],"object":[]}
            self.total_functions     = {"function":[], "type":[],"type_or_loc":[]}
            self.defined_functions   = {"function":[], "type":[],"object": [],"type_or_loc":[]}
            self.elf_functions       = {"function":[], "type":[],"object": [],"type_or_loc":[]}
            self.shared_functions    = {"function":[], "type":[],"object": [],"type_or_loc":[]}
        #SEG1
        if arguments.detection == 'headers':
            pass
        #SEG2
        elif int(arguments.detection) == 1:
            pass

    def findsharedobject(self):
        ''''''
        for filename in os.listdir(projectroot):
            if "shared object" in subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode('utf-8'):
                greenprint("Found shared object " + filename)
                self.shared_objects.append(filename)

        for object in scanner.shared_objects:
            readelf = subprocess.run("readelf", "-a",object, stdout=subprocess.PIPE).stdout.decode('utf-8')
            self.object_functions["output"].append(readelf)
            self.object_functions["object"].append(object)

    def picker(self,outputlocation):
        data = pd.read_csv(outputlocation)
        total_functions["function"] = list(data.f)
        total_functions["type"] = list(data.t)
        total_functions["type_or_loc"] = list(data.g)

for index, define in enumerate(scanner.object_functions["output"]):
    for index2, cur in enumerate(total_functions["function"]):
        if (str(cur) in define):
            defined_functions["function"].append(cur)
            defined_functions["type"].append(total_functions["type"][index2])
            defined_functions["object"].append(scanner.object_functions["object"][index])
            defined_functions["type_or_loc"].append(total_functions["type_or_loc"][index2])
for i in range(len(defined_functions["function"])):
    if ".so" not in str(defined_functions["object"][i]):
        elf = lief.parse(arguments.library + str(defined_functions["object"][i]))
        try:
            addr = elf.get_function_address(str(defined_functions["function"][i]))
        except: 
            continue
        elf.add_exported_function(addr, str(defined_functions["function"][i]))
        elf[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE) 
        outfile = "lib%s.so" % str(defined_functions["function"][i])
        elf.write(outfile)
        elf_functions["function"].append(str(defined_functions["function"][i]))
        elf_functions["type"].append(str(defined_functions["type"][i]))
        elf_functions["object"].append(outfile)
        elf_functions["type_or_loc"].append(str(defined_functions["type_or_loc"][i]))
    else:
        shared_functions["function"].append(str(defined_functions["function"][i]))
        shared_functions["type"].append(str(defined_functions["type"][i]))
        shared_functions["object"].append(str(defined_functions["object"][i]))
        shared_functions["type_or_loc"].append(str(defined_functions["type_or_loc"][i]))
for index3 in range(len(shared_functions["function"])):
    header_section = ""
    if not arguments.headers:
        if int(arguments.detection) == 0:
            header_section = "#include \"" + os.path.basename(shared_functions["type_or_loc"][index3]) + "\"\n\n"
        else:
            header_section = ""
    else: 
        header_list = arguments.headers.split(",")
        for x in header_list:
            header_section+= "#include \"" + x + "\"\n\n"
                
    if int(arguments.detection) == 0: 
        main_section = "int LLVMFuzzerTestOneInput(" + str(shared_functions["type"][index3]) + " Data, long Size) {\n\t" + str(shared_functions["function"][index3]) + "(Data);\n\treturn 0;\n}"
    else: 
        main_section = str(shared_functions["type_or_loc"][index3]) + " " + str(shared_functions["function"][index3]) + "(" + str(shared_functions["type"][index3])+ " testcase);\n" + "int LLVMFuzzerTestOneInput(" + str(shared_functions["type"][index3]) + " Data, long Size) {\n\t" + str(shared_functions["function"][index3]) + "(Data);\n\treturn 0;\n}" 
    full_source = header_section + main_section
    filename = "".join([c for c in str(shared_functions["function"][index3]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
    f = open(arguments.output + filename +".c", "w")
    f.write(full_source)
    if int(arguments.detection) == 0:
        if arguments.flags is not None and int(arguments.debug) == 1:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        elif arguments.flags is not None and int(arguments.debug) == 0:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        elif arguments.flags is None and int(arguments.debug) == 1:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        else:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
    else:
        if arguments.flags is not None and int(arguments.debug) == 1:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        elif arguments.flags is not None and int(arguments.debug) == 0:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        elif arguments.flags is None and int(arguments.debug) == 1:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        else:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
if (int(arguments.detection) == 1):
    for index4 in range(len(elf_functions["function"])):
        header_section = ""
        if not arguments.headers:
                header_section = ""
        else: 
            header_list = arguments.headers.split(",")
                for x in header_list:
                    header_section+= "#include \"" + x + "\"\n\n"               
            main_section = "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef " + str(elf_functions["type_or_loc"][index4]) + "(*" + str(elf_functions["function"][index4]) + "_t)(" + str(elf_functions["type"][index4]) + ");\n" + "void CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen(\"" + arguments.library + str(elf_functions["object"][index4]) + "\",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nint LLVMFuzzerTestOneInput(" + str(elf_functions["type"][index4]) + " Data, long Size) {\n\tLoadLibrary();\n\t" + str(elf_functions["function"][index4]) + "_t " + str(elf_functions["function"][index4]) + "_s = (" + str(elf_functions["function"][index4]) + "_t)dlsym(library,\"" + str(elf_functions["function"][index4]) + "\");\n\t" + str(elf_functions["function"][index4]) + "_s(Data);\n\treturn 0;\n}"
            full_source = header_section + main_section
            filename = "".join([c for c in str(elf_functions["function"][index4]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
            f = open(arguments.output + filename +".c", "w")
            f.write(full_source)
            if arguments.flags is not None and int(arguments.debug) == 1:
                
                print("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " " + arguments.output + filename +".c -o " + arguments.output + filename)
                subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
            elif arguments.flags is not None and int(arguments.debug) == 0:
                subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif arguments.flags is None and int(arguments.debug) == 1:
                subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
            else:
                subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT) 
elif (int(arguments.mode) == 1):
    scanner.shared_objects=[]
    func_objects=[]
    object_functions={"output":[],"object":[]}
    cwd = os.getcwd()
    if (int(arguments.detection) == 0):
        subprocess.check_output("cp " + cwd + "/multiarglocation.ql " + arguments.ql, shell=True)
        subprocess.check_output("cd "+ arguments.ql + ";" +arguments.ql+ "codeql query run multiarglocation.ql -o " + arguments.output + "multiarg.bqrs -d " + arguments.ql + arguments.database +";" + arguments.ql + "codeql bqrs decode --format=csv " + arguments.output + "multiarg.bqrs -o " + arguments.output + "multiarg.csv", shell=True)
    elif (int(arguments.detection) == 1):
        subprocess.check_output("cp " + cwd + "/multiargfunc.ql " + arguments.ql, shell=True)
        subprocess.check_output("cd "+ arguments.ql + ";" +arguments.ql+ "codeql query run multiargfunc.ql -o " + arguments.output + "multiarg.bqrs -d " + arguments.ql + arguments.database +";" + arguments.ql + "codeql bqrs decode --format=csv " + arguments.output + "multiarg.bqrs -o " + arguments.output + "multiarg.csv", shell=True)
    data = pd.read_csv(arguments.output + "multiarg.csv")
    total_functions = data.drop_duplicates().groupby(["f", "g"], as_index=False)["t"].agg(list)
    print(total_functions)
    os.chdir(arguments.library)
    defined_functions = pd.DataFrame(columns=["f","t","g","object"])
    for filename in os.listdir(arguments.library):
        if "shared object" in subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode('utf-8'):
            print("Found shared object " + filename)
            scanner.shared_objects.append(filename)
    for obj in scanner.shared_objects:
        scanner.object_functions["output"].append(subprocess.run(["readelf", "-a",obj], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        scanner.object_functions["object"].append(obj)
    for index, defe in enumerate(scanner.object_functions["output"]):
        for index2, cur in enumerate(total_functions["f"]):
            if (str(cur) in defe):
                func_objects.append(scanner.object_functions["object"][index])
                defined_functions = defined_functions.append([total_functions.iloc[index2,:]])
    defined_functions["object"] = func_objects
    defined_functions = defined_functions.to_dict(orient='list')
    elf_functions={"function":[], "type":[],"object": [],"type_or_loc":[]}
    shared_functions={"function":[], "type":[],"object": [],"type_or_loc":[]}
    for i in range(len(defined_functions["f"])):
        if ".so" not in str(defined_functions["object"][i]):
            elf = lief.parse(arguments.library + str(defined_functions["object"][i]))
            try:
                addr = elf.get_function_address(str(defined_functions["f"][i]))
            except: 
                continue
            elf.add_exported_function(addr, str(defined_functions["f"][i]))
            elf[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE) 
            outfile = "lib%s.so" % str(defined_functions["f"][i])
            elf.write(outfile)
            elf_functions["function"].append(str(defined_functions["f"][i]))
            elf_functions["type"].append(str(defined_functions["t"][i]))
            elf_functions["object"].append(outfile)
            elf_functions["type_or_loc"].append(str(defined_functions["g"][i]))
        else:
            shared_functions["function"].append(str(defined_functions["f"][i]))
            shared_functions["type"].append(str(defined_functions["t"][i]))
            shared_functions["object"].append(str(defined_functions["object"][i]))
            shared_functions["type_or_loc"].append(str(defined_functions["g"][i]))
    for index3 in range(len(shared_functions["function"])):
        header_section = ""
        if not arguments.headers:
            if (int(arguments.detection) == 0):
                header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n" + "#include \"" + os.path.basename(shared_functions["type_or_loc"][index3]) + "\"\n\n"
            else:
                header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"            
        else: 
            header_list = arguments.headers.split(",")
            header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
            for x in header_list:
                header_section+= "#include \"" + x + "\"\n\n"
        stub = ""
        marker = 1
        param = ""
        header_args = ""
        for ty in literal_eval(shared_functions["type"][index3]):
            if ty.count('*') == 1:
                if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" 
                   param += "pointer" + str(marker) + ", "
                   header_args += ty + "pointer" + str(marker) + ", "
                elif "char" in ty or "string" in ty:
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                   param += "pointer" + str(marker) + ", "
                   header_args += ty + "pointer" + str(marker) + ", "
                elif "float" in ty or "double" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") +">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                    param += "pointer" + str(marker) + ", "
                    header_args += ty + "pointer" + str(marker) + ", "
                elif "bool" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty + "pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                    param += "pointer" + str(marker) + ", "
                    header_args += ty + "pointer" + str(marker) + ", "
                else: 
                    continue    
            elif ty.count('*') == 2:
                if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                   param += "doublepointer" + str(marker) + ", "
                   header_args += ty + "doublepointer" + str(marker) + ", "
                elif "char" in ty or "string" in ty:
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n" 
                   param += "doublepointer" + str(marker) + ", "
                   header_args += ty + "doublepointer" + str(marker) + ", "
                elif "float" in ty or "double" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                    param += "doublepointer" + str(marker) + ", "
                    header_args += ty + "doublepointer" + str(marker) + ", "
                elif "bool" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty.replace("*", "") + "*pointer" + str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"    
                    param += "doublepointer" + str(marker) + ", "
                    header_args += ty + "doublepointer" + str(marker) + ", "                    
                else: 
                    continue
            else:
                if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n" 
                   param += "data" + str(marker) + ", "
                   header_args += ty + " data" + str(marker) + ", "
                elif "char" in ty or "string" in ty:
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n"
                   param += "data" + str(marker) + ", "
                   header_args += ty + " data" + str(marker) + ", "
                elif "float" in ty or "double" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty +">();\n"
                    param += "data" + str(marker) + ", "
                    header_args += ty + " data" + str(marker) + ", "
                elif "bool" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n"
                    param += "data" + str(marker) + ", "
                    header_args += ty + " data" + str(marker) + ", "
                else: 
                    continue
            marker+= 1
        param = rreplace(param,', ','',1)
        header_args = rreplace(header_args,', ','',1)
        if (int(arguments.detection) == 0):
            main_section = "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t" + stub + str(shared_functions["function"][index3]) + "(" + param + ");\nreturn 0;\n}"
        else:
            main_section = str(shared_functions["type_or_loc"][index3]) + " " + str(shared_functions["function"][index3]) +"(" + header_args + ");\n\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t" + stub + str(shared_functions["function"][index3]) + "(" + param + ");\nreturn 0;\n}"
        full_source = header_section + main_section
        filename = "".join([c for c in str(shared_functions["function"][index3]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
        f = open(arguments.output + filename +".cc", "w")
        f.write(full_source)
        if int(arguments.detection) == 0:
            if arguments.flags is not None and int(arguments.debug) == 1:
                
                print("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename)
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            elif arguments.flags is not None and int(arguments.debug) == 0:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif arguments.flags is None and int(arguments.debug) == 1:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            else:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        else:
            if arguments.flags is not None and int(arguments.debug) == 1:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            elif arguments.flags is not None and int(arguments.debug) == 0:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif arguments.flags is None and int(arguments.debug) == 1:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            else:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +arguments.library + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
    if (int(arguments.detection) == 1):
        for index4 in range(len(elf_functions["function"])):
            header_section = ""
            if not arguments.headers:
                    header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"            
            else: 
                header_list = arguments.headers.split(",")
                header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
                for x in header_list:
                    header_section+= "#include \"" + x + "\"\n"
            stub = ""
            marker = 1
            param = ""
            header_args = ""
            for ty in literal_eval(elf_functions["type"][index4]):
                if ty.count('*') == 1:
                    if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" 
                       param += "pointer" + str(marker) + ", "
                       header_args += ty + "pointer" + str(marker) + ", "
                    elif "char" in ty or "string" in ty:
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                       param += "pointer" + str(marker) + ", "
                       header_args += ty + "pointer" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") +">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                        param += "pointer" + str(marker) + ", "
                        header_args += ty + "pointer" + str(marker) + ", "
                    elif "bool" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty + "pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                        param += "pointer" + str(marker) + ", "
                        header_args += ty + "pointer" + str(marker) + ", "
                    else: 
                        continue    
                elif ty.count('*') == 2:
                    if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                       param += "doublepointer" + str(marker) + ", "
                       header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "char" in ty or "string" in ty:
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n" 
                       param += "doublepointer" + str(marker) + ", "
                       header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                        param += "doublepointer" + str(marker) + ", "
                        header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "bool" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty.replace("*", "") + "*pointer" + str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"    
                        param += "doublepointer" + str(marker) + ", "
                        header_args += ty + "doublepointer" + str(marker) + ", "                    
                    else: 
                        continue
                else:
                    if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n" 
                       param += "data" + str(marker) + ", "
                       header_args += ty + " data" + str(marker) + ", "
                    elif "char" in ty or "string" in ty:
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n"
                       param += "data" + str(marker) + ", "
                       header_args += ty + " data" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty +">();\n"
                        param += "data" + str(marker) + ", "
                        header_args += ty + " data" + str(marker) + ", "
                    elif "bool" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n"
                        param += "data" + str(marker) + ", "
                        header_args += ty + " data" + str(marker) + ", "
                    else: 
                        continue
                marker+= 1
            param = rreplace(param,', ','',1)
            header_args = rreplace(header_args,', ','',1)
            main_section = "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef " + str(elf_functions["type_or_loc"][index4]) + "(*" + str(elf_functions["function"][index4]) + "_t)(" + header_args + ");\nvoid CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen(\"" + arguments.library + str(elf_functions["object"][index4]) + "\",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t\n\tLoadLibrary();\n\t" + stub + str(elf_functions["function"][index4]) + "_t " + str(elf_functions["function"][index4]) + "_s = (" + str(elf_functions["function"][index4]) + "_t)dlsym(library,\"" + str(elf_functions["function"][index4]) + "\");\n\t" + str(elf_functions["function"][index4]) + "_s(" + param + ");\n\treturn 0;\n}" 
            full_source = header_section + main_section
            filename = "".join([c for c in str(elf_functions["function"][index4]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
            f = open(arguments.output + filename +".cc", "w")
            f.write(full_source)
            if arguments.flags is not None and int(arguments.debug) == 1:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            elif arguments.flags is not None and int(arguments.debug) == 0:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif arguments.flags is None and int(arguments.debug) == 1:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            else:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT) 
else:
    print("Invalid Mode")



