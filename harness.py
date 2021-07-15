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
scanning file
"""
################################################################################
##############                      IMPORTS                    #################
################################################################################
import cpp
import lief
import sys,os
import subprocess
import pandas as pd
from pathlib import Path
from datetime import date
from os import _exit as exit
from ast import literal_eval
from signal import SIGINT, signal
from subprocess import DEVNULL, STDOUT
from codeqlops import scanoperation
from util import errormessage,greenprint,blueprint,redprint
print("[+] Basic imports completed")


class SharedObject(object):
    '''
    This is a representation of a file
    '''
    def __init__(self):
        self.defined_functions = {
            'function'   : [],
            'type'       : [],
            'object'     : [],
            'type_or_loc': []
            }
        self.object_functions = {
            "output"     :[],
            "object"     :[]
            }
        self.elf_functions     = {
            "function"   : [],
            "type"       : [],
            "object"     : [],
            "type_or_loc": []
            }
        self.shared_functions  = {
            "function"   : [],
            "type"       : [],
            "object"     : [],
            "type_or_loc": []
            }
        self.total_functions  = {
            "function"   :[], 
            "type"       :[],
            "type_or_loc":[]
            }
################################################################################
##############                  CODE SCANNER                   #################
################################################################################

class Scanner(object):
    '''Performs a scan of the requested resource
General Usage:
    
    param : arglen
        type: int
        info: number of inputs per whatever, I dunno figure this shit out
    
    param: detectmode
        type:
        info:
    
    param: maxtreads
        type: int
        info: number of threads to use for scanning
    
    Load up bpython (seriously)

>>> pip3 install bpython; python3 -m bpython
>>> #load the scanner
>>> scanmodule = Scanner()
>>> #root the scanner in place
>>> scanmodule.rootinplace()
>>> scanmodule.scancode()
>>> scanmodule.genharness()

    '''
    def __init__(self,detectmode:str, arglen:int, maxthreads:int):#,arguments):
        #limit it to 4 please
        self.maxthreads             = maxthreads        
        self.multiharness           = True
        self.projectroot            = "./input_source_code"
        self.codeqlroot             = "./codeql/"
        self.harnessoutputdirectory = "./harnesses/"
        self.codeqloutputdir        = "./codeqloutput/"
        self.bqrsoutputdirectory    = "./bqrsfiles/"
        self.oneargoutputname       = "onearg.csv"
        self.detectionmode          = detectmode
        #A list of the operations available in the codeqlops.py file
        self.codeqloperationslist = scanoperation.keys()        
        self.cwd = lambda : os.getcwd()

        #this is the file representation we pack into 
        # one new one per item found matching spec
        self.sharedobject = SharedObject()

        if self.detectionmode == 'headers':
            self.manageheaders()
        # make a harness for every function/file/object
        # mass enumeration of vulnerabilities
        # very CPU intensive
        if self.multiharness == False:
            pass
    def rootinplace(self):
        '''establishes this scripts operating location and relative code locations'''
        self.env = [self.projectroot,
                    self.codeqlroot,
                    self.harnessoutputdirectory,
                    self.codeqloutputdir,
                    self.bqrsoutputdirectory,
                    self.oneargoutputname,
                    self.detectionmode
                    ]
        self.setenv(self.env)

    def setenv(self, installdirs:list):
        '''sets the PATH variables for operation'''
        try:
            #validation for future expansions
            if len(installdirs) > 1:
                #make the installation directories
                for projectdirectory in installdirs:
                    os.makedirs(projectdirectory, exist_ok=False)
                #set path to point to those directories
                os.environ["PATH"] += os.pathsep + os.pathsep.join(installdirs)
        except Exception:
            errormessage("[-] Failure to set Environment, Check Your Permissions Schema")

    def rreplace(self, s, old, new, occurrence):
        '''copied from somewhere
        string replacment inline'''
        li = s.rsplit(old, occurrence)
        return new.join(li)

    def writecodeql(self,codename:str):
        '''writes the requested codeql block to file for execution
        currently supported operations are as follows
        {}
        '''.format(self.codeqloperationslist)
        name = scanoperation[codename]
        data = scanoperation['filedata']
        filehandle = open(name)
        filehandle.write(data)
        filehandle.close()

    def makedirs():
        '''
        makes directories for project
        '''
        pass
    
    def codeqlquery(self,query):
        self.queryoutputfilename = lambda filename: '{}.bqrs'.format(filename)
        self.codeqlquery = 'codeql query run {} -o {} {} -d {}'.format( 
                query,
                self.queryoutputfilename,
                self.codeqloutputdir)

    def findsharedobject(self):
        ''''''
        for filename in os.listdir(self.projectroot):
            if "shared object" in subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode('utf-8'):
                greenprint("Found shared object " + filename)
                self.shared_objects.append(filename)

    def readelf(self):
        ''''''
        for object in self.shared_objects:
            readelf = subprocess.run("readelf", "-a",object, stdout=subprocess.PIPE).stdout.decode('utf-8')
            self.object_functions["output"].append(readelf)
            self.object_functions["object"].append(object)


    def manageheaders(self):
            self.scanner.shared_objects = []
            self.object_functions    = {"output":[],"object":[]}
            self.total_functions     = {"function":[], "type":[],"type_or_loc":[]}
            self.defined_functions   = {"function":[], "type":[],"object": [],"type_or_loc":[]}
            self.elf_functions       = {"function":[], "type":[],"object": [],"type_or_loc":[]}
            self.shared_functions    = {"function":[], "type":[],"object": [],"type_or_loc":[]}

    def bqrsinfo(self):
        command = "codeql bqrs decode --format=csv {} onearg.bqrs -o {bqrsoutput} {outputcsvfile}"
        pass

    def picker(self,outputlocation):
        data = pd.read_csv(outputlocation)
        total_functions["function"] = list(data.f)
        total_functions["type"] = list(data.t)
        total_functions["type_or_loc"] = list(data.g)

    def parseobject(self):
        '''parses the currently loaded object file
    - extract the following items
        - functions
        - function type?
        - 
'''
        for index, define in enumerate(self.object_functions["output"]):
            for index2, function in enumerate(total_functions["function"]):
                if (str(function) in define):
                    self.defined_functions["function"].append(function)
                    self.defined_functions["type"].append(total_functions["type"][index2])
                    self.defined_functions["object"].append(self.object_functions["object"][index])
                    self.defined_functions["type_or_loc"].append(total_functions["type_or_loc"][index2])
        for i in range(len(defined_functions["function"])):
            if ".so" not in str(defined_functions["object"][i]):
                elf = lief.parse(self.projectroot + str(defined_functions["object"][i]))
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
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        elif arguments.flags is not None and int(arguments.debug) == 0:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        elif arguments.flags is None and int(arguments.debug) == 1:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        else:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
    else:
        if arguments.flags is not None and int(arguments.debug) == 1:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        elif arguments.flags is not None and int(arguments.debug) == 0:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        elif arguments.flags is None and int(arguments.debug) == 1:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True)
        else:
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".c -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
if (int(arguments.detection) == 1):
    for index4 in range(len(elf_functions["function"])):
        header_section = ""
        if not arguments.headers:
                header_section = ""
        else: 
            header_list = arguments.headers.split(",")
                for x in header_list:
                    header_section+= "#include \"" + x + "\"\n\n"               
            main_section = "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef " + str(elf_functions["type_or_loc"][index4]) + "(*" + str(elf_functions["function"][index4]) + "_t)(" + str(elf_functions["type"][index4]) + ");\n" + "void CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen(\"" + self.projectroot + str(elf_functions["object"][index4]) + "\",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nint LLVMFuzzerTestOneInput(" + str(elf_functions["type"][index4]) + " Data, long Size) {\n\tLoadLibrary();\n\t" + str(elf_functions["function"][index4]) + "_t " + str(elf_functions["function"][index4]) + "_s = (" + str(elf_functions["function"][index4]) + "_t)dlsym(library,\"" + str(elf_functions["function"][index4]) + "\");\n\t" + str(elf_functions["function"][index4]) + "_s(Data);\n\treturn 0;\n}"
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
if arguments.mode== '1':
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
    os.chdir(self.projectroot)
    defined_functions = pd.DataFrame(columns=["f","t","g","object"])
    for filename in os.listdir(self.projectroot):
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
            elf = lief.parse(self.projectroot + str(defined_functions["object"][i]))
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
                
                print("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename)
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            elif arguments.flags is not None and int(arguments.debug) == 0:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif arguments.flags is None and int(arguments.debug) == 1:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            else:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        else:
            if arguments.flags is not None and int(arguments.debug) == 1:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            elif arguments.flags is not None and int(arguments.debug) == 0:
                
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + arguments.flags + " -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif arguments.flags is None and int(arguments.debug) == 1:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True)
            else:
               
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + arguments.output + " -L " +self.projectroot + " -l:" + str((shared_functions["object"][index3])) + " " + arguments.output + filename +".cc -o " + arguments.output + filename, env=self.env, shell=True, stdout=DEVNULL, stderr=STDOUT)
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
            main_section = "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef " + str(elf_functions["type_or_loc"][index4]) + "(*" + str(elf_functions["function"][index4]) + "_t)(" + header_args + ");\nvoid CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen(\"" + self.projectroot + str(elf_functions["object"][index4]) + "\",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t\n\tLoadLibrary();\n\t" + stub + str(elf_functions["function"][index4]) + "_t " + str(elf_functions["function"][index4]) + "_s = (" + str(elf_functions["function"][index4]) + "_t)dlsym(library,\"" + str(elf_functions["function"][index4]) + "\");\n\t" + str(elf_functions["function"][index4]) + "_s(" + param + ");\n\treturn 0;\n}" 
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



