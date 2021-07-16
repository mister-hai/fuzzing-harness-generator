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
print("[+] Basic imports completed")

################################################################################
##############                  LOCAL IMPORTS                  #################
################################################################################
from codeqlops import scanoperation

from util import errormessage,greenprint,blueprint,redprint,rreplace
from util import filescan,readelf

from SharedObject import SharedObject
from Header import Header

from DOCS.docs import *
################################################################################
##############                  CODE SCANNER                   #################
################################################################################

class Scanner(object):
    '''
    {docs}
    '''.format(docs = __SCANNER__)
    def __init__(self,detectmode:str,maxthreads:int):#,arguments):
        #limit it to 4 please
        self.maxthreads             = maxthreads        
        self.multiharness           = True
        self.detectionmode          = detectmode
        #A list of the operations available in the codeqlops.py file
        self.codeqloperationslist = scanoperation.keys()        
        self.cwd = lambda : os.getcwd()

        self.mapdependencies = True
        self.dependancymapping = {}
        #this is the file representation we pack into 
        # one new one per item found matching spec
        self.sharedobjectpile = {}

        if self.detectionmode == 'headers':
            self.manageheaders()
        # make a harness for every function/file/object
        # mass enumeration of vulnerabilities
        # very CPU intensive
        if self.multiharness == False:
            pass

    def findsharedobject(self):
        '''
        setter method for the .so files found by the scanner
        '''
            #0x0000000000000001 (NEEDED)             Shared library: [libz.so.1]
            #0x0000000000000001 (NEEDED)             Shared library: [libdl.so.2]
            #0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
        for filename in os.listdir(self.projectroot):
            #uses the linux command 
            # `file`
            if "shared object" in filescan(filename):
                greenprint("Found shared object " + filename)
                newsharedobject = SharedObject(filename= filename)
                self.sharedobjectspile[filename] = newsharedobject
    
    def listsharedobjects(self):
        '''
        lister method for the .so files scanned by the tool

        returns an array of keys
        '''
        if len(self.sharedobjectspile) != 0:
            returnkeys = self.sharedobjectspile.keys()
            returnpile = []
            for each in returnkeys:
                returnpile.append(returnkeys)
            return returnpile

    def getsharedobject(self,itemkey):
        '''
        getter method for .so files scanned by the tool
        '''
        if itemkey in dir(self.sharedobjectspile):
            return self.sharedobjectpile[itemkey]
        else:
            KeyError


    def readsharedobject(self):
        '''
        .so parsing
        '''
        for sharedobject in self.sharedobjectspile    
        pass

    def readelf(self):
        '''
        ELF parsing

        Uses `readelf` from standard linux utilities

        '''
        for sharedobject in self.sharedobjectspile.keys():
            readelf(self.sharedobjectspile[sharedobject])
            self.object_functions["output"] = readelf
            self.object_functions["object"] = sharedobject


    def readheaders(self):
        '''
        .h parsing
        '''
            self.object_functions    = {"output":[],"object":[]}
            self.total_functions     = {"function":[], "type":[],"type_or_loc":[]}
            self.defined_functions   = {"function":[], "type":[],"object": [],"type_or_loc":[]}
            self.elf_functions       = {"function":[], "type":[],"object": [],"type_or_loc":[]}
            self.shared_functions    = {"function":[], "type":[],"object": [],"type_or_loc":[]}

    def picker(self,outputlocation):
        '''
        pick apart the loaded file for the scanner to scan
        '''
        data = pd.read_csv(outputlocation)
        total_functions["function"] = list(data.f)
        total_functions["type"] = list(data.t)
        total_functions["type_or_loc"] = list(data.g)
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



