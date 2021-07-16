# -*- coding: utf-8 -*-
#!/usr/bin/python3.9
################################################################################
##  Pybash-sh; fuzzing harness generator - Vintage 2021 Python 3.9            ##
################################################################################                
#  YOU HAVE TO PROVIDE THE MODULES YOU CREATE AND THEY MUST FIT THE SPEC      ##
#                                                                             ##
#     You can fuck up the backend all you want but if I can't run the module  ##
#     you provide, nor understand it, you have to then follow the original    ##
#     terms of the GPLv3 and open source all modified code so I can see       ##
#     what's going on.                                                        ##
#                                                                             ##
# Licenced under GPLv3-modified                                               ##
# https://www.gnu.org/licenses/gpl-3.0.en.html                                ##
#                                                                             ##
# The above copyright notice and this permission notice shall be included in  ##
# all copies or substantial portions of the Software.                         ##
#                                                                             ##
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  ##
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,    ##
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE ##
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER      ##
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,#
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN   ##
# THE SOFTWARE.                                                               ##
################################################################################
"""
core.py
"""

TESTING = True
import sys,os
import logging
import pkgutil
import inspect
import traceback
import threading
import subprocess
from pathlib import Path
from importlib import import_module

from util import greenprint,yellowboldprint,blueprint,redprint,errormessage,makeyellow
from util import info_message,critical_message,GenPerpThreader
basic_items  = ['__name__', 'steps','success_message', 'failure_message', 'info_message']

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
            errormessage("[-] JSON Input Failed to MATCH SPECIFICATION!\n\n    ")

    def __repr__(self):
        greenprint("Command:")
        print(self.name)
        greenprint("Command String:")
        print(self.cmd_line)

class CommandSet():
    ''' metaclass'''
    #def __new__(cls):
    #    ''' waaat'''
    #    cls.name         = str
    #    cls.__name__     = cls.name
    #    cls.__qualname__ = cls.__name__
       
    def __init__(self):
        ''' waaat'''
        self.name         = ''
        self.__name__     = self.name
        self.__qualname__ = self.__name__
    
    def __repr__(self):
        makeyellow("HI! I AM A CommandSet()!")
    
    def AddCommandDict(self, cmd_name, new_command_dict):
        '''Creates a new Command() from a step and assigns to self'''
        try:
            new_command = Command(cmd_name, new_command_dict)
            setattr(self , new_command.name, new_command)
        except Exception:
            errormessage('[-] Interpreter Message: CommandSet() Could not Init')  

class FunctionSet(CommandSet):
    '''This is just a CommandSet under a different name'''
    def __init__(self):
        '''This is a functionSet()'''
        # I shouldn't have to declare this twice, why did it not work?!?!
        self.name         = ''
        self.__name__     = self.name
        self.__qualname__ = self.__name__
        
    def __repr__(self):
         makeyellow("FunctionSet() ")

    def add_function(self, function_set):
        function_name = function_set.name
        greenprint("INTERNAL: FunctionSet().add_function(FunctionSet())")
        print(function_set.name)
        setattr(self, function_name, function_set)

class ExecutionPool():
    def __init__(self):
        '''todo : get shell/environ setup and CLEAN THIS SHIT UP MISTER'''
        self.set_actions = {}

    def get_actions_from_set(self, command_set : CommandSet):
        #itterating over the classes properties
        for attribute in command_set.items():
            #leave out internals
            #only get the user declared code
            if attribute.startswith("__") != True:
                # add the named attribute from the function to the set of all actions
                self.set_actions.update({attribute : getattr(command_set,attribute)})

    def run_set(self, command_set : CommandSet):
        '''
        runs a full command set
        '''
        for field_name, field_object in command_set.items:
            if field_name in basic_items:
                command_line    = getattr(field_object,'cmd_line')
                success_message = getattr(field_object,'success_message')
                failure_message = getattr(field_object,'failure_message')
                info_message    = getattr(field_object,'info_message')
                yellowboldprint(info_message)
                try:
                    self.exec_command(command_line)
                    print(success_message)
                except Exception:
                    errormessage(failure_message)

    def run_function(self,command_set, function_to_run ):
        '''
        Run a specific Command()
        '''
        try:
            command_object  = command_set.command_list.get(function_to_run)
            command_line    = getattr(command_object,'cmd_line')
            success_message = getattr(command_object,'success_message')
            failure_message = getattr(command_object,'failure_message')
            info_message    = getattr(command_object,'info_message')
            yellowboldprint(info_message)
            try:
                self.exec_command(command_line)
                print(success_message)
            except Exception:
                errormessage(failure_message)
            # running the whole CommandSet()
        except Exception:
            errormessage(failure_message)

    def exec_command(self, command, blocking = True, shell_env = True):
        '''
        Internal use only
        '''
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
            yellowboldprint("[-] Interpreter Message: exec_command() failed!")
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
        NewFunctionSet.name  = getattr(FunctionToRun, "__name__")
        steps                = getattr(FunctionToRun, "steps")
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



    ########################################################################
    ####                    TESTING EXEC POOL NOW                       ####
    ###             # NEVER FEAR, THE END IS FUCKING NEAR!#              ###
    ########################################################################
#cmdstrjson = {'ls_etc' : { "command": "ls -la /etc","info_message":"[+] Info Text","success_message" : "[+] Command Sucessful", "failure_message" : "[-] ls -la Failed! Check the logfile!"},'ls_home' : { "command" : "ls -la ~/","info_message" : "[+] Info Text","success_message" : "[+] Command Sucessful","failure_message" : "[-] ls -la Failed! Check the logfile!"}}
#exec_pool          = ExecutionPool()
#module_set         = ModuleSet('test1')
#function_prototype = CommandSet()
#new_function       = FunctionSet()
#runner = CommandRunner(exec_pool = exec_pool)
#runner.get_stuff("test.py")
#def run_test():
#    try:
#        for command_name in cmdstrjson.keys():
#            cmd_dict = cmdstrjson.get(command_name)
#            critical_message('[+] Adding command_dict to FunctionSet()')
#            new_function.AddCommandDict(command_name,cmd_dict)
#
#            critical_message('[+] Adding command_dict to ModuleSet()')
#            module_set.AddCommandDict(command_name, cmdstrjson.get(command_name))
#
#            critical_message('[+] Adding FunctionSet() to ModuleSet()')
#            module_set.add_function(new_function)
#
#            critical_message('[+] Adding ModuleSet() to ExecutionPool()')
#            setattr(exec_pool, module_set.__name__, module_set)
#            greenprint("=======================================")
#            critical_message('[+] TEST COMMAND : ls -la ./') 
#            # feed it JUST the command str
#            blueprint("exec_pool.exec_command(exec_pool.test1.ls_la.cmd_line)")
#            greenprint("=======================================")
            #exec_pool.exec_command(exec_pool.test.ls_la.cmd_line)
#            greenprint("=======================================")
#            critical_message('[+] TEST FUNCTION : ls -la ./')
            #run the whole functionset()
#            blueprint("exec_pool.run_function(exec_pool.test1)")
#            greenprint("=======================================")
            #exec_pool.run_function(exec_pool.test1)
#    except Exception:
#        errormessage("WAAAAGHHH!\n\n")
#run_test()