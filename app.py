
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
main file
"""
################################################################################
##############                      IMPORTS                    #################
################################################################################

import sys
import argparse
import configparser
from util import errormessage,greenprint
from harness import Scanner
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
                        default = "./codeql" ,
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
                        help = "display debugging information \n DEFAULT: On"
                        )
parser.add_argument('--detection', 
                        dest = 'detection',
                        action  = "store",
                        default = 'headers' ,
                        help = "'headers' to Auto-detect headers \n\
                            'functions' for function definitions? what is this dogin?.", required=True)
arguments = parser.parse_args()
 
 #these are the old options
('-L', '--library',  "Specify directory to program's libraries")
('-C', '--ql',  "Specify directory of codeql modules, database, and binary")
('-D', '--database',  "Specify Codeql database")
('-M', '--mode',  "Specify 0 for 1 argument harnesses or 1 for multiple argument harnesses")
('-O', '--output',  "Output directory")
('-F', '--flags',  "Specify compiler flags (include)")
('-X', '--headers',  "Specify header files (comma seperated)")
('-Y', '--detection', "Automatic header detection (0) or Function Definition (1).")
###############################################################################
##                     CONFIGURATION FILE PARSER                             ##
###############################################################################
try:
    arguments = parser.parse_args()
    if arguments.config == True:
        config = configparser.ConfigParser()
        codeqllocation = config['DEFAULT']['codeql']
        projectroot            = config['DEFAULT']['projectroot']
        codeqlroot             = config['DEFAULT']['codeqlroot']
        harnessoutputdirectory = config['DEFAULT']['harnessoutputdirectory']
        codeqloutputdir        = config['DEFAULT']['codeqloutputdir']
        bqrsoutputdirectory    = config['DEFAULT']['bqrsoutputdirectory']
        oneargoutputname       = config['DEFAULT']['oneargoutputname']
    elif arguments.config == False:
        projectroot            = arguments.projectroot
        codeqlroot             = arguments.codeqlroot
        harnessoutputdirectory = arguments.harnessoutputdirectory
        codeqloutputdir        = arguments.codeqloutputdir
        bqrsoutputdirectory    = arguments.bqrsoutputdirectory
        oneargoutputname       = arguments.oneargoutputname
 




except Exception:
    errormessage("[-] Configuation File could not be parsed!")
    sys.exit(1)

greenprint("[+] Loaded Commandline Arguments")

def rootinplace():
    '''establishes this scripts operating location and relative code locations'''
    env = [projectroot,
           codeqlroot,
           harnessoutputdirectory,
           codeqloutputdir,
           bqrsoutputdirectory,
           oneargoutputname,
           detectionmode
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

def rreplace(s, old, new, occurrence):
    '''copied from somewhere
    string replacment inline'''
    li = s.rsplit(old, occurrence)
    return new.join(li)

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

def bqrsinfo():
    command = "codeql bqrs decode --format=csv {} onearg.bqrs -o {bqrsoutput} {outputcsvfile}"


if __name__ == '__main__':
    scanmodule = Scanner()
    #root the scanner in place
    scanmodule.rootinplace()
    scanmodule.scancode()
    #scanmodule.genharness()