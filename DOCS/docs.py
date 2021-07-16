 __SCANNER__ = '''Performs a scan of the requested resource
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

__filestested__='''

r_version.h: C source, ASCII text, with CRLF line terminators
linux-arm-64.c: C source, ASCII text, with CRLF line terminators
radare2.exe: PE32+ executable (console) x86-64, for MS Windows
r_syscall.dll: PE32+ executable (DLL) (GUI) x86-64, for MS Windows
libacof32.lib: current ar archive
libaomf32.lib: SysEx File - ADA
/usr/bin/7z: POSIX shell script, ASCII text executable
/usr/bin/acpi_listen: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=692a2a9bb658b5494b6afe62825242812adadb93, stripped
/usr/bin/ark: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ea4d5d5355bd41b904549986eeedc4294c6acbfc, stripped
avr4.xu: assembler source, ASCII text
/usr/lib/avr/bin/ld: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f81aa1b54e8240f49924e20b776e2f1168a6c1d4, stripped
/usr/share/discord/libvulkan.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=70afa139f77567801e3922512205db4dde77ee4d, stripped

'''