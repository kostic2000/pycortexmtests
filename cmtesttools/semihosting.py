'''
Created on 20 Mar 2018

@author: kostic
'''
import sys
import os
import errno
import time

class Semihosting(object):
   
    def __init__(self):
        self.errno = 0
        self.files = [None] * 80
        self.files[0] = sys.stdin
        self.files[1] = sys.stdout
        self.files[2] = sys.stderr
        self.tmps = [None] * 255

    def __set_errno(self, errno):
        if errno is not None:
            self.errno = errno
        else:
            self.errno = -1

    def __get_file(self, h):
        if h < len(self.files) and self.files[h] is not None:
            self.errno = 0
            return self.files[h]
        else:
            self.errno = errno.EINVAL
            return None

    def close(self, h):
        if h <= 2: return 0
        try:
            f = self.__get_file(h)
            if f is not None:
                f.close()
                self.files[h] = None
                return 0
            else:
                return -1
        except IOError as e:
            self.__set_errno(e.errno)
            return -1
        
    def get_errno(self):
        return self.errno
    
    def flen(self, h):
        try:
            f = self.__get_file(h)
            if f is not None:
                curp = f.seek(0, 1)
                l = f.seek(0, 2)
                f.seek(curp, 0)
                return l
            else:
                return -1
        except IOError as e:
            self.__set_errno(e.errno)
            return -1
        
    def get_cmdline(self):
        self.errno = errno.EPERM
        return None
    
    def iserror(self, e):
        return 0 if e == 0 else 1
    
    def istty(self, h):
        try:
            f = self.__get_file(h)
            if f is not None:
                return 1 if f.isatty() else 0 
            else:
                return -1
        except IOError as e:
            self.__set_errno(e.errno)
            return -1
        
    def open(self, name, mode):
        modes = ["r", "rb", "r+", "r+b", "w", "wb", "w+", "w+b", "a", "ab", "a+", "a+b" ]
        if mode >= len(modes):
            self.errno = errno.EINVAL
            return -1
        openmode = modes[mode]
        h = None
        
        if name == ":tt":
            if openmode == "r": # stdin
                return 0
            elif openmode == "w": # stdout
                return 1
            elif openmode == "a": # stderr
                return 2
            else:
                self.errno = errno.EINVAL
                return -1
        else:
            for slot in range(len(self.files)):
                if self.files[slot] is None:
                    h = slot
                    break
            if h is None:
                self.errno = errno.EMFILE
                return -1
    
            try:
                f = open(name, openmode)
                self.files[h] = f
                return h
            except IOError as e:
                self.__set_errno(e.errno)
                return -1
    
    def read(self, h, num):
        try:
            f = self.__get_file(h)
            if f is not None:
                return f.read(num).encode()
            else:
                return None
        except IOError as e:
            self.__set_errno(e.errno)
            return None

    def readc(self):
        try:
            c = sys.stdin.read(1)
            return -1 if len(c) == 0 else ord(c)
        except IOError as e:
            self.__set_errno(e.errno)
            return -1

    def remove(self, name):
        try:
            os.remove(name)
        except OSError as e:
            self.__set_errno(e.errno)
            return self.errno

    def rename(self, oldname, newname):
        try:
            os.rename(oldname, newname)
        except OSError as e:
            self.__set_errno(e.errno)
            return self.errno
        
    def seek(self, h, abspos):
        try:
            f = self.__get_file(h)
            if f is not None:
                return f.seek(abspos, 0)                
            else:
                return -1
        except IOError as e:
            self.__set_errno(e.errno)
            return -1

    def system(self, cmd):
        try:
            return os.system(cmd)
        except OSError as e:
            self.__set_errno(e.errno)
            return self.errno
        
    def time(self):
        return int(time.time())
    
    def tmpnam(self, fid):
        if fid > len(self.tmps):
            self.errno = errno.EINVAL
            return None
        try:
            if self.tmps[fid] is None:
                self.tmps[fid] = os.tempnam()

            return self.tmps[fid]            
        except OSError as e:
            self.__set_errno(e.errno)
            return None
        
    def write(self, h, data):
        try:
            f = self.__get_file(h)
            if f is not None:
                f.write(data.decode())
                return 0
            else:
                return len(data)
        except IOError as e:
            self.__set_errno(e.errno)
            return len(data)
        
    def writec(self, c):
        sys.stdout.write(c)
        
    def write0(self, s):
        sys.stdout.write(s)