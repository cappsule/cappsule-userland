#!/usr/bin/env python

import ctypes
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time


INSTALL_PREFIX = '/usr/local/cappsule/'
FSSERVER = os.path.join(INSTALL_PREFIX, 'usr/bin/fsserver')
FSCLIENT = os.path.join(INSTALL_PREFIX, 'usr/share/cappsule/ramfs/fsclient')
MOUNT_SO = os.path.join(INSTALL_PREFIX, 'usr/share/cappsule/ramfs/mount_override.so')
TEST_DIR = '/tmp/cappsule-testfs/'
CAPSULE_ID = '1'
POLICY_ID = '5'


def prepare_tests():
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)

    for d in [ 'rw', 'r', 'w' ]:
        path = os.path.join(TEST_DIR, d)
        os.makedirs(path, 0755)
        os.chown(path, 1000, 1000)	# XXX: owner shouldn't be hardcoded

    os.system('ls -l ' + TEST_DIR)


def run_tests():
    filename = os.path.join(TEST_DIR, 'rw/blah')
    data = ''.join([ chr(random.randint(0, 255)) for i in range(0, random.randint(0, 0x100000)) ])

    with open(filename, 'w') as fp:
        fp.write(data)

    with open(filename, 'r') as fp:
        data2 = fp.read()
    assert data2 == data

    symlink = filename + '_'
    os.symlink(filename, symlink)

    with open(symlink, 'r') as fp:
        data2 = fp.read()
    assert data2 == data

    os.unlink(filename)
    os.unlink(symlink)


class Tests:
    def __init__(self):
        self.mountpoint = ''
        self.client = None
        self.server = None
        self.libc = ctypes.cdll.LoadLibrary('libc.so.6')

    def _set_pdeath(self, sig):
        PR_SET_PDEATHSIG = 1
        self.libc.prctl(PR_SET_PDEATHSIG, sig)

    def _set_pdeath_sigkill(self):
        self._set_pdeath(signal.SIGKILL)

    def _set_pdeath_sigterm(self):
        self._set_pdeath(signal.SIGTERM)

    def _mount_proc(self):
        '''
        Mount proc fs in mountpoint directory. It isn't necessary to make /proc/
        directory since it already exists in host.
        '''

        proc = os.path.join(self.mountpoint, 'proc/')
        MS_MGC_VAL = 0xc0ed0000
        assert self.libc.mount('proc', proc, 'proc', MS_MGC_VAL, 0) == 0

    def _umount_proc(self):
        proc = os.path.join(self.mountpoint, 'proc/')
        if os.path.exists(proc):
            self.libc.umount(proc)

    def run_server(self):
        env = dict(os.environ, POLICY_ID=POLICY_ID, CAPSULE_ID=CAPSULE_ID)
        args = [ FSSERVER, '--no-monitor', os.path.join(sys.path[0], 'policies/') ]
        self.server = subprocess.Popen(args, preexec_fn=self._set_pdeath_sigterm)

        time.sleep(1)
        if self.server.poll():
            print '[-] fsserver failed'
            self.exit()
            sys.exit(1)

    def run_client(self):
        self.mountpoint = tempfile.mkdtemp()
        print '[*] mountpoint:', self.mountpoint

        env = dict(os.environ, LD_PRELOAD=MOUNT_SO, POLICY_ID=POLICY_ID, CAPSULE_ID=CAPSULE_ID)
        args = [ FSCLIENT,
                 '--no-hv',
                 '-s',
                 '-f',
                 '-o', 'allow_other',
                 '-o', 'default_permissions',
                 self.mountpoint ]
        self.client = subprocess.Popen(args, env=env, preexec_fn=self._set_pdeath_sigkill)

        time.sleep(1)
        if self.client.poll():
            print '[-] fsclient failed'
            self.exit()
            sys.exit(1)

        self._mount_proc()

    def run_tests(self):
        '''Run tests through FUSE.'''

        prepare_tests()

        pid = os.fork()
        if pid == 0:
            self._set_pdeath_sigterm()
            os.chroot(self.mountpoint)
            os.chdir('/')
            run_tests()
            sys.exit(0)

        os.waitpid(pid, 0)
        print '[*] tests done'
        shutil.rmtree(TEST_DIR)

    def exit(self):
        '''Try to cleanup everything'''

        if self.client:
            if not self.client.poll():
                self.client.terminate()
            self.client.wait()
            self.client = None

        if self.server:
            if not self.server.poll():
                self.server.terminate()
            self.server.wait()
            self.server = None

        if self.mountpoint:
            self._umount_proc()
            # needed if client wasn't properly killed
            with open('/proc/mounts') as fp:
                mounts = fp.read()
            if self.mountpoint in mounts:
                args = [ 'fusermount', '-u', self.mountpoint ]
                subprocess.call(args)

            os.rmdir(self.mountpoint)
            self.mountpoint = ''


if __name__ == '__main__':
    if os.getuid() != 0:
        print '[-] not root'
        sys.exit(0)

    t = Tests()
    t.run_server()
    t.run_client()
    t.run_tests()
    t.exit()
