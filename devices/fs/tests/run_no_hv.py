#!/usr/bin/env python

'''
Run fsserver and fsclient without hypervisor.

xchan must be compiled with -DNOHV (recompile the whole project with the NOHV
environment variable set to 1).

XXX: shared folders aren't umounted.
'''

import ctypes
import os
import re
import signal
import subprocess
import sys
import time
import tempfile

INSTALL_PREFIX = '/usr/local/cappsule/'
FSSERVER = os.path.join(INSTALL_PREFIX, 'usr/bin/fsserver')
FSCLIENT = os.path.join(INSTALL_PREFIX, 'usr/share/cappsule/ramfs/fsclient')
MOUNT_SO = os.path.join(INSTALL_PREFIX, 'usr/share/cappsule/ramfs/mount_override.so')
CAPSULE_ID = '1'
POLICY_ID = '5'

# CAPSULE_FS is hardcoded in mount_override.c. If the mountpoint differs, setuid
# binaries lose their setuid bit.
MOUNTPOINT = '/run/cappsule/fs'


class NoHV:
    def __init__(self):
        self.mountpoint = ''
        self.client = None
        self.server = None
        self.libc = ctypes.cdll.LoadLibrary('libc.so.6')
        self.virtual_dirs = []
        signal.signal(signal.SIGTERM, self.kill_handler)

    def kill_handler(self):
        self.exit()
        sys.exit(0)

    def _set_pdeath(self, sig):
        PR_SET_PDEATHSIG = 1
        self.libc.prctl(PR_SET_PDEATHSIG, sig)

    def _set_pdeath_sigkill(self):
        self._set_pdeath(signal.SIGKILL)

    def _set_pdeath_sigterm(self):
        self._set_pdeath(signal.SIGTERM)

    def mount_virtual_dirs(self):
        allowed = [ 'sysfs', 'proc', 'devtmpfs', 'tmpfs', 'cgroup' ]
        with open('/proc/mounts') as fp:
            mounts = fp.readlines()

        # mount a new tmpfs in chroot
        mounts.append('tmpfs /tmp tmpfs rw')

        for l in mounts:
            origin, fstype = l.split(' ')[1:3]
            if fstype not in allowed:
                continue

            dest = re.sub('^/+', '', origin)
            dest = os.path.join(self.mountpoint, dest)
            args = [ 'mount', '-o', 'bind', origin, dest ]
            ret = subprocess.call(args)
            if ret != 0:
                self.exit()
                sys.exit(1)

            self.virtual_dirs.append(dest)

    def umount_virtual_dirs(self):
        for d in self.virtual_dirs:
            args = [ 'umount', d ]
            devnull = open('/dev/null', 'w')
            subprocess.call(args, stderr=devnull)
            devnull.close()

    def run_server(self):
        env = dict(os.environ, POLICY_ID=POLICY_ID, CAPSULE_ID=CAPSULE_ID)
        args = [
            FSSERVER,
            '--no-monitor', os.path.join(INSTALL_PREFIX, 'etc/cappsule/policies/'),
        ]

        out = open('/tmp/fsserver.log', 'w')
        self.server = subprocess.Popen(args, env=env, preexec_fn=self._set_pdeath_sigterm, stdout=out, stderr=out)
        out.close()

        time.sleep(1)
        if self.server.poll():
            print '[-] fsserver failed'
            self.exit()
            sys.exit(1)

    def run_client(self):
        if not os.path.exists(MOUNTPOINT):
            os.makedirs(MOUNTPOINT)
        self.mountpoint = MOUNTPOINT
        print '[*] mountpoint:', self.mountpoint

        env = dict(os.environ, LD_PRELOAD=MOUNT_SO, POLICY_ID=POLICY_ID, CAPSULE_ID=CAPSULE_ID)
        args = [
            FSCLIENT,
            '--no-hv',
            '-s',
            '-f',
            '-o', 'allow_other',
            '-o', 'default_permissions',
            self.mountpoint
        ]

        out = open('/tmp/fsclient.log', 'w')
        self.client = subprocess.Popen(args, env=env, preexec_fn=self._set_pdeath_sigkill, stdout=out, stderr=out)
        out.close()

        time.sleep(1)
        if self.client.poll():
            print '[-] fsclient failed'
            self.exit()
            sys.exit(1)

    def exit(self):
        '''Try to cleanup everything'''

        print '[*] exiting'

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

        self.umount_virtual_dirs()

        if self.mountpoint:
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

    n = NoHV()
    n.run_server()
    n.run_client()
    n.mount_virtual_dirs()

    print 'You can now chroot to %s' % n.mountpoint

    try:
        signal.pause()
    except KeyboardInterrupt:
        n.exit()
