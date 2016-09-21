#!/usr/bin/env python

'''
Run netserver and netclient without hypervisor.
'''

import ctypes
import os
import signal
import subprocess
import sys
import time

INSTALL_PREFIX = '/usr/local/cappsule/'
NETSERVER = os.path.join(INSTALL_PREFIX, 'usr/bin/netserver')
NETCLIENT = os.path.join(INSTALL_PREFIX, 'usr/share/cappsule/ramfs/netclient')
CAPSULE_ID = '1'
POLICY_ID = '5'


class NoHV:
    def __init__(self):
        self.ip_forward = open('/proc/sys/net/ipv4/ip_forward').read()
        self.client = None
        self.server = None
        self.libc = ctypes.cdll.LoadLibrary('libc.so.6')
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

    def _set_ip_forward(self, enable):
        if self.ip_forward != '1\n':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as fp:
                fp.write('1\n')

    def run_server(self):
        env = dict(os.environ, POLICY_ID=POLICY_ID, CAPSULE_ID=CAPSULE_ID)
        args = [
            NETSERVER,
            '--no-monitor', os.path.join(INSTALL_PREFIX, 'etc/cappsule/policies/'),
        ]

        self._set_ip_forward(True)
        subprocess.call([ 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-j', 'MASQUERADE' ])

        out = open('/tmp/netserver.log', 'w')
        self.server = subprocess.Popen(args, env=env, preexec_fn=self._set_pdeath_sigterm, stdout=out, stderr=out)
        out.close()

        time.sleep(0.5)
        if self.server.poll():
            print '[-] netserver failed'
            self.exit()
            sys.exit(1)

    def run_client(self):
        env = dict(os.environ, POLICY_ID=POLICY_ID, CAPSULE_ID=CAPSULE_ID)
        args = [ NETCLIENT, '--no-hv' ]

        out = open('/tmp/netclient.log', 'w')
        self.client = subprocess.Popen(args, env=env, preexec_fn=self._set_pdeath_sigkill, stdout=out, stderr=out)
        out.close()

        time.sleep(0.5)
        if self.client.poll():
            print '[-] netclient failed'
            self.exit()
            sys.exit(1)

    def exit(self):
        '''Try to cleanup everything'''

        print '[*] exiting'

        if self.client:
            if not self.client.poll():
                try:
                    self.client.terminate()
                except:
                    pass
            self.client.wait()
            self.client = None

        if self.server:
            if not self.server.poll():
                try:
                    self.server.terminate()
                except:
                    pass
            self.server.wait()
            self.server = None

        subprocess.call([ 'iptables', '-t', 'nat', '-D', 'POSTROUTING', '-j', 'MASQUERADE' ])
        self._set_ip_forward(self.ip_forward)


def join_net_ns(pid):
    CLONE_NEWNET = 0x40000000
    libc = ctypes.cdll.LoadLibrary('libc.so.6')

    with open('/proc/%d/ns/net' % pid) as fp:
        ret = libc.setns(fp.fileno(), CLONE_NEWNET)

    if ret != 0:
        print '[-] setns failed (error: %s)' % os.strerror(ctypes.get_errno())
        sys.exit(1)


def usage():
    print 'Usage: %s [options ...] -- <program> [args ...]' % sys.argv[0]
    sys.exit(0)


if __name__ == '__main__':
    if os.getuid() != 0:
        print '[-] not root'
        sys.exit(0)

    try:
        i = sys.argv.index('--')
    except ValueError:
        usage()

    if i == len(sys.argv) - 1:
        usage()
    cmd = sys.argv[i+1:]

    n = NoHV()
    n.run_server()
    n.run_client()

    pid = os.fork()
    if pid == 0:
        # execute command in netclient network namespace
        print '[*] executing %s' % ' '.join(cmd)
        join_net_ns(n.client.pid)
        os.execlp(cmd[0], *cmd)
        sys.exit(0)

    os.waitpid(pid, 0)
    print '[*] done'

    n.exit()
