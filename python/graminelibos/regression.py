import contextlib
import logging
import os
import pathlib
import resource
import select
import signal
import subprocess
import sys
import time
import unittest

import graminelibos

fspath = getattr(os, 'fspath', str) # pylint: disable=invalid-name

# pylint: disable=subprocess-popen-preexec-fn,subprocess-run-check

HAS_AVX = os.environ.get('AVX') == '1'
HAS_EDMM = os.environ.get('EDMM') == '1'
HAS_SGX = os.environ.get('SGX') == '1'
HAS_TDX = os.environ.get('TDX') == '1'
HAS_VM  = os.environ.get('VM')  == '1'
IS_VM = os.environ.get('IS_VM') == '1'
ON_X86 = os.uname().machine in ['x86_64']
USES_MUSL = os.environ.get('GRAMINE_MUSL') == '1'

def expectedFailureIf(predicate):
    if predicate:
        return unittest.expectedFailure
    return lambda func: func

def set_open_fds_limit(n):
    if n is not None:
        resource.setrlimit(resource.RLIMIT_NOFILE, (n, n))

def run_command(cmd, *, timeout, open_fds_limit=None, can_fail=False, **kwds):
    # pylint: disable=too-many-locals
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          preexec_fn=lambda: set_open_fds_limit(open_fds_limit),
                          start_new_session=True, **kwds) as proc:
        class LoggingSplice:
            def __init__(self, input_pipe, output_pipe):
                self.logged_data = b''
                self.closed = False
                self.at_line_start = True
                self.input_pipe = input_pipe
                self.output_pipe = output_pipe
                self.start_time = time.time()

            def pump_data(self, pending_reads):
                if self.input_pipe in pending_reads:
                    data = self.input_pipe.read(1024)
                    self.logged_data += data

                    if not data:
                        self.closed = True
                        return

                    timestamped = bytearray()
                    for ch in data:
                        if self.at_line_start:
                            timestamped += b'[%.3f] ' % (time.time() - self.start_time)
                            self.at_line_start = False

                        timestamped.append(ch)

                        if ch == 10:
                            self.at_line_start = True

                    self.output_pipe.write(timestamped)
                    self.output_pipe.flush()

        stdout_splice = LoggingSplice(proc.stdout.raw, sys.stdout.buffer)
        stderr_splice = LoggingSplice(proc.stderr.raw, sys.stderr.buffer)

        # returns True if we've used only some of the time and more data can arrive later
        def try_pump(timeout):
            splices = [stdout_splice, stderr_splice]
            poll_reads = [splice.input_pipe for splice in splices if not splice.closed]
            if not poll_reads:
                # both pipes are closed. select([]) would block, so exit now
                return False

            pending_reads, _, _ = select.select(poll_reads, [], [], timeout)
            if not pending_reads:
                # this can only happen if we've timed out and both pipes are empty
                return False

            for splice in splices:
                splice.pump_data(pending_reads)
            return True

        # We implement this manually so that the captured output is also printed on our
        # stdout/stderr as it is being generated.
        time_end = time.time() + timeout
        while True:
            time_remaining = time_end - time.time()
            if time_remaining < 0:
                # if we've timed out, use a timeout of 0 to copy all leftover data
                time_remaining = 0

            if not try_pump(time_remaining):
                break

        # Once we're here, we've either timed out, or both pipes got closed and the process is about
        # to exit
        time_remaining = time_end - time.time()
        if time_remaining > 0:
            proc.wait(time_remaining)

        timed_out = time_end < time.time()

        proc.poll()
        main_returncode = proc.returncode

        # Kill the whole process group: even if we did not time out, there might be some processes
        # remaining

        try:
            # after `setsid`, pgid should be the same as pid
            if proc.pid != os.getpgid(proc.pid):
                logging.warning(
                    'run_command: main process changed pgid, this might indicate an error and '
                    'prevent all processes from being cleaned up'
                )
        except ProcessLookupError:
            pass

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        # Copy any output generated while we were busy killing the processes
        while try_pump(0):
            pass

        raw_stdout = stdout_splice.logged_data
        raw_stderr = stderr_splice.logged_data

        stdout = raw_stdout.decode(errors='surrogateescape')
        stderr = raw_stderr.decode(errors='surrogateescape')

        if timed_out:
            if main_returncode is not None:
                # XXX: Don't fail the test as long the main process exited (i.e. if it left dangling
                # child processes). This can happen due to a known issue with Gramine failing to
                # deliver a signal for an arbitrary amount of time. See the comment in
                # `libos_internal.h:handle_signal` for details.
                #
                # This happens occasionally when running LTP tests (e.g. `sendfile04`,
                # `fdatasync01`, `recvfrom01`, `sendto01`) that send SIGKILL to child processes.
                logging.warning(
                    'run_command: Command %s timed out, but the main process exited. This might be '
                    'due to a known issue with Gramine failing to deliver a signal. Continuing.',
                    cmd)
            else:
                raise AssertionError('Command {} timed out after {} s'.format(cmd, timeout))

        assert main_returncode is not None

        if main_returncode != 0 and not can_fail:
            raise subprocess.CalledProcessError(proc.returncode, cmd, raw_stdout, raw_stderr)

        return main_returncode, stdout, stderr
    
def cleanup_vm(gramine_vm_id):
    sock = f"/tmp/gramine_vhostfs_{gramine_vm_id}"
    pidf = f"{sock}.pid"

    in_use = False
    try:
        r = subprocess.run(["lsof", "-t", "--", pidf],
                           capture_output=True, text=True, check=False)
        in_use = (r.returncode == 0 and r.stdout.strip() != "")
    except FileNotFoundError:
        in_use = False

    if in_use and os.path.exists(pidf):
        try:
            with open(pidf, "r", encoding="utf-8") as f:
                pid_txt = f.read().strip()
            pid = int("".join(ch for ch in pid_txt if ch.isdigit()))
        except Exception:
            pid = None

        if pid is not None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    break
                deadline = time.time() + (1.0 if sig == signal.SIGTERM else 0.5)
                while time.time() < deadline:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        deadline = 0  # dead
                        break
                    time.sleep(0.05)

    for path in (pidf, sock):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

def sq(s: str) -> str:
    return "'" + s + "'"

class RegressionTestCase(unittest.TestCase):
    # TDX takes extra long time
    if HAS_TDX:
        DEFAULT_TIMEOUT = 150
    elif HAS_VM:
        DEFAULT_TIMEOUT = 120
    elif HAS_SGX:
        DEFAULT_TIMEOUT = 20
    else:
        DEFAULT_TIMEOUT = 10

    def get_env(self, name):
        try:
            return os.environ[name]
        except KeyError:
            self.fail('environment variable {} not set'.format(name))

    @property
    def pal_path(self):
        # pylint: disable=protected-access
        base = pathlib.Path(graminelibos._CONFIG_PKGLIBDIR)
        if HAS_TDX:
            sub = 'tdx'
        elif HAS_VM:
            sub = 'vm'
        elif HAS_SGX:
            sub = 'sgx'
        else:
            sub = 'direct'
        return base / sub

    @property
    def libpal_path(self):
        return self.pal_path / 'libpal.so'

    @property
    def loader_path(self):
        return self.pal_path / 'loader'
    
    @property
    def libpal_vm_path(self):
        return (self.pal_path / 'tdshim-pal') if HAS_TDX else (self.pal_path / 'pal')
    
    @property
    def bios_path(self):
        return self.pal_path / 'bios'

    def has_debug(self):
        p = subprocess.run(['objdump', '-x', fspath(self.libpal_path)],
            check=True, stdout=subprocess.PIPE)
        dump = p.stdout.decode()
        return '.debug_info' in dump

    def run_gdb(self, args, gdb_script, **kwds):
        if HAS_TDX or HAS_VM:
            return self.run_vm(args, prefix=None, run_gdb=True, **kwds)
        prefix = ['gdb', '-q']
        env = os.environ.copy()
        if HAS_SGX:
            prefix += ['-x', fspath(self.pal_path / 'gdb_integration/gramine_sgx_gdb.py')]
            sgx_gdb = fspath(self.pal_path / 'gdb_integration/sgx_gdb.so')
            env['LD_PRELOAD'] = sgx_gdb + ':' + env.get('LD_PRELOAD', '')
        else:
            prefix += ['-x', fspath(self.pal_path / 'gdb_integration/gramine_linux_gdb.py')]

        # Override TTY, as apparently os.setpgrp() confuses GDB and causes it to hang.
        prefix += ['-x', gdb_script, '-batch', '-tty=/dev/null']
        prefix += ['--args']

        return self.run_binary(args, prefix=prefix, env=env, **kwds)

    # mirror gramine-vm.in
    def run_vm(self, args, *, timeout=None, prefix=None, run_gdb=False, env=None, **kwds):
        timeout = (max(self.DEFAULT_TIMEOUT, timeout) if timeout is not None
                   else self.DEFAULT_TIMEOUT)

        application, rest = args[0], list(args[1:])

        qemu_gdb = ('-gdb tcp::9000 -S' if run_gdb else '')

        def pick_mem():
            import re

            manifest_base = os.environ.get('GRAMINE_MANIFEST', f'{application}.manifest')
            manifests = {
                'tdx': manifest_base + '.tdx',
                'sgx': manifest_base + '.sgx',
            }

            size_str = ''
            for type, file in manifests.items():
                try:
                    with open(file, 'rb') as f:
                        manifest_data = f.read()
                    manifest = graminelibos.Manifest.loads(manifest_data.decode('utf-8'))
                    size_str = manifest[type]['enclave_size']
                    break
                except Exception:
                    continue
            else:
                return (os.environ.get('GRAMINE_RAM_SIZE') or '8G')

            unit = 1
            if size_str.endswith('G'):
                unit = 1024 * 1024 * 1024
            elif size_str.endswith('M'):
                unit = 1024 * 1024
            elif size_str.endswith('K'):
                unit = 1024

            try:
                size = int(re.search(r'\d+', size_str).group())
                return size_str if unit * size > 1024 * 1024 * 1024 else '1G'
            except Exception:
                return (os.environ.get('GRAMINE_RAM_SIZE') or '8G')

        mem_size = pick_mem()
        cpu_num = (os.environ.get('QEMU_CPU_NUM')
                   or os.environ.get('GRAMINE_CPU_NUM')
                   or '1')

        qemu = 'qemu'

        qemu_vm   = (f'-cpu host,host-phys-bits,-kvm-steal-time,pmu=off,+tsc-deadline,+invtsc '
                     f'-m {mem_size} -smp {cpu_num}')
        qemu_opts = (f'-enable-kvm -vga none -display none -no-reboot -monitor none '
                     f'-object memory-backend-memfd,id=mem,size={mem_size},share=on '
                     f'-M memory-backend=mem,hpet=off')

        if not HAS_TDX:
            qemu_machine = '-M q35,kernel_irqchip=split'
            qemu_binaries = (
                f'-kernel {sq(fspath(self.libpal_vm_path))} -device loader,file={sq(fspath(self.bios_path))}'
            )
        else:
            qemu_machine = (
                '-M q35,kernel_irqchip=split,confidential-guest-support=tdx '
                '-object \'{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type": "vsock", "cid":"2","port":"4050"}}\''
            )
            qemu_binaries = f'-bios {sq(fspath(self.libpal_vm_path))}'

        def determine_vm_id():
            import psutil
            import re

            # Identify the qemu processes
            qemu_processes = []
            try:
                for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                    if 'qemu' in process.info['name']:
                        qemu_processes.append(process)
            except Exception:
                raise SystemExit('Exception while iterating over system processes.')

            # Identify the occupied guest-cids
            used_cids = set()
            for process in qemu_processes:
                pid = process.info['pid']  # retained from original (even if unused)
                cmdline = ' '.join(process.info['cmdline'])
                match = re.search(r'guest-cid=(\d+)', cmdline)
                guest_cid = int(match.group(1)) if match else None
                if guest_cid is not None:
                    used_cids.add(guest_cid)

            # Identify the next available Gramine VM ID based on the uniquely assigned vsock guest-cid.
            cid = 10
            while cid in used_cids:
                cid += 1

            # Check that the guest-cid is in a valid range
            if cid > 2 and cid < 0xffffffff:
                return cid
            else:
                raise SystemExit('Invalid chosen CID value: ' + str(cid) + '. It must be > 2 and < 0xffffffff.')

        try:
            gramine_vm_id = determine_vm_id()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
            msg  = '' if (e.code is None or isinstance(e.code, int)) else str(e.code)
            logging.error("Error: determining Gramine-VM ID failed with status: %s", code)
            if msg:
                logging.error("Error message: %s", msg)
            raise

        qemu_virtio_console = ('-device virtio-serial,iommu_platform=off,romfile= '
                               '-chardev stdio,id=virtioconsole0 '
                               '-device virtconsole,chardev=virtioconsole0')
        qemu_virtio_fs      = (f'-chardev socket,path=/tmp/gramine_vhostfs_{gramine_vm_id},id=vhostfs '
                               f'-device vhost-user-fs-pci,iommu_platform=off,queue-size=1024,chardev=vhostfs,tag=graminefs')
        qemu_virtio_vsock   = (f'-device vhost-vsock-pci,iommu_platform=off,guest-cid={gramine_vm_id},id=vsockdev')

        escaped_app = application.replace(',', ',,')
        gramine_args = f'-gramine-args init "{escaped_app}"'
        if rest:
            gramine_args += ' ' + ' '.join(rest)
        gramine_args += ' -gramine-args-end'

        def get_envs():
            env_str = ''
            for name, value in os.environ.items():
                env_str += ('\"{0}={1}\" '.format(name, value).replace(',', ',,'))
            return env_str

        gramine_envs = '-gramine-envs ' + get_envs() + ' -gramine-envs-end'

        if prefix is None:
            prefix = []

        envs = []

        parts = [
            'exec',
            'env',
            *envs,
            *prefix,
            qemu,
            qemu_gdb,
            qemu_vm,
            qemu_opts,
            qemu_machine,
            qemu_virtio_console,
            qemu_virtio_fs,
            qemu_virtio_vsock,
            qemu_binaries,
            f'-fw_cfg name=opt/gramine/pwd,string={sq(os.getcwd())}',
            f'-fw_cfg name=opt/gramine/args,string={sq(gramine_args)}',
            f'-fw_cfg name=opt/gramine/envs,string={sq(gramine_envs)}',
            f'-fw_cfg name=opt/gramine/unixtime_s,string={str(int(time.time()))}',
        ]
        parts = [p for p in parts if p]

        sock = f'/tmp/gramine_vhostfs_{gramine_vm_id}'
        pidf = f'{sock}.pid'

        shell_line = ' '.join([
            # lsof check like the script
            f'if lsof {pidf} >/dev/null 2>&1; then '
            f'echo "Error: {pidf} is already in use."; exit 2; fi;',
            # start virtiofsd in background
            'virtiofsd',
            f'--socket-path {sock}',
            '--shared-dir /',
            '--log-level error',
            '--sandbox none',
            '--no-announce-submounts',
            '&',
            # wait until socket appears
            f'while [ ! -e {sock} ]; do sleep 0.1; done;',
            # run QEMU
            ' '.join(parts),
        ])

        cmd = ['bash', '-c', shell_line]
        try:
            _returncode, stdout, stderr = run_command(cmd, timeout=timeout, **kwds)
        finally:
            cleanup_vm(gramine_vm_id)
        return stdout, stderr

    def run_binary(self, args, *, timeout=None, prefix=None, env=None, **kwds):
        # VM/TDX path (QEMU)
        if HAS_VM or HAS_TDX:
            return self.run_vm(args, timeout=timeout, prefix=prefix, run_gdb=False, env=env, **kwds)

        timeout = (max(self.DEFAULT_TIMEOUT, timeout) if timeout is not None
            else self.DEFAULT_TIMEOUT)

        if not self.loader_path.exists():
            self.fail('loader ({}) not found'.format(self.loader_path))
        if not self.libpal_path.exists():
            self.fail('libpal ({}) not found'.format(self.libpal_path))

        if prefix is None:
            prefix = []

        cmd = [*prefix, fspath(self.loader_path), fspath(self.libpal_path), 'init', *args]
        _returncode, stdout, stderr = run_command(cmd, timeout=timeout, **kwds)
        return stdout, stderr

    @classmethod
    def run_native_binary(cls, args, timeout=None, libpath=None, **kwds):
        timeout = (max(cls.DEFAULT_TIMEOUT, timeout) if timeout is not None
            else cls.DEFAULT_TIMEOUT)

        my_env = os.environ.copy()
        if not libpath is None:
            my_env["LD_LIBRARY_PATH"] = libpath

        _returncode, stdout, stderr = run_command(args, timeout=timeout, env=my_env, **kwds)
        return stdout, stderr

    @contextlib.contextmanager
    def expect_returncode(self, returncode):
        if returncode == 0:
            raise ValueError('expected returncode should be nonzero')
        try:
            yield
            self.fail('did not fail (expected {})'.format(returncode))
        except subprocess.CalledProcessError as e:
            self.assertEqual(e.returncode, returncode,
                'failed with returncode {} (expected {})'.format(
                    e.returncode, returncode))
