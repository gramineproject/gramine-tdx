import ast
import collections
import mmap
import pathlib
import random
import re
import shutil
import string
import subprocess
import unittest

from graminelibos.regression import (
    HAS_EDMM,
    HAS_SGX,
    HAS_TDX,
    HAS_VM,
    ON_X86,
    RegressionTestCase,
)

# Need to capture the output from VM/TDX in stdout as all guest console output will be redirected by QEMU to host's stdout

class TC_00_Basic(RegressionTestCase):
    def test_001_path_normalization(self):
        stdout, stderr = self.run_binary(['normalize_path'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        self.assertIn("Success!\n", output)

    def test_002_avl_tree(self):
        _, _ = self.run_binary(['avl_tree_test'])

    def test_003_printf(self):
        stdout, stderr = self.run_binary(['printf_test'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn("TEST OK", output)

    def test_004_strtoll(self):
        stdout, stderr = self.run_binary(['strtoll_test'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn("TEST OK", output)


class TC_00_BasicSet2(RegressionTestCase):
    @unittest.skipUnless(ON_X86, "x86-specific")
    def test_Exception2(self):
        stdout, stderr = self.run_binary(['Exception2'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('Enter Main Thread', output)
        self.assertIn('failure in the handler: 0x', output)
        self.assertNotIn('Leave Main Thread', output)

    def test_File2(self):
        stdout, stderr = self.run_binary(['File2'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('Enter Main Thread', output)
        self.assertIn('Hello World', output)
        self.assertIn('Leave Main Thread', output)

    def test_HelloWorld(self):
        stdout, _ = self.run_binary(['HelloWorld'])
        self.assertIn('Hello World', stdout)

    def test_Pie(self):
        stdout, stderr = self.run_binary(['Pie'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('start program: Pie', output)
        self.assertIn('Hello World', stdout)

    @unittest.skipIf(HAS_SGX, "Pipes must be created in two parallel threads under SGX")
    def test_Process4(self):
        stdout, stderr = self.run_binary(['Process4'], timeout=5)
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertRegex(output, r'In process: .*Process4')
        self.assertIn('wall time = ', output)
        for i in range(100):
            self.assertIn('In process: Process4 %d ' % i, output)

    @unittest.skipUnless(ON_X86, "x86-specific")
    def test_Segment(self):
        stdout, stderr = self.run_binary(['Segment'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('Test OK', output)


class TC_01_Bootstrap(RegressionTestCase):
    def test_100_basic_boostrapping(self):
        stdout, stderr = self.run_binary(['Bootstrap'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Basic Bootstrapping
        self.assertIn('User Program Started', output)

        # One Argument Given
        self.assertIn('# of Arguments: 1', output)
        self.assertRegex(output, r'argv\[0\] = .*Bootstrap')

        # Control Block: Debug Stream (Inline)
        self.assertIn('Written to Debug Stream', output)

        # Control Block: Allocation Alignment
        self.assertIn('Allocation Alignment: {}'.format(mmap.ALLOCATIONGRANULARITY), output)

    def test_101_basic_boostrapping_five_arguments(self):
        stdout, stderr = self.run_binary(['Bootstrap', 'a', 'b', 'c', 'd'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Five Arguments Given
        self.assertIn('# of Arguments: 5', output)
        self.assertIn('argv[1] = a', output)
        self.assertIn('argv[2] = b', output)
        self.assertIn('argv[3] = c', output)
        self.assertIn('argv[4] = d', output)

    def test_102_cpuinfo(self):
        with open('/proc/cpuinfo') as file_:
            cpuinfo = file_.read().strip().split('\n\n')[-1]
        cpuinfo = dict(map(str.strip, line.split(':'))
            for line in cpuinfo.split('\n'))

        stdout, stderr = self.run_binary(['Bootstrap'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        self.assertIn('CPU num: {}'.format(int(cpuinfo['processor']) + 1),
            output)
        self.assertIn('CPU vendor: {[vendor_id]}'.format(cpuinfo), output)
        self.assertIn('CPU brand: {[model name]}'.format(cpuinfo), output)
        self.assertIn('CPU family: {[cpu family]}'.format(cpuinfo), output)
        self.assertIn('CPU model: {[model]}'.format(cpuinfo), output)
        self.assertIn('CPU stepping: {[stepping]}'.format(cpuinfo), output)

    def test_103_dotdot(self):
        stdout, stderr = self.run_binary(['..Bootstrap'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('User Program Started', output)

    @unittest.skipUnless(HAS_SGX, 'this test requires SGX')
    def test_120_8gb_enclave(self):
        _, stderr = self.run_binary(['Bootstrap6'], timeout=360)
        self.assertIn('Memory Address Range OK', stderr)

    def test_130_large_number_of_items_in_manifest(self):
        stdout, stderr = self.run_binary(['Bootstrap7'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('key1=na', output)
        self.assertIn('key1000=batman', output)

    def test_140_missing_executable_and_manifest(self):
        if HAS_TDX or HAS_VM:
            stdout, _ = self.run_binary(['fakenews'])
            # Guest reports the error and non-zero code on stdout; QEMU exits 0.
            self.assertIn('Reading manifest failed', stdout)
            m = re.search(r'VM exited with code (\d+)', stdout)
            self.assertIsNotNone(m, 'did not find guest exit code in output')
            self.assertNotEqual(int(m.group(1)), 0)
        else:
            try:
                _, stderr = self.run_binary(['fakenews'])
                self.fail('expected non-zero returncode, stderr: {!r}'.format(stderr))
            except subprocess.CalledProcessError:
                pass

class TC_02_Symbols(RegressionTestCase):
    ALL_SYMBOLS = [
        'PalVirtualMemoryAlloc',
        'PalVirtualMemoryFree',
        'PalVirtualMemoryProtect',
        'PalSetMemoryBookkeepingUpcalls',
        'PalProcessCreate',
        'PalProcessExit',
        'PalStreamOpen',
        'PalStreamWaitForClient',
        'PalStreamRead',
        'PalStreamWrite',
        'PalStreamDelete',
        'PalStreamMap',
        'PalStreamSetLength',
        'PalStreamFlush',
        'PalSendHandle',
        'PalReceiveHandle',
        'PalStreamAttributesQuery',
        'PalStreamAttributesQueryByHandle',
        'PalStreamAttributesSetByHandle',
        'PalStreamChangeName',
        'PalThreadCreate',
        'PalThreadYieldExecution',
        'PalThreadExit',
        'PalThreadResume',
        'PalSetExceptionHandler',
        'PalEventCreate',
        'PalEventSet',
        'PalEventClear',
        'PalEventWait',
        'PalStreamsWaitEvents',
        'PalObjectDestroy',
        'PalSystemTimeQuery',
        'PalRandomBitsRead',
    ]
    if ON_X86:
        ALL_SYMBOLS.append('PalSegmentBaseGet')
        ALL_SYMBOLS.append('PalSegmentBaseSet')

    def test_000_symbols(self):
        stdout, stderr = self.run_binary(['Symbols'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        prefix = 'symbol: '
        found_symbols = dict(line[len(prefix):].split(' = ')
            for line in output.strip().split('\n') if line.startswith(prefix))
        self.assertCountEqual(found_symbols, self.ALL_SYMBOLS)
        for k, value in found_symbols.items():
            value = ast.literal_eval(value)
            self.assertNotEqual(value, 0, 'symbol {} has value 0'.format(k))

class TC_10_Exception(RegressionTestCase):
    def is_altstack_different_from_main_stack(self, output):
        mainstack = 0
        altstack = 0
        for line in output.splitlines():
            if line.startswith('Stack in main:'):
                mainstack = int(line.split(':')[1], 0)
            elif line.startswith('Stack in handler:'):
                altstack = int(line.split(':')[1], 0)

        # handler stack cannot be "close" to the main stack
        if abs(mainstack - altstack) < 8192:
            return False
        return True

    @unittest.skipUnless(ON_X86, "x86-specific")
    def test_000_exception(self):
        try:
            _, stderr = self.run_binary(['Exception'])
            if HAS_SGX and not HAS_EDMM:
                self.fail('expected to return nonzero')
        except subprocess.CalledProcessError as e:
            if HAS_SGX and not HAS_EDMM:
                self.assertNotEqual(e.returncode, 0)
                stderr = e.stderr.decode()
            else:
                self.fail('expected to return zero')

        self.assertTrue(self.is_altstack_different_from_main_stack(stderr))

        # Exception Handling (Div-by-Zero)
        self.assertIn('Arithmetic Exception Handler 1', stderr)
        self.assertIn('Arithmetic Exception Handler 2', stderr)

        # Exception Handling (Red zone)
        self.assertIn('Arithmetic Exception Handler 3', stderr)
        self.assertIn('Red zone test ok.', stderr)

        if not HAS_SGX or HAS_EDMM:
            # Exception Handling (Memory Fault)
            self.assertIn('Memory Fault Exception Handler', stderr)
            self.assertNotIn('Wrong faulting address', stderr)

class TC_20_SingleProcess(RegressionTestCase):
    def test_000_exit_code(self):
        if HAS_TDX or HAS_VM:
            stdout, _ = self.run_binary(['Exit'])
            m = re.search(r'VM exited with code (\d+)', stdout)
            self.assertIsNotNone(m, 'failed to parse VM exit code from output')
            self.assertEqual(int(m.group(1)), 112)
        else:
            with self.expect_returncode(112):
                self.run_binary(['Exit'])

    def test_100_file(self):
        try:
            pathlib.Path('file_nonexist.tmp').unlink()
        except FileNotFoundError:
            pass
        pathlib.Path('file_delete.tmp').touch()

        with open('File.manifest', 'rb') as file_:
            file_exist = file_.read()

        stdout, stderr = self.run_binary(['File'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Basic File Opening
        self.assertIn('File Open Test 1 OK', output)
        self.assertIn('File Open Test 2 OK', output)
        self.assertIn('File Open Test 3 OK', output)

        # Basic File Creation
        self.assertIn('File Creation Test 1 OK', output)
        self.assertIn('File Creation Test 2 OK', output)
        self.assertIn('File Creation Test 3 OK', output)

        # File Reading
        self.assertIn('Read Test 1 (0th - 40th): {}'.format(
            file_exist[0:40].hex()), output)
        self.assertIn('Read Test 2 (0th - 40th): {}'.format(
            file_exist[0:40].hex()), output)
        self.assertIn('Read Test 3 (200th - 240th): {}'.format(
            file_exist[200:240].hex()), output)

        # File Writing
        with open('file_nonexist.tmp', 'rb') as file_:
            file_nonexist = file_.read()

        self.assertEqual(file_exist[0:40], file_nonexist[200:240])
        self.assertEqual(file_exist[200:240], file_nonexist[0:40])

        # File Attribute Query
        self.assertIn('Query: type = ', output)
        self.assertIn(', size = {}'.format(len(file_exist)), output)

        # File Attribute Query by Handle
        self.assertIn('Query by Handle: type = ', output)
        self.assertIn(', size = {}'.format(len(file_exist)), output)

        # File Mapping
        self.assertIn(
            'Map Test 1 (0th - 40th): {}'.format(file_exist[0:40].hex()),
            output)
        self.assertIn(
            'Map Test 2 (200th - 240th): {}'.format(file_exist[200:240].hex()),
            output)

        # Set File Length
        self.assertEqual(
            pathlib.Path('file_nonexist.tmp').stat().st_size,
            mmap.ALLOCATIONGRANULARITY)

        # File Deletion
        self.assertFalse(pathlib.Path('file_delete.tmp').exists())

    def test_110_directory(self):
        for path in ['dir_exist.tmp', 'dir_nonexist.tmp', 'dir_delete.tmp',
                     'dir_rename.tmp', 'dir_rename_delete.tmp']:
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                pass

        path = pathlib.Path('dir_exist.tmp')
        files = [path / ''.join(random.choice(string.ascii_letters)
                                for _ in range(8))
                 for _ in range(5)]
        path.mkdir()
        for file_ in files:
            file_.touch()
        pathlib.Path('dir_delete.tmp').mkdir()

        stdout, stderr = self.run_binary(['Directory'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Basic Directory Opening
        self.assertIn('Directory Open Test 1 OK', output)
        self.assertIn('Directory Open Test 2 OK', output)
        self.assertIn('Directory Open Test 3 OK', output)

        # Basic Directory Creation
        self.assertIn('Directory Creation Test 1 OK', output)
        self.assertIn('Directory Creation Test 2 OK', output)
        self.assertIn('Directory Creation Test 3 OK', output)

        # Directory Reading
        for file_ in files:
            self.assertIn('Read Directory: {}'.format(file_.name), output)

        # Directory Attribute Query
        self.assertIn('Query: type = ', output)

        # Directory Attribute Query by Handle
        self.assertIn('Query by Handle: type = ', output)

        # Directory Deletion
        self.assertFalse(pathlib.Path('dir_delete.tmp').exists())
        self.assertFalse(pathlib.Path('dir_rename.tmp').exists())
        self.assertFalse(pathlib.Path('dir_rename_delete.tmp').exists())

    def test_200_event(self):
        stdout, stderr = self.run_binary(['Event'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('TEST OK', output)

    def test_300_memory(self):
        if not HAS_SGX or HAS_EDMM:
            stdout, stderr = self.run_binary(['memory'])
            output = stdout if (HAS_TDX or HAS_VM) else stderr
            self.assertIn('TEST OK', output)
        else:
            # SGX1 does not support unmapping a page or changing its permission after enclave init.
            # Therefore the memory protection and deallocation tests will fail.
            try:
                self.run_binary(['memory'])
                self.fail('expected to return nonzero')
            except subprocess.CalledProcessError as e:
                self.assertEqual(e.returncode, 1)
                stderr = e.stderr.decode()
                self.assertRegex(stderr, r'exec on RW mem at 0x[0-9a-f]+ unexpectedly succeeded')

    def test_400_pipe(self):
        stdout, stderr = self.run_binary(['Pipe'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Pipe Creation
        self.assertIn('Pipe Creation 1 OK', output)

        # Pipe Attributes
        self.assertIn('Pipe Attribute Query 1 on pipesrv returned OK', output)

        # Pipe Connection
        self.assertIn('Pipe Connection 1 OK', output)

        # Pipe Transmission
        self.assertIn('Pipe Write 1 OK', output)
        self.assertIn('Pipe Read 1: Hello World 1', output)
        self.assertIn('Pipe Write 2 OK', output)
        self.assertIn('Pipe Read 2: Hello World 2', output)

    @unittest.skipUnless(ON_X86, "x86-specific")
    def test_500_thread(self):
        stdout, stderr = self.run_binary(['Thread'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Thread Creation
        self.assertIn('Child Thread Created', output)
        self.assertIn('Run in Child Thread: Hello World', output)

        # Multiple Threads Run in Parallel
        self.assertIn('Threads Run in Parallel OK', output)

        # Set Thread Private Segment Register
        self.assertIn('Private Message (FS Segment) 1: Hello World 1', output)
        self.assertIn('Private Message (FS Segment) 2: Hello World 2', output)

        # Thread Exit
        self.assertIn('Child Thread Exited', output)

    def test_510_thread2(self):
        stdout, stderr = self.run_binary(['Thread2'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Thread Cleanup: Exit by return.
        self.assertIn('Thread 2 ok.', output)

        # Thread Cleanup: Exit by PalThreadExit.
        self.assertIn('Thread 3 ok.', output)
        self.assertNotIn('Exiting thread 3 failed.', output)

        # Thread Cleanup: Can still start threads.
        self.assertIn('Thread 4 ok.', output)

    @unittest.skipUnless(HAS_SGX, 'This test is only meaningful on SGX PAL')
    def test_511_thread2_exitless(self):
        stdout, stderr = self.run_binary(['Thread2_exitless'], timeout=60)
        output = stdout if (HAS_TDX or HAS_VM) else stderr

        # Thread Cleanup: Exit by return.
        self.assertIn('Thread 2 ok.', output)

        # Thread Cleanup: Exit by PalThreadExit.
        self.assertIn('Thread 3 ok.', output)
        self.assertNotIn('Exiting thread 3 failed.', output)

        # Thread Cleanup: Can still start threads.
        self.assertIn('Thread 4 ok.', output)

    @unittest.skipUnless(HAS_SGX, 'This test is only meaningful on SGX PAL')
    def test_512_thread2_edmm(self):
        if HAS_EDMM:
            stdout, stderr = self.run_binary(['Thread2_edmm'])
            output = stdout if (HAS_TDX or HAS_VM) else stderr
            self.assertIn('Thread 2 ok.', output)
            self.assertIn('Thread 3 ok.', output)
            self.assertNotIn('Exiting thread 3 failed.', output)
            self.assertIn('Thread 4 ok.', output)
        else:
            try:
                self.run_binary(['Thread2_edmm'])
                self.fail('expected to return nonzero')
            except subprocess.CalledProcessError as e:
                stderr = e.stderr.decode()
                self.assertIn("PalThreadCreate failed for thread 2.", stderr)

    def test_900_misc(self):
        stdout, stderr = self.run_binary(['Misc'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        # Query System Time
        self.assertIn('Query System Time OK', output)

        # Delay Execution for 10000 Microseconds
        self.assertIn('Delay Execution for 10000 Microseconds OK', output)

        # Delay Execution for 3 Seconds
        self.assertIn('Delay Execution for 3 Seconds OK', output)

        # Generate Random Bits
        self.assertIn('Generate Random Bits OK', output)

    def test_910_hex(self):
        stdout, stderr = self.run_binary(['Hex'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        # Hex 2 String Helper Function
        self.assertIn('Hex test 1 is deadbeef', output)
        self.assertIn('Hex test 2 is cdcdcdcdcdcdcdcd', output)

class TC_21_ProcessCreation(RegressionTestCase):
    def test_100_process(self):
        stdout, stderr = self.run_binary(['Process'], timeout=60)
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        counter = collections.Counter(output.split('\n'))
        # Process Creation
        self.assertEqual(counter['Child Process Created'], 3)

        # Process Creation Arguments
        self.assertEqual(counter['argv[0] = Process'], 3)
        self.assertEqual(counter['argv[1] = Child'], 3)

        # Process Channel Transmission
        self.assertEqual(counter['Process Write 1 OK'], 3)
        self.assertEqual(counter['Process Read 1: Hello World 1'], 3)
        self.assertEqual(counter['Process Write 2 OK'], 3)
        self.assertEqual(counter['Process Read 2: Hello World 2'], 3)

class TC_23_SendHandle(RegressionTestCase):
    def test_000_send_handle(self):
        stdout, stderr = self.run_binary(['send_handle'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('Parent: test OK', output)
        self.assertIn('Child: test OK', output)

class TC_30_IPParser(RegressionTestCase):
    def test_000_ipv4(self):
        stdout, stderr = self.run_binary(['ipv4_parser'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('TEST OK', output)

    def test_010_ipv6(self):
        stdout, stderr = self.run_binary(['ipv6_parser'])
        output = stdout if (HAS_TDX or HAS_VM) else stderr
        self.assertIn('TEST OK', output)

@unittest.skipUnless(HAS_SGX, 'This test is only meaningful on SGX PAL')
class TC_50_Attestation(RegressionTestCase):
    def test_000_attestation_report(self):
        _, stderr = self.run_binary(['AttestationReport'])
        self.assertNotIn('ERROR', stderr)
        self.assertIn('Success', stderr)
