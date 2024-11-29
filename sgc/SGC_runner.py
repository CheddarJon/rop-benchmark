import sys
import fuckpy3
import logging
from datetime import datetime 
import os
import time
import json
import subprocess
import re
from elftools.elf.elffile import ELFFile
from shutil import copyfile, rmtree

class SGC:

    def __init__(self, binary, ropchain, job, rw_address, check_regs_set_func_addr = 0, cehck_reg = 0):
        self.rop_tool = "SGC"
        self.binary = binary
        self.job = job
        self.binary_input = "{}.SGC.input".format(self.binary)
        self.binary_name = ""
        self.win_stack = ""
        self.ropchain_path = ropchain
        self.rw_address = rw_address
        self.check_regs_set_func_addr = check_regs_set_func_addr
        self.cehck_reg = cehck_reg
        self.reg_lists = ['rax','rbx','rcx','rdx','rsi','rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        self.precondition = {}
        self.twoparams = False # False, True

    def construct_json(self, json_file):
        with open(json_file, 'r') as file:
            json_data = file.read()

            data = json.loads(json_data)

            data['executable'] = self.binary_name

            crash_addr = 0x0
            crash_addr = self.remote_debug_vulret_addr(self.binary)

            # set the rsp
            preconditions = []
            for reg_info in data['preconditions']:
                if(reg_info[0] == 'RSP'):
                    # rsp_register_info = self.remote_debug(self.binary, crash_addr, pre_reg = 'rsp')
                    rsp_register_info = False
                    if(rsp_register_info != False):
                        reg_info[1] = rsp_register_info
                    else:
                        rsp_register_info = reg_info[1]
                
                if(reg_info[0] == 'IRDst'):
                    if(crash_addr != 0x0):
                        reg_info[1] = crash_addr
                    else:
                        ret_gadget_addr = self.find_ret_gadget(self.binary)
                        if(ret_gadget_addr != 0x0):
                            reg_info[1] = ret_gadget_addr
                
                
                preconditions.append(reg_info)
            
            reg_lists = ['rax','rbx','rcx','rdx','rsi','rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
            #self.remote_debug_all_regs()
            for reg_name in self.precondition:
                register_info = hex(self.precondition[reg_name])
                preconditions.append([reg_name.upper(), register_info, 64])
            data['preconditions'] = preconditions

            postconditions = []
            for reg_info in data['postconditions']:
                if(reg_info[0] == 'IRDst'):
                   syscall_gadget_addr = self.find_syscall_gadget(self.binary)
                   if(syscall_gadget_addr != ''):
                       reg_info[1] = syscall_gadget_addr
                
                postconditions.append(reg_info)
            
            data['postconditions'] = postconditions

            min_addr, max_addr = self.get_read_mem_range()

            # append the full readable area (maybe needed)
            full_read_range = self.extract_combined_range(self.binary)
            data['read_mem_areas'] = [[full_read_range[0], full_read_range[1]]]
            data['read_mem_areas'].append([hex(min_addr), hex(min_addr+15)])
            if(eval(data['write_mem_areas'][0][0]) > eval(rsp_register_info)):
                original_stack_range = data['write_mem_areas'][0]
                data['read_mem_areas'].pop(0)
                data['write_mem_areas'].append([hex(eval(rsp_register_info)), hex(eval(original_stack_range[1]))])
                data['write_mem_areas'].append([hex(min_addr), hex(max_addr)])
            else:
                data['write_mem_areas'].append([hex(min_addr), hex(min_addr+15)])
            
             
            
            print(data)

            with open(json_file, 'w') as file:
                json.dump(data, file)
            
        return 

    

    def extract_combined_range(self,binary_path):
        # Run gdb with the binary and execute 'info proc mappings'
        try:
            # Run gdb, pause the program, and capture mappings
            gdb_command = f"""
            gdb -batch -ex 'file {binary_path}' -ex 'start' -ex 'info proc mappings' -ex 'quit'
            """
            result = subprocess.run(gdb_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #create_symlink(original_target, symlink_path)
            # Check for errors in gdb execution
            if result.returncode != 0:
                print(f"Error: {result.stderr.strip()}")
                return None
            
            # Parse the output for readable address ranges
            mappings = result.stdout
            print(mappings)
            readable_ranges = []
            
            # Regular expression to match the mappings format
            mapping_pattern = re.compile(
                r"^\s*(0x[0-9a-f]+)\s*(0x[0-9a-f]+)\s*(0x[0-9a-f]+)\s*(0x[0-9a-f]+)\s*(.*)$"
            )
            
            for line in mappings.splitlines():
                match = mapping_pattern.match(line)
                if match:
                    start_addr, end_addr, size, offset, objfile = match.groups()
                    # Include ranges with binary path in objfile, exclude stack, and non-binary paths
                    if binary_path in objfile and "[stack]" not in objfile and "[vdso]" not in objfile:
                        readable_ranges.append((start_addr, end_addr))
            
            if not readable_ranges:
                print("No readable ranges found!")
                return None

            # Combine ranges into a single range: start of first to end of last
            start = readable_ranges[0][0]
            end = readable_ranges[-1][1]

            return start, end    
        except Exception as e:
            print(f"Error while processing: {e}")
        return None

    def remote_debug_all_regs(self):
        program_args = self.win_stack

        import random
        import string
        letters = string.ascii_lowercase
        inputFileName = '/tmp/' + ''.join(random.choice(letters) for i in range(6))
        subprocess.run(['cp', self.win_stack, inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        program_args = inputFileName

        gdb_cmd = ['gdb'] + [self.binary]
        gdb_proc = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=os.getcwd())

        gdb_proc.stdin.write(b'b vul\n')
        if(self.binary_name.startswith('ex') or self.twoparams):
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b'\n')
        else:
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b' 0 \n')
        gdb_proc.stdin.flush()

        output = gdb_proc.stdout.readline().decode()
        while 'Breakpoint 1, vul ' not in output:
            output = gdb_proc.stdout.readline().decode()

        gdb_proc.stdin.write(b'disassemble vul\n')
        gdb_proc.stdin.flush()

        ret_addr_info = 0x0
        output = gdb_proc.stdout.readline().decode()
        while not output.endswith('ret    \n'):
            output = gdb_proc.stdout.readline().decode()

        ret_addr_info = eval(output.split(' <')[0])
        
        gdb_proc.stdin.write(b'b *'+ hex(ret_addr_info).encode() + b'\n')
        gdb_proc.stdin.write(b'continue\n')
        gdb_proc.stdin.flush()

        output = gdb_proc.stdout.readline().decode()
        while 'Breakpoint 2, ' not in output:
            output = gdb_proc.stdout.readline().decode()

        min_addr, max_addr = self.get_read_mem_range()
        for idx, pre_reg in enumerate(self.reg_lists):
            gdb_proc.stdin.write(b'print $' + pre_reg.encode() + b'\n')
            gdb_proc.stdin.flush()

            register_info = ''
            output = gdb_proc.stdout.readline().decode()
            split_str = '$' + str(idx + 1) + ' = '
            while split_str not in output:
                output = gdb_proc.stdout.readline().decode()

            if('(void *)' in output):
                output = output.split('(void *) ')[-1]
            else:
                output = output.split(split_str)[-1]
            if('-' in output):
                register_info = eval(output) & 0xffffffffffffffff
            else:
                register_info = eval(output)
            
            gdb_proc.stdin.write(b'xinfo ' + hex(register_info).encode() + b'\n')
            gdb_proc.stdin.flush()

            output = gdb_proc.stdout.readline().decode()
            while 'not mapped' not in output and 'Extended information for virtual address' not in output:
                output = gdb_proc.stdout.readline().decode()

            if('not mapped' in output):
                self.precondition[pre_reg] = register_info
            
            if('Extended information for virtual address' in output):
                if(register_info >= min_addr and register_info <= max_addr):
                    self.precondition[pre_reg] = register_info
        
        print(self.precondition)
        gdb_proc.stdin.write(b'quit\n')
        gdb_proc.stdin.flush()

        subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def find_ret_gadget(self, program_path):  
        
        ret_gadget_addr = 0x0
        command = ['/venv-sgc/bin/ROPgadget', '--binary', program_path]
        p1 = subprocess.Popen(command, stdout=subprocess.PIPE)
        process = subprocess.Popen(["grep", ": ret$"], stdin=p1.stdout, stdout=subprocess.PIPE)
        
        for line in process.stdout:
            if(': ret' in line.decode()):
                ret_gadget_addr = line.split(b' : ')[0]
        
        if(ret_gadget_addr == 0x0):
            command = ['/venv-sgc/bin/ROPgadget', '--binary', program_path]
            p1 = subprocess.Popen(command, stdout=subprocess.PIPE)
            process = subprocess.Popen(["grep", ": ret 0$"], stdin=p1.stdout, stdout=subprocess.PIPE)
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
            for line in process.stdout:
                if(': ret' in line.decode()):
                    ret_gadget_addr = line.split(b' : ')[0]

        return ret_gadget_addr.strip().decode()

    def find_syscall_gadget(self, program_path):

        syscall_gadget_addr = b''
        command = ['/venv-sgc/bin/ROPgadget', '--binary', program_path]
        p1 = subprocess.Popen(command, stdout=subprocess.PIPE)
        process = subprocess.Popen(["grep", ": syscall$"], stdin=p1.stdout, stdout=subprocess.PIPE)
        for line in process.stdout:
            if(': syscall' in line.decode()):
                syscall_gadget_addr = line.split(b' : ')[0]
        
        return syscall_gadget_addr.strip().decode()

    def remote_debug(self, program_path, crash_addr, pre_reg = 'rsp'):
        program_args = self.win_stack
        
        import random
        import string
        letters = string.ascii_lowercase
        inputFileName = '/tmp/' + ''.join(random.choice(letters) for i in range(6))
        subprocess.run(['cp', self.win_stack, inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        program_args = inputFileName

        gadget_synthesis_dir = '/ssd/home/rop/rop-benchmark-master/gadget_synthesis'
        gdb_cmd = ['gdb'] + [program_path]
        gdb_proc = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=gadget_synthesis_dir)

        gdb_proc.stdin.write(b'b *' + crash_addr.encode() + b'\n')
        print(program_args.encode())
        if(self.binary_name.startswith('ex') or self.twoparams):
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b'\n')
        else:
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b'  0 \n')
        gdb_proc.stdin.flush()

        output = gdb_proc.stdout.readline().decode()
        while 'Breakpoint 1, ' not in output:
            output = gdb_proc.stdout.readline().decode()

        gdb_proc.stdin.write(b'print $' + pre_reg.encode() + b'\n')
        gdb_proc.stdin.flush()

        rsp_register_info = ''
        output = gdb_proc.stdout.readline().decode()
        while '$1 = ' not in output:
            output = gdb_proc.stdout.readline().decode()

        if('(void *)' in output):
            output = output.split('(void *) ')[-1]
        else:
            output = output.split('$1 = ')[-1]
        if('-' in output):
            rsp_register_info = eval(output) & 0xffffffffffffffff
        else:
            rsp_register_info = eval(output)

        gdb_proc.stdin.write(b'quit\n')
        gdb_proc.stdin.flush()

        subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return hex(rsp_register_info)

    def remote_debug_vulret_addr(self, program_path, ):
        obj_cmd = subprocess.Popen(['objdump', '--disassemble=vul', program_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        vul_disass, _ = obj_cmd.communicate()
        vul_lines = vul_disass.decode().split('\n')
        for line in reversed(vul_disass.decode().split('\n')):
            if 'ret' in line:
                addr = line.split(':')[0].strip()
                
                return hex(int(addr, 16))

        return hex(0)

    def run_rop_tool(self):
        """
        create /<binary>/target_template
        create /<binary>/config
        create /<binary>/executable
        """
        from pathlib import Path 

        sgc_dir = '/venv-sgc/sgc' 
        target_template_path = f'/rop-benchmark/sgc/target_template' 
        self.binary_name = self.binary.split('/')[-1] 
        target_chain = self.job.split('/')[-1].replace('job_', '').replace('.py', '')
        target_config = f'config_{target_chain}.json'

        binary_dir = self.binary[:self.binary.rfind(self.binary_name) - 1]
        target_dir = f'/tmp/sgc_{self.binary_name}'
        stack_file = 'stack.bin'
        self.win_stack = os.path.join(target_dir, stack_file)
        target_file = os.path.join(target_dir, self.binary_name)
        json_file = os.path.join(target_dir, target_config)
        gadgets_dir = os.path.join(target_dir, 'gadgets')
        smt_out_dir = os.path.join(target_dir, 'smt_out')

        if os.path.exists(target_dir):
            rmtree(target_dir)

        Path(target_dir).mkdir(parents=True)
        copyfile(self.binary, target_file)
        copyfile(os.path.join(target_template_path, target_config), json_file)
        copyfile(os.path.join(target_template_path, stack_file), self.win_stack)
        
        self.construct_json(json_file)

        command_1 = ['/venv-sgc/bin/python3', 'extractor.py', '-c', 'config_execve.json', target_dir, '-o', gadgets_dir] 
        process = subprocess.Popen(command_1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, cwd=sgc_dir)
        for line in process.stdout:
            print(line)

        command_2 = ['/venv-sgc/bin/python3', 'synthesizer.py', '-v', '-j', '12', '-c', 'config_execve.json', target_dir, '-o', smt_out_dir]
        print(command_2)
        process = subprocess.Popen(command_2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, cwd=sgc_dir)
        for line in process.stdout:
            print(line)
        print(command_2)
        if(self.get_correct_stack(smt_out_dir)):
            #self.write_csv('result/SGC.3600.x86.0715_3_params_itself.csv',['SGC', self.binary, True])
            print("Chain found!")

    def write_csv(self, filename, one_row_data):
        import csv
        with open(filename,'a+') as f:
            csv_write = csv.writer(f)
            csv_write.writerow(one_row_data)

    def get_correct_stack(self, solver_out):
        # TODO What does this function do??
        current_path = os.path.abspath(__file__)
        gadget_synthesis_dir = '/venv-sgc/sgc'
        rop_benchmark_dir = '/rop-benchmark'
        correct = False
        solver_self_out = os.path.join(gadget_synthesis_dir, solver_out, f'sgc_{self.binary_name}')
        print("solver_self_out = " + solver_self_out)
        folders = []
        for name in os.listdir(solver_self_out):
            if os.path.isdir(os.path.join(solver_self_out, name)):
                folders.append(name)

        self.ropchain_path = os.path.join(rop_benchmark_dir, self.ropchain_path)
        self.input_path = self.ropchain_path.replace('SGC.ropchain', 'SGC.input')

        subprocess.run(['rm', self.ropchain_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
        subprocess.run(['rm', self.input_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
        for folder in folders:
            result_file_path = os.path.join(solver_self_out, folder, 'result.json')
            if(os.path.exists(result_file_path)):
                        
                with open(result_file_path, 'r') as file:
                    json_data = file.read()
                    data = json.loads(json_data)

                    if('verification' in data and data['verification'] == True):
                        print("it's win")
                        stack_path = os.path.join(solver_self_out, folder, 'stack.bin')
                        print("[+] maybe win input : " + str(stack_path))
                        correct = True
                        
                        subprocess.run(['cp', stack_path, self.win_stack], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
                        print("self.ropchain_path = " + self.ropchain_path)
                        subprocess.run(['cp', stack_path, self.ropchain_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
                        
        return correct
        

    def add_exp_padding(self, filename):
        padding_length = 29
        with open(filename, 'rb+') as file:
            string_to_insert = b'a'*padding_length

            file.seek(0)

            original_data = file.read()

            file.seek(0)
            file.write(string_to_insert)

            file.write(original_data)

    def get_read_mem_range(self,):
        
        '''
        typedef struct {
            Elf32_Word p_type;
            Elf32_Off p_offset;
            Elf32_Addr p_vaddr;
            Elf32_Addr p_paddr;
            Elf32_Word p_filesz;
            Elf32_Word p_memsz;
            Elf32_Word p_flags;
            Elf32_Word p_align;
        }
        '''
        rwx_flag = {0:'', 1:'w', 2:'r', 3 : 'rw', 4:'x', 5: 'xw', 6:'rx', 7:'rwx'} 
        file = open(self.binary, 'rb')
        elf_file = ELFFile(file)

        all_segment = []
        for segment in elf_file.iter_segments():
            all_segment.append(segment)
        
        writable_addr_range = {}
        readable_addr_range = {}
        for segment in all_segment:
            header = segment.header
            sh_flags = header.p_flags
            if(sh_flags in rwx_flag and header.p_vaddr != 0):
                flag_name = rwx_flag[sh_flags]
                if('w' in flag_name):
                    writable_addr_range[header['p_type']] = (header['p_vaddr'], header['p_vaddr'] + header['p_memsz'])
                if('r' in flag_name):
                    readable_addr_range[header['p_type']] = (header['p_vaddr'], header['p_vaddr'] + header['p_memsz'])

        all_section = []
        for section in elf_file.iter_sections():
            all_section.append(section.name)
        for section_name in all_section:
            section = elf_file.get_section_by_name(section_name)
            if(section == None):
                continue
            sh_flags = section.header.sh_flags
            if(sh_flags in rwx_flag and section.header.sh_addr != 0):
                flag_name = rwx_flag[sh_flags]
                if('w' in flag_name):
                    writable_addr_range[section.name] = (section.header.sh_addr, section.header.sh_addr + section.header.sh_size)
                if('r' in flag_name):
                    readable_addr_range[section.name] = (section.header.sh_addr, section.header.sh_addr + section.header.sh_size)
        
        
        if('.bss' in writable_addr_range):
            bss_end_addr = writable_addr_range['.bss'][1]
            bss_end_addr = ((bss_end_addr >> 12) + 1)*0x1000 
            bss_end_addr = writable_addr_range['.bss'][0] + 0x100
            writable_addr_range['.bss'] = (writable_addr_range['.bss'][0], bss_end_addr)
        if('.bss' in readable_addr_range):
            bss_end_addr = readable_addr_range['.bss'][1]
            bss_end_addr = ((bss_end_addr >> 12) + 1)*0x1000 #  不需要这么大的吧
            bss_end_addr = readable_addr_range['.bss'][0] + 0x100
            readable_addr_range['.bss'] = (readable_addr_range['.bss'][0], bss_end_addr)  

        target_addr_range = {'.bss' : writable_addr_range['.bss']}
        max_addr = 0
        min_addr = 0xffffffffffffffff
        sec_list = list(target_addr_range.keys())
        for sec_name in sec_list:
            if(target_addr_range[sec_name][0] <= min_addr):
                min_addr = target_addr_range[sec_name][0]
            if(max_addr <= target_addr_range[sec_name][1]):
                max_addr = target_addr_range[sec_name][1]
        
        return min_addr, max_addr

logging.getLogger('angr').setLevel('CRITICAL')
binary = sys.argv[1]
ropchain_path = sys.argv[2]
job = sys.argv[3]
rw = int(sys.argv[4]) #
arch_type = sys.argv[5]
check_reg_count = 0
check_regs_set_func_addr = 0
if(len(sys.argv) > 6):
    check_regs_set_func_addr = int(sys.argv[5])
if(len(sys.argv) > 7):
    check_reg_count = int(sys.argv[6])


mysgc = SGC(binary, ropchain_path, job, rw, check_regs_set_func_addr = check_regs_set_func_addr, cehck_reg = check_reg_count)

mysgc.run_rop_tool()

