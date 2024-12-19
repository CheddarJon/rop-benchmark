import sys
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


class SGC:

    def __init__(self, binary, input, job, ropchain, rw_address, bad_chars, cehck_reg = 0):
        self.binary = binary
        self.input = input
        self.job = job
        self.logger = job.logger
        self.check_regs_set_func_addr = 0x0
        self.ropchain = ropchain
        self.bad_chars = bad_chars
        self.rw_address = rw_address
        self.cehck_reg = cehck_reg

    def run(self, timeout):
        from os.path import abspath, dirname, join
        
        arch = self.job.arch
        runner = abspath(join(dirname(__file__), "SGC_runner.py"))
        cmd = ["/venv-sgc/bin/python3", runner, self.binary, self.ropchain, self.job.script_file]
        if self.rw_address:
            cmd += [str(self.rw_address)]
        cmd += [str(arch)]
        self.logger.debug("RUN SGC runner {}".format(" ".join(cmd)))
        process = Popen(cmd, stderr=STDOUT, stdout=PIPE)

        try:
            stdout = process.communicate(timeout=timeout)[0]
            self.logger.error("SGC runner output:")
            self.logger.error(stdout.decode(errors='ignore'))
        except TimeoutExpired:
            process.kill()
            self.logger.critical("FAIL TIMEOUT")
            exit(3)

        if process.returncode != 0:
            self.logger.error("Compilation ERROR with {} (SGC)".format(process.returncode))
            exit(1)
