import sys
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


class Gadgetplanner:

    def __init__(self, binary, input, job, ropchain, bad_chars):
        self.binary = binary
        self.input = input
        self.job = job
        self.logger = job.logger
        self.ropchain = ropchain
        self.bad_chars = bad_chars
        self.gadget_planner_main = "/venv-gadgetplanner/gadgetplanner/tools/main.py"

    def run(self, timeout):
        from os.path import abspath, dirname, join
        cmd = ["python3", self.gadget_planner_main, self.binary, "--fancy"]
        self.logger.debug(cmd)
        if self.bad_chars:
            cmd += [self.bad_chars]
        self.logger.debug("RUN gadget-planner: {}".format(" ".join(cmd)))
        process = Popen(cmd, stderr=STDOUT, stdout=PIPE)

        try:
            stdout = process.communicate(timeout=timeout)[0]
            self.logger.debug("gadget-planner output:")
            self.logger.debug(stdout.decode(errors='ignore'))
        except TimeoutExpired:
            process.kill()
            self.logger.critical("FAIL TIMEOUT")
            exit(3)

        if process.returncode != 0:
            self.logger.error("Compilation ERROR with {} (gadget-planner)".format(process.returncode))
            exit(1)
