#!/bin/bash

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space >/dev/null 2>&1

docker run --rm -it -v `pwd`:/rop-benchmark/ \
  -e PYTHONUNBUFFERED=1 -e PYTHONPATH=/rop-benchmark \
  rop-benchmark /bin/bash -c "rm /venv-sgc/sgc/synthesizer_config_default.json && \
  cp /rop-benchmark/sgc/target_template/synthesizer_config_default.json /venv-sgc/sgc && \
  exec /bin/bash"

echo 2 | sudo tee /proc/sys/kernel/randomize_va_space >/dev/null 2>&1