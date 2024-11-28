#!/bin/bash

_term() {
  docker stop rop-benchmark > /dev/null
  echo 2 | sudo tee /proc/sys/kernel/randomize_va_space >/dev/null 2>&1
}

trap _term SIGTERM
trap _term SIGINT

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space >/dev/null 2>&1
docker run --rm -t -v `pwd`:/rop-benchmark/ \
  --name="rop-benchmark" \
  -e PYTHONUNBUFFERED=1 -e PYTHONPATH=/rop-benchmark \
  rop-benchmark \
  /bin/bash -c "cd /rop-benchmark && python3 /rop-benchmark/run.py $*" &

child=$!
wait "$child"
