FROM ubuntu:20.04

MAINTAINER Alexey Nurmukhametov

ARG DEBIAN_FRONTEND=noninteractive

COPY ./zh /zh
RUN apt-get update && \
    apt-get install -y locales python python3 python3-pip python3-venv make gcc nasm git libcapstone-dev curl unzip wget cmake && \
# uncomment locales and generate them
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen && \
# replace some shebangs to /bin/bash
    sed 's@#!/bin/sh@#!/bin/bash@g' -i /sbin/ldconfig && \
    sed 's@#!/bin/sh@#!/bin/bash@g' -i /bin/lesspipe

RUN pip3 install psutil==6.1.0 pyelftools==0.31 pytest==8.3.3 pybind11==2.13.6 && \
    pip3 freeze > base_requirements.txt

ENV LC_ALL=en_US.utf-8
ENV LANG=en_US.utf-8
ENV LANGUAGE=en_US.utf-8

RUN python3 -m venv venv-ropgadget && \
    . venv-ropgadget/bin/activate && \
    pip3 install -r /base_requirements.txt && \
    pip3 install ropgadget==7.5 && \
    deactivate

RUN python3 -m venv venv-angrop && \
    . venv-angrop/bin/activate && \
    pip3 install -r /base_requirements.txt && \
    pip3 install wheel && \
    pip3 install angrop==9.2.11 && \
    deactivate

RUN python3 -m venv venv-ropper && \
    . venv-ropper/bin/activate && \
    pip3 install -r /base_requirements.txt && \
    pip3 install wheel && \
    pip3 install ropper==1.13.8 && \
    deactivate

RUN python3 -m venv venv-ropium && \
    . venv-ropium/bin/activate && \
    pip3 install -r /base_requirements.txt && \
    pip3 install prompt_toolkit && \
    pip3 install ropgadget==7.5 && \
    curl -s -o ropium.zip -L https://github.com/Boyan-MILANOV/ropium/archive/refs/tags/v3.3.zip && \
    unzip -q ropium.zip && mv ropium-* ropium && cd ropium && \
    make && make test && \
    make install PREFIX=/venv-ropium PYTHONDIR=/venv-ropium/lib/python3.8/site-packages && \
    cd / && rm -rf ropium* && \
    sed -i 's/#!.*/#!\/venv-ropium\/bin\/python3/' /venv-ropium/bin/ropium && \
    deactivate

RUN python3 -m venv venv-sgc && \
    . venv-sgc/bin/activate && \
    pip3 install -r /base_requirements.txt && \
    pip3 install wheel && \
    pip3 install fuckpy3==1.0 && \
    pip3 install forbiddenfruit==0.1.3 && \
    curl -s -o sgc.zip -L https://github.com/RUB-SysSec/gadget_synthesis/archive/6a92a37525aa9810146003906ab41b7eb8e9ce2d.zip && \
    unzip -q sgc.zip && rm sgc.zip && mv gadget_synthesis-* /venv-sgc/sgc && cd /venv-sgc/sgc && \
    pip3 install -r requirements.txt && pip3 install -e . && \
    cd / && deactivate

RUN python3 -m venv venv-gadgetplanner && \
    . venv-gadgetplanner/bin/activate && \
    pip3 install -r /base_requirements.txt && \
    pip3 install wheel && \
    curl -s -o gadgetplanner.zip -L https://github.com/softsec-unh/Gadget-Planner/archive/afe0abdba57a0831650b34a102a5201e72c0f354.zip && \
    unzip -q gadgetplanner.zip && rm gadgetplanner.zip && mv Gadget-Planner-* /venv-gadgetplanner/gadgetplanner && cd /venv-gadgetplanner/gadgetplanner && \
    pip3 install -r requirements.txt && \
    pip3 install numpy==1.19.2 && \
    pip3 install stn==1.0.1 && \
    pip3 install tensorboard==2.6.0 && \
    pip3 install tensorflow==2.4.3 && \
    cd / && deactivate

ARG GHIDRA_VERSION="9.2.2"
ARG GHIDRA_VERSION_FULL="9.2.2_PUBLIC_20201229"
ARG GHIDRA_SHA256="8cf8806dd5b8b7c7826f04fad8b86fc7e07ea380eae497f3035f8c974de72cf8"

# Install Ghidra (required by Sgc)
RUN mkdir /venv-sgc/builds && cd /venv-sgc/builds && \
    wget -q -O ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION_FULL}.zip && \
    echo "${GHIDRA_SHA256} *ghidra.zip" | sha256sum -c && \
    unzip -q ghidra.zip && \
    rm ghidra.zip

# Create symbolic links to ghidra and ghidra-analyzeHeadless
RUN ln -s /venv-sgc/builds/ghidra* /bin/ghidra && \
    ln -s /venv-sgc/builds/ghidra*/support/analyzeHeadless /bin/ghidra-analyzeHeadless

# Install boolector (sgc)
RUN mkdir -p /venv-sgc/builds && cd /venv-sgc/builds && \
    wget -q -O boolector.zip https://github.com/Boolector/boolector/archive/refs/tags/3.2.2.zip && \
    unzip -q boolector.zip && rm boolector.zip && \
    mv boolector-* boolector && cd boolector && \
    ./contrib/setup-lingeling.sh && \
    ./contrib/setup-btor2tools.sh && \
    ./configure.sh && cd build && make

# Create symlink for boolector (sgc)
RUN ln -s /venv-sgc/builds/boolector/build/bin/boolector /usr/bin/boolector

# create symlink /bin/sh -> /zh
RUN rm -rf /bin/sh && ln -s /zh /bin/sh && \
    rm -rf /var/lib/apt/lists/* /root/.cache

# libc.so built with popen calling /bin/bash instead of /bin/sh
COPY ./libc.so /lib/x86_64-linux-gnu/libc.so.6
