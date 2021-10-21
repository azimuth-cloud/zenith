FROM debian:bullseye-slim

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# Install tini, which we will use to marshal the processes, and Python
RUN apt-get update && \
    apt-get install -y git python3 python3-pip tini && \
    rm -rf /var/lib/apt/lists/*

# Installing dependencies separately ensures better use of the build cache
COPY ./requirements.txt /opt/zenith/common/
RUN pip3 install --no-deps --requirement /opt/zenith/common/requirements.txt

COPY . /opt/zenith/common
RUN pip3 install --no-deps -e /opt/zenith/common

ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
