FROM debian:bullseye-slim

# Create an unprivileged user to run the application process
ENV ZENITH_UID 1001
ENV ZENITH_USER zenith
RUN useradd \
      --no-create-home \
      --user-group \
      --shell /sbin/nologin \
      --uid $ZENITH_UID \
      $ZENITH_USER

# By default, we run as root but switch to the zenith user after reading configuration
ENV ZENITH_CLIENT__RUN_AS_USER 1001

# Install tini, which we will use to marshal the processes, Python and the OpenSSH client
RUN apt-get update && \
    apt-get install -y git openssh-client python3 python3-pip tini && \
    rm -rf /var/lib/apt/lists/*

# Installing dependencies separately ensures better use of the build cache
COPY requirements.txt /opt/zenith/client/
RUN pip3 install --no-deps --requirement /opt/zenith/client/requirements.txt

COPY . /opt/zenith/client
RUN pip3 install --no-deps -e /opt/zenith/client

ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["zenith-client"]
