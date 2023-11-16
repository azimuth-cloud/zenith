FROM ubuntu:jammy AS python-builder

RUN apt-get update && \
    apt-get install -y python3 python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv && \
    /venv/bin/pip install -U pip setuptools

COPY requirements.txt /app/requirements.txt
RUN  /venv/bin/pip install --no-deps --requirement /app/requirements.txt

# Jinja2 doesn't support namespace packages properly
# https://jinja.palletsprojects.com/en/3.1.x/api/#loaders
# So we install here instead as an editable installation and also copy over
# the app directory, which also avoids needing pip in the final image
COPY . /app
RUN /venv/bin/pip install --no-deps -e /app


FROM ubuntu:jammy

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# Create the user that will be used to run the app
ENV ZENITH_UID 1001
ENV ZENITH_GID 1001
ENV ZENITH_USER zenith
ENV ZENITH_GROUP zenith
RUN groupadd --gid $ZENITH_GID $ZENITH_GROUP && \
    useradd \
      --no-create-home \
      --no-user-group \
      --gid $ZENITH_GID \
      --shell /sbin/nologin \
      --uid $ZENITH_UID \
      $ZENITH_USER

RUN apt-get update && \
    apt-get install -y ca-certificates python3 tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /venv /venv
COPY --from=python-builder /app /app

USER $ZENITH_UID
ENTRYPOINT ["tini", "-g", "--"]
CMD ["/venv/bin/kopf", "run", "--module", "zenith.operator", "--all-namespaces"]
