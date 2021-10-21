ARG ZENITH_TAG=
FROM ghcr.io/stackhpc/zenith-common:${ZENITH_TAG}

# Create the user that will be used to run the app
ENV APP_UID 1001
ENV APP_GID 1001
ENV APP_USER app
ENV APP_GROUP app
RUN groupadd --gid $APP_GID $APP_GROUP && \
    useradd \
      --no-create-home \
      --no-user-group \
      --gid $APP_GID \
      --shell /sbin/nologin \
      --uid $APP_UID \
      $APP_USER

# Installing dependencies separately ensures better use of the build cache
COPY requirements.txt /opt/zenith/sync/
RUN pip3 install --no-deps --requirement /opt/zenith/sync/requirements.txt

COPY . /opt/zenith/sync
RUN pip3 install --no-deps -e /opt/zenith/sync

USER $APP_UID
CMD ["zenith", "sync"]
