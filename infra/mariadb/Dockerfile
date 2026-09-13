# MariaDB with our configuration and seed scripts baked in.
#
# These were bind-mounted from the host until 0.26.4. That works on Linux
# and is a recurring source of failure on Docker Desktop for Windows,
# where a bind mount goes through a WSL2 shim that gets into a state
# where it reports:
#
#   error while creating mount source path
#   '/run/desktop/mnt/host/d/...': mkdir /run/desktop/mnt/host/d: file exists
#
# The usual trigger is the machine sleeping, or a non-C: drive. The usual
# fix is `wsl --shutdown` plus a Docker Desktop restart, which is a poor
# thing to ask of someone on their first run.
#
# All three mounts were read-only configuration. Copying them into the
# image removes the failure mode entirely rather than documenting a
# workaround for it — the files change when the repository changes, which
# is exactly when an image rebuild happens anyway.
FROM mariadb:11.4

COPY conf.d/ /etc/mysql/mariadb.conf.d/
COPY init/ /docker-entrypoint-initdb.d/
