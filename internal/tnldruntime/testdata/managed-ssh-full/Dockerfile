FROM mirror.gcr.io/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61

RUN groupadd --gid 21001 tnl-ssh-test && \
    groupadd --gid 21002 tnl-ssh-extra && \
    groupadd --gid 21003 tnl-ssh-other && \
    useradd --no-log-init --create-home --uid 21001 --gid 21001 --groups 21002 --shell /bin/sh tnl-ssh-test && \
    useradd --no-log-init --create-home --uid 21003 --gid 21003 --shell /bin/sh tnl-ssh-other && \
    touch /run/tnl-managedssh-fixture

ENV PATH="/fixture:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENTRYPOINT ["/fixture/tnldruntime.test"]
