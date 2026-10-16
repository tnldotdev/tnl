FROM mirror.gcr.io/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61

RUN groupadd --gid 21001 tnl-ssh-test && \
    groupadd --gid 21002 tnl-ssh-extra && \
    useradd --no-log-init --create-home --uid 21001 --gid 21001 --groups 21002 --shell /bin/sh tnl-ssh-test && \
    useradd --no-log-init --non-unique --uid 0 --gid 0 --shell /bin/sh tnl-ssh-root-alias && \
    touch /run/tnl-managedssh-fixture

ENTRYPOINT ["/managedssh.test", "-test.run=^TestIntegrationManagedSSHRoot$", "-test.v", "-test.timeout=60s", "-tnl-test-tier=integration", "-tnl-test-managed-ssh-root-user=tnl-ssh-test"]
