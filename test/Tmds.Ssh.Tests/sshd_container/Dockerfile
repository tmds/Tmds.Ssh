FROM quay.io/centos/centos:stream9

# Install packages.
RUN dnf install -y openssh-server passwd socat dos2unix && \
    rm -rf /var/cache/yum/*

# Add a user.
RUN useradd -ms /bin/bash testuser
RUN echo 'secret' | passwd --stdin testuser

# Add test subsystem configuration
RUN echo 'Subsystem tmds_test /usr/bin/sh' >> /etc/ssh/sshd_config

# Add server keys.
COPY server_key_rsa /etc/ssh/ssh_host_rsa_key
COPY server_key_ecdsa /etc/ssh/ssh_host_ecdsa_key
COPY server_key_ed25519 /etc/ssh/ssh_host_ed25519_key
RUN chmod 600 /etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key
RUN dos2unix /etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key

# Add user authorized key.
COPY user_key_rsa.pub /home/testuser/.ssh/authorized_keys
RUN chown -R testuser:testuser /home/testuser/.ssh
RUN chmod 600 /home/testuser/.ssh/authorized_keys
RUN dos2unix /home/testuser/.ssh/authorized_keys

# Run sshd.
CMD /usr/sbin/sshd -o LogLevel=DEBUG2 -De
