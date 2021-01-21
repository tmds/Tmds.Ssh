FROM centos:8

# Install packages.
RUN dnf install -y openssh-server passwd && \
    rm -rf /var/cache/yum/*

# Add a user.
RUN useradd -ms /bin/bash testuser
RUN echo 'secret' | passwd --stdin testuser

# Add server keys.
COPY server_key_rsa /etc/ssh/ssh_host_rsa_key
COPY server_key_ecdsa /etc/ssh/ssh_host_ecdsa_key
COPY server_key_ed25519 /etc/ssh/ssh_host_ed25519_key

# Add user authorized key.
COPY user_key_rsa.pub /home/testuser/.ssh/authorized_keys

# Needed for sshd to start.
RUN rm /run/nologin

# Run sshd.
CMD /usr/sbin/sshd -o LogLevel=DEBUG3 -De
