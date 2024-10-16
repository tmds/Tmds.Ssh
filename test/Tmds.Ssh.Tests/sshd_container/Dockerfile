FROM registry.fedoraproject.org/fedora:40

EXPOSE 88/tcp
EXPOSE 88/udp

# Install packages.
RUN dnf install -y krb5-{libs,server,workstation} openssh-server passwd socat dos2unix && \
    rm -rf /var/cache/yum/*

# Add a user.
RUN useradd -ms /bin/bash testuser
RUN useradd -ms /bin/bash --badname testuser@REALM.TEST
RUN echo 'secret' | passwd --stdin testuser

# Add test subsystem configuration
RUN echo 'Subsystem test_subsystem /usr/bin/sh' >> /etc/ssh/sshd_config

# Add server keys.
COPY server_key_rsa /etc/ssh/ssh_host_rsa_key
COPY server_key_ecdsa /etc/ssh/ssh_host_ecdsa_key
COPY server_key_ed25519 /etc/ssh/ssh_host_ed25519_key
RUN chmod 600 /etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key
RUN dos2unix /etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key

# Add user authorized key.
COPY user_key_rsa.pub /home/testuser/.ssh/user_key_rsa.pub
COPY user_key_ecdsa_256.pub /home/testuser/.ssh/user_key_ecdsa_256.pub
COPY user_key_ecdsa_384.pub /home/testuser/.ssh/user_key_ecdsa_384.pub
COPY user_key_ecdsa_521.pub /home/testuser/.ssh/user_key_ecdsa_521.pub
COPY user_key_ed25519.pub /home/testuser/.ssh/user_key_ed25519.pub
RUN cat /home/testuser/.ssh/user_key_*.pub > /home/testuser/.ssh/authorized_keys
RUN chown -R testuser:testuser /home/testuser/.ssh
RUN chmod 600 /home/testuser/.ssh/authorized_keys
RUN dos2unix /home/testuser/.ssh/authorized_keys

# Configure KDC and setup keytab
COPY krb5.conf /etc/krb5.conf
COPY kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
RUN echo -e "secret\nsecret" | /usr/sbin/kdb5_util create -r REALM.TEST
RUN kadmin.local -q "addprinc -pw secret testuser"
RUN kadmin.local -q "addprinc -randkey host/localhost@REALM.TEST"
RUN kadmin.local -q "ktadd -k /etc/krb5.keytab host/localhost@REALM.TEST"
RUN echo 'testuser@REALM.TEST' > /home/testuser/.k5login
RUN echo 'testuser@REALM.TEST' > /home/testuser@REALM.TEST/.k5login
COPY 90-gssapi.conf /etc/ssh/sshd_config.d/90-gssapi.conf

# Run kdc and sshd.
CMD /usr/sbin/krb5kdc && /usr/sbin/sshd -o LogLevel=DEBUG2 -De
