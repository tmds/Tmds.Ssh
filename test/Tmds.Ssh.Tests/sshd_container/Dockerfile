ARG PASSWORD=secret

FROM quay.io/centos/centos:stream10

ARG PASSWORD

EXPOSE 88/tcp
EXPOSE 88/udp

# Install packages.
RUN dnf install -y krb5-{libs,server,workstation} openssh-server passwd socat dos2unix && \
    rm -rf /var/cache/yum/*

# Add a user.
RUN useradd -ms /bin/bash testuser
RUN useradd -ms /bin/bash --badname testuser@REALM.TEST
RUN [ -z "$PASSWORD" ] && passwd --delete testuser || echo "$PASSWORD" | passwd --stdin testuser

# Add test subsystem configuration
RUN echo 'Subsystem test_subsystem /usr/bin/sh' >> /etc/ssh/sshd_config

# Add server keys.
COPY server_key_* /etc/ssh
COPY ca.pub /etc/ssh/user_ca.pub
RUN chmod 600 /etc/ssh/server_key_* && dos2unix /etc/ssh/server_key_*
COPY 91-keys.conf /etc/ssh/sshd_config.d/91-keys.conf

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

# Disable PAM.
RUN sed -i 's/UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config.d/50-redhat.conf

# Remove custom crypto policies.
RUN rm /etc/ssh/sshd_config.d/40-redhat-crypto-policies.conf

# Disable penalties.
RUN echo 'PerSourcePenaltyExemptList "0.0.0.0/0,::/0"' > /etc/ssh/sshd_config.d/99-no-per-source-penalty.conf
# Accept TEST_ENVVAR.
RUN echo 'AcceptEnv TEST_ENVVAR' > /etc/ssh/sshd_config.d/99-accept-envvar.conf

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
