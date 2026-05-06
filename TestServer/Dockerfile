# syntax=docker/dockerfile:1
FROM debian:testing

RUN apt-get update && \
    apt-get install -y --no-install-recommends samba && \
    rm -rf /var/lib/apt/lists/*

# Create system users
RUN useradd -M -s /usr/sbin/nologin smbuser && \
    useradd -M -s /usr/sbin/nologin smbadmin

# Set passwords
RUN echo "smbuser:smbpass123" | chpasswd && \
    echo "smbadmin:smbadmin123" | chpasswd

# Configure Samba (must be in place before smbpasswd)
COPY --chmod=644 <<'SMB_CONF' /etc/samba/smb.conf
[global]
    workgroup = WORKGROUP
    server string = SwiftSMB Test Server
    server role = standalone server
    log file = /var/log/samba/log.%m
    max log size = 50
    dns proxy = no
    smb ports = 445
    min protocol = SMB2
    map to guest = Bad User
    nt pipe support = yes

[public]
    path = /shares/public
    browseable = yes
    read only = no
    guest ok = yes
    force user = smbuser
    create mask = 0644
    directory mask = 0755

[private]
    path = /shares/private
    browseable = yes
    read only = no
    guest ok = no
    valid users = smbuser, smbadmin
    create mask = 0644
    directory mask = 0755

[readonly]
    path = /shares/readonly
    browseable = yes
    read only = yes
    guest ok = yes

[hidden$]
    path = /shares/hidden
    browseable = no
    read only = no
    valid users = smbadmin
    force user = smbadmin
    create mask = 0644
    directory mask = 0755
SMB_CONF

# Create Samba users
RUN printf "smbpass123\nsmbpass123\n" | smbpasswd -a smbuser -s && \
    printf "smbadmin123\nsmbadmin123\n" | smbpasswd -a smbadmin -s

# Create share directories
RUN mkdir -p /shares/public && \
    mkdir -p /shares/private && \
    mkdir -p /shares/readonly && \
    mkdir -p /shares/hidden

# Set ownership and permissions
RUN chown -R smbuser:smbuser /shares/private && \
    chown -R smbuser:smbuser /shares/public && \
    chown -R smbadmin:smbadmin /shares/readonly && \
    chown -R smbuser:smbuser /shares/hidden && \
    chmod -R 755 /shares && \
    chmod 555 /shares/readonly

# Create test files and directories
RUN mkdir -p /shares/public/testdir/subdir && \
    echo "Hello, SMB!" > /shares/public/testdir/hello.txt && \
    echo "nested content" > /shares/public/testdir/subdir/nested.dat && \
    mkdir -p /shares/public/empty_dir && \
    ln -s /shares/public/testdir/hello.txt /shares/public/testdir/link_to_file && \
    ln -s /shares/public/testdir/subdir /shares/public/testdir/link_to_dir && \
    echo "readme" > /shares/readonly/readme.txt && \
    echo "private file" > /shares/private/secret.txt && \
    awk 'BEGIN{n=5*1024*1024;for(i=0;i<n;i++)printf "%c",i%251}' > /shares/private/largefile.bin && \
    echo "hidden file" > /shares/hidden/hidden.txt

EXPOSE 445

CMD ["smbd", "--foreground", "--no-process-group", "--debuglevel=1"]