# Insecure Dockerfile with multiple security misconfigurations
FROM ubuntu:latest

ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

WORKDIR /root

ADD https://example.com/downloads/archive.tar.gz /tmp/
ADD local_file.tar.gz /opt/
COPY script.sh /usr/local/bin/

EXPOSE 22
EXPOSE 80 443/tcp

# Intentionally missing USER instruction (runs as root)

CMD ["/bin/bash"]
