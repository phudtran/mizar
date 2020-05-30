FROM debian
COPY etc/docker/scripts/node-init.sh /
COPY . /var/mizar
RUN chmod u+x node-init.sh