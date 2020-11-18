FROM ubuntu:18.04

ARG BUILD_DATE

LABEL maintainer="b.aimard@adacis.net"
LABEL build_date="${BUILD_DATE}"

#Installation des paquets
RUN apt update; apt upgrade -y; apt-get install python3-software-properties software-properties-common -y; add-apt-repository ppa:yubico/stable -y ; apt-get update 
RUN apt-get install yhsm-yubikey-ksm python-pymysql -y

#Création des ressources
RUN mkdir -p /etc/yubico/yhsm

# VERSION FICHIER
#CMD ["yhsm-yubikey-ksm", "-D", "/etc/yubico/yhsm/keys.json", "-v",  "--key-handle", "1", "--addr", "0.0.0.0"]

# ALTERNATIVE BDD
CMD ["yhsm-yubikey-ksm", "-D", "/dev/ttyACM0", "-v", "--key-handle", "1", "--addr", "0.0.0.0", "--db-url", "mysql://otp:otp@database/otp", "--debug"]
