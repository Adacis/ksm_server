#/usr/bin/python3 /etc/adacis/ksm.py -D /etc/yubico/yhsm/keys.json -v --key-handle 1 --addr 0.0.0.0
FROM debian

ARG BUILD_DATE

LABEL maintainer="b.aimard@adacis.net"
LABEL build_date="${BUILD_DATE}"

#Installation des paquets
#RUN apt update; apt upgrade -y; apt-get install python3-software-properties software-properties-common -y; add-apt-repository ppa:yubico/stable -y ; apt-get update 
#RUN apt-get install yhsm-yubikey-ksm python-pymysql -y

#old

# RUN apt update && apt install -y python2 python-pip-whl python-pymysql default-mysql-client libmariadbclient-dev
# RUN pip install pyhsm[db,daemon]
# RUN pip install sqlalchemy
# RUN pip install mysqlclient

# new
#####
RUN apt update
RUN apt install -y python3 python3-pymysql python3-pip default-mysql-client mariadb-client python3-mysqldb
RUN pip install python-daemon sqlalchemy db pycrypto
RUN pip install chardet
RUN mkdir -p /etc/adacis
COPY ./src/*.py /etc/adacis/
#######

#Création des ressources
RUN mkdir -p /etc/yubico/yhsm

COPY ./generateKey.sh /etc/yubico/yhsm
COPY ./generate_keys_bdd.py /etc/yubico/yhsm
COPY ./decrypt_aead_bdd.py /etc/yubico/yhsm

#DEV
RUN mkdir -p /var/cache/yubikey-ksm/aeads
RUN cd /etc/yubico/yhsm ; ./generateKey.sh
# VERSION FICHIER
CMD ["yhsm-yubikey-ksm", "-D", "/etc/yubico/yhsm/keys.json", "-v",  "--key-handle", "1", "--addr", "0.0.0.0"]

# ALTERNATIVE BDD
#CMD ["yhsm-yubikey-ksm", "-D", "/dev/ttyACM0", "-v", "--key-handle", "1", "--addr", "0.0.0.0", "--db-url", "mysql://otp:otp@database/otp", "--debug"]
