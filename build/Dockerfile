#/usr/bin/python3 /etc/adacis/ksm.py -D /etc/yubico/yhsm/keys.json -v --key-handle 1 --addr 0.0.0.0
FROM debian

ARG BUILD_DATE

LABEL maintainer="b.aimard@adacis.net"
LABEL build_date="${BUILD_DATE}"

RUN apt update; apt upgrade -y

RUN apt install -y \
            python3 \
            python3-pymysql \
            python3-pip \
            default-mysql-client \
            mariadb-client \
            python3-mysqldb

RUN pip install \
            python-daemon \
            sqlalchemy \
            db \
            pycrypto \
            chardet

RUN mkdir -p /etc/adacis ; mkdir -p /etc/yubico/yhsm

COPY ./src /etc/adacis/

CMD ["yhsm-yubikey-ksm", "-D", "/etc/yubico/yhsm/keys.json", "-v",  "--key-handle", "1", "--addr", "0.0.0.0"]

# ALTERNATIVE BDD
#CMD ["yhsm-yubikey-ksm", "-D", "/dev/ttyACM0", "-v", "--key-handle", "1", "--addr", "0.0.0.0", "--db-url", "mysql://otp:otp@database/otp", "--debug"]
