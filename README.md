# ksm_server
KSM server compatible hsm for yubikey OTP (compatible with all yubikey

.env
```
USERDB=otp
PASSWORDDB=otp
DATABASE=otp
DATABASEIP=database
```
docker-compose.yml
```
version: '3.8'
services:
    ksm:
      image: ksm:latest
      container_name: ksm
      user: root
      depends_on:
        - database
      environment:
        USER: ${USERDB}
        PASSWORD: ${PASSWORDDB}
        DATABASE: ${DATABASE}
        DATABASEIP: ${DATABASEIP}
        DATABASETYPE: mysql
      command: ["/usr/bin/python3", "/etc/adacis/ksm.py", "-D", "/etc/yubico/yhsm/keys.json", "-v", "--key-handle", "1", "--addr", "0.0.0.0", "--db-url", "mysql://${USERDB}:${PASSWORDDB}@${DATABASEIP}/${DATABASE}", "--debug"]
      volumes:
        - ./conf_ksm/keys.json:/etc/yubico/yhsm/keys.json
        - ./conf_ksm/yubikey_ksm.py:/usr/local/lib/python2.7/dist-packages/pyhsm/ksm/yubikey_ksm.py
      networks:
        - auth
      ports:
        - 8002:8002

    database: 
      image: mariadb
      container_name: database
      volumes: 
        - "./data_db:/var/lib/mysql"
        - "./conf_db/replication.cnf:/etc/mysql/conf.d/replication.cnf"
      ports:
        - 3306:3306
      environment:
        MYSQL_ROOT_PASSWORD: ${PASSWORDDB}
        MYSQL_DATABASE: ${DATABASE}
        MYSQL_USER: ${USERDB}
        MYSQL_PASSWORD: ${PASSWORDDB}
      networks:
        - auth

    phpmyadmin:
      image: phpmyadmin
      environment: 
        PMA_ARBITRARY: 1
      ports:
        - 8080:80
      networks:
        - auth
```
