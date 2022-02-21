# ksm_server
Server as Key System Manager (KSM), for YUBIOTP embeded in yubikey. (Becarefull you certainely need a validation server)

## How to

### Directory configuration

First walk into example folder there are : 
- conf_ksm: contains secret AESKEY to encrypt all yubikey synchronous secret
- data_db: for the persistence of database data
- aead_table.sql: create aead table that is used by the KSM server
- docker-compose.yml: example of docker-compose file
- generateKey.sh: that allow to generate an AES key

### step by step

#### Create .env file

.env
```
USERDB=otp
PASSWORDDB=otp
DATABASE=otp
DATABASEIP=database
```

#### Configure KSM:

```
git clone https://github.com/Adacis/ksm_server.git
cd ksm_server
chmod +x generateKey.sh
./generateKey.sh
mv keys.json conf_ksm
```

#### Start project:

```
docker-compose up -d
```

#### Create table

```
docker exec -u mysql -i database bash -c 'mariadb -u${MYSQL_USER} -p${MYSQL_PASSWORD} ${MYSQL_DATABASE}' < aead_table.sql
```

#### Generate new secret
```
docker exec -it ksm python3 /etc/adacis/generate_keys_bdd.py -D /etc/yubico/yhsm/keys.json --key-handle 1 -c 1
```

#### Generate yubico configuration
```
docker exec -it ksm python3 /etc/adacis/decrypt_aead_bdd.py -D /etc/yubico/yhsm/keys.json --public-id <public_id generate in the step before (see in database)>
```
so :

```
docker exec -it ksm python3 /etc/adacis/decrypt_aead_bdd.py -D /etc/yubico/yhsm/keys.json --public-id cccccccccccb
```

output very secret line : 
```
ykpersonalize -1 -ofixed=cccccccccccb -ouid=457e1ef96f98 -ac7a239873d5fe8aaa9f48a330d1e309
```

#### Configure hardware yubikey
you can install both package :
```
sudo apt install ykman yubikey-personalization
```

```
ykpersonalize -1 -ofixed=cccccccccccb -ouid=457e1ef96f98 -ac7a239873d5fe8aaa09f48a330d1e309
```

or 

```
ykman otp yubiotp 2 -P cccccccccccb -p 457e1ef96f98 -k c7a239873d5fe8ddd09f48a330d1e309
```