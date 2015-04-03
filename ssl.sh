#/bin/bash

USER="dsteele"
DB_PATH="/var/lib/postgresql/9.4/main"
USER_PATH="/home/$USER/.postgresql"
SUBJ="/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN="
SERVER_CNAME="server.crunchydata.com"
ROOT_CNAME="root-ca"
CLIENT_CNAME=$USER

CA="ca"
ROOT="root"
POSTGRESQL="postgresql"
SERVER="server"
CLIENT="client"

rm *

# generate passphrase file
echo "test" > passphrase.txt

# Generate self-signed root CA cert
openssl req -nodes -new -x509 -keyout $CA.key -out $CA.crt \
   -subj "$SUBJ$ROOT_CNAME"

# Generate server cert
openssl req -nodes -new -x509 -keyout $SERVER.key -out $SERVER.crt \
   -subj "$SUBJ$SERVER_CNAME"

openssl req -new -sha256 -days 1825 -key $SERVER.key -out $SERVER.csr \
  -subj "$SUBJ$SERVER_CNAME"

openssl x509 -req -days 1825 -CA $CA.crt -CAkey $CA.key -set_serial 01 \
        -in $SERVER.csr -out $SERVER.crt

rm server.csr

# Generate client cert
openssl req -nodes -new -x509 -keyout $CLIENT.key -out $CLIENT.crt \
   -subj "$SUBJ$CLIENT_CNAME"

openssl req -new -sha256 -days 1825 -key $CLIENT.key -out $CLIENT.csr \
   -subj "$SUBJ$CLIENT_CNAME"

openssl x509 -req -days 1825 -CA $CA.crt -CAkey $CA.key -set_serial 01 \
        -in $CLIENT.csr -out $CLIENT.crt

rm client.csr

# Stop Postgres
pg_ctlcluster 9.4 main stop -m fast

rm "$DB_PATH/$CA.crt"
rm "$DB_PATH/$SERVER.key"
rm "$DB_PATH/$SERVER.crt"

# Move files to Postgres
cp ca.crt "$DB_PATH/$CA.crt"
cp server.key "$DB_PATH/$SERVER.key"
cp server.crt "$DB_PATH/$SERVER.crt"
chown postgres:postgres "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"
chmod 400 "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"

# Start postgres
pg_ctlcluster 9.4 main start

# Remove old files from user
rm /home/dsteele/.postgresql/*

# Move files to user
cp ca.crt "$USER_PATH/$ROOT.crt"
cp client.key "$USER_PATH/$POSTGRESQL.key"
cp client.crt "$USER_PATH/$POSTGRESQL.crt"

chown $USER:root "$USER_PATH/root.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"
chmod 400 "$USER_PATH/root.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"
