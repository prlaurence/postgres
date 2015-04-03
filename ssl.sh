#/bin/bash

USER="dsteele"
DB_PATH="/var/lib/postgresql/9.4/main"
USER_PATH="/home/$USER/.postgresql"
SUBJ="/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN="
SERVER_CNAME="server.crunchydata.com"
ROOT_CNAME="root-ca"
CLIENT_CNAME=$USER

rm *

# generate passphrase file
echo "test" > passphrase.txt

# Generate self-signed root CA cert
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt \
   -subj "$SUBJ$ROOT_CNAME"

# Generate server cert
openssl req -nodes -new -x509 -keyout server.key -out server.crt \
   -subj "$SUBJ$SERVER_CNAME"

openssl req -new -sha256 -days 1825 -key server.key -out server.csr \
  -subj "$SUBJ$SERVER_CNAME"

openssl x509 -req -days 1825 -CA ca.crt -CAkey ca.key -set_serial 01 \
        -in server.csr -out server.crt

rm server.csr

# Generate client cert
openssl req -nodes -new -x509 -keyout client.key -out client.crt \
   -subj "$SUBJ$CLIENT_CNAME"

openssl req -new -sha256 -days 1825 -key client.key -out client.csr \
   -subj "$SUBJ$CLIENT_CNAME"

openssl x509 -req -days 1825 -CA ca.crt -CAkey ca.key -set_serial 01 \
        -in client.csr -out client.crt

rm client.csr

# Move files to Postgres
cp ca.crt "$DB_PATH/ca.crt"
cp server.key "$DB_PATH/server.key"
cp server.crt "$DB_PATH/server.crt"
chown postgres:postgres "$DB_PATH/ca.crt" "$DB_PATH/server.key" "$DB_PATH/server.crt"
chmod 400 "$DB_PATH/ca.crt" "$DB_PATH/server.key" "$DB_PATH/server.crt"

# Move files to user
cp ca.crt "$USER_PATH/root.crt"
cp client.key "$USER_PATH/postgresql.key"
cp client.crt "$USER_PATH/postgresql.crt"

chown dsteele:root "$USER_PATH/root.crt" "$USER_PATH/postgresql.key" "$USER_PATH/postgresql.crt"
chmod 400 "$USER_PATH/root.crt" "$USER_PATH/postgresql.key" "$USER_PATH/postgresql.crt"

# Restart postgres
pg_ctlcluster 9.4 main restart