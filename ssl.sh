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
SERVER_IM="server-intermediate"
CLIENT="client"
CLIENT_IM="client-intermediate"

function cert
{
    openssl req -nodes -new -x509 -keyout $1.key -out $1.crt \
       -subj "$SUBJ$2"

    openssl req -new -sha256 -days 1825 -key $1.key -out $1.csr \
      -subj "$SUBJ$2"

    openssl x509 -req -days 1825 -CA $3.crt -CAkey $3.key -set_serial 01 \
            -in $1.csr -out $1.crt
    
    rm $1.csr
}  

# Remove current certs and keys
rm *

# generate passphrase file
echo "test" > passphrase.txt

# Generate self-signed root CA cert
openssl req -nodes -new -x509 -keyout $CA.key -out $CA.crt \
   -subj "$SUBJ$ROOT_CNAME"

# Generate server cert
cert $SERVER $SERVER_CNAME $CA

# Generate client cert
cert $CLIENT $CLIENT_CNAME $CA

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
