#/bin/bash

USER="dsteele"
DB_PATH="/var/lib/postgresql/9.4/main"
USER_PATH="/home/$USER/.postgresql"

SUBJ="/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN="
SERVER_CNAME="server.crunchydata.com"
ROOT_CNAME="root-ca"
IM_CNAME="im-ca"
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

# Generate intermediate server cert
cert $SERVER_IM "$SERVER-$IM_CNAME" $CA

# Generate server cert
#cert $SERVER $SERVER_CNAME $SERVER_IM
cert $SERVER $SERVER_CNAME $CA

# Generate intermediate client cert
cert $CLIENT_IM "$CLIENT-$IM_CNAME" $CA

# Generate client cert
#cert $CLIENT $CLIENT_CNAME $CLIENT_IM
cert $CLIENT $CLIENT_CNAME $CA

# Stop Postgres
pg_ctlcluster 9.4 main stop -m fast

# Remove old file from Postgres
rm "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"

# Move files to Postgres
cp $CA.crt "$DB_PATH/$CA.crt"
cp $SERVER.key "$DB_PATH/$SERVER.key"
#cat $SERVER.crt $SERVER_IM.crt > "$DB_PATH/$SERVER.crt"
cat $SERVER.crt > "$DB_PATH/$SERVER.crt"
chown postgres:postgres "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"
chmod 400 "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"

# Start postgres
pg_ctlcluster 9.4 main start

# Remove old files from user
rm "$USER_PATH/$ROOT.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"

# Move files to user
cp $CA.crt "$USER_PATH/$ROOT.crt"
cp $CLIENT.key "$USER_PATH/$POSTGRESQL.key"
#cat $CLIENT.crt $CLIENT_IM.crt > "$USER_PATH/$POSTGRESQL.crt"
cat $CLIENT.crt > "$USER_PATH/$POSTGRESQL.crt"

chown $USER:root "$USER_PATH/$ROOT.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"
chmod 400 "$USER_PATH/$ROOT.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"
