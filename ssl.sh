#/bin/bash

USER="dsteele"
DB_PATH="/var/lib/postgresql/9.4/main"
USER_PATH="/home/$USER/.postgresql"

SERVER_HOST="server.crunchydata.com"

SUBJ="/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN="
SERVER_CNAME=$SERVER_HOST
ROOT_CNAME="root-ca"
IM_CNAME="im-ca"
CLIENT_CNAME=$USER

SIMPLE="simple"
INTERMEDIATE="intermediate"

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

    openssl x509 -req -days 1825 -CA $3.crt -CAkey $3.key -set_serial $4 \
            -in $1.csr -out $1.crt
    
    rm $1.csr
}  

# Remove current certs and keys
rm *

# Generate self-signed root CA cert
openssl req -nodes -new -sha256 -x509 -keyout $CA.key -out $CA.crt \
   -subj "$SUBJ$ROOT_CNAME"

# Generate intermediate server cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $SERVER_IM ]
    then cert $SERVER_IM "$SERVER-$IM_CNAME" $CA "01";
fi

# Generate server cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $SERVER_IM ]
    then cert $SERVER $SERVER_CNAME $SERVER_IM "02";
    else cert $SERVER $SERVER_CNAME $CA "03";
fi
#cert $SERVER $SERVER_CNAME $CA

# Generate intermediate client cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $CLIENT_IM ]
    then cert $CLIENT_IM "$CLIENT-$IM_CNAME" $CA "04";
fi

# Generate client cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $CLIENT_IM ]
    then cert $CLIENT $CLIENT_CNAME $CLIENT_IM "05";
    else cert $CLIENT $CLIENT_CNAME $CA "06";
fi

# Stop Postgres
pg_ctlcluster 9.4 main stop -m fast

# Remove old file from Postgres
rm "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"

# Move files to Postgres
# if [[ "$1" == "$INTERMEDIATE" ]]
#     then cat $CLIENT_IM.crt $CA.crt > "$DB_PATH/$CA.crt";
#     else cp $CA.crt "$DB_PATH/$CA.crt";
# fi
cp $CA.crt "$DB_PATH/$CA.crt"

cp $SERVER.key "$DB_PATH/$SERVER.key"

if [ $1 == $INTERMEDIATE ] || [ $1 == $SERVER_IM ]
    then cat $SERVER.crt $SERVER_IM.crt > "$DB_PATH/$SERVER.crt";
    else cat $SERVER.crt > "$DB_PATH/$SERVER.crt";
fi

chown postgres:postgres "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"
chmod 400 "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"

# Start postgres
pg_ctlcluster 9.4 main start

# Remove old files from user
rm "$USER_PATH/$ROOT.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"

# Move files to user
cp $CA.crt "$USER_PATH/$ROOT.crt";

cp $CLIENT.key "$USER_PATH/$POSTGRESQL.key"

if [ $1 == $INTERMEDIATE ] || [ $1 == $CLIENT_IM ]
    then cat $CLIENT.crt $CLIENT_IM.crt > "$USER_PATH/$POSTGRESQL.crt";
    else cp $CLIENT.crt "$USER_PATH/$POSTGRESQL.crt";
fi

chown $USER:root "$USER_PATH/$ROOT.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"
chmod 400 "$USER_PATH/$ROOT.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"

# Now try to connect
sudo su - $USER -c 'echo "select count(*) from pg_database" | psql -h localhost postgres'
