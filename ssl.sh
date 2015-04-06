#!/bin/bash

USER="dsteele"
DB_VERSION="9.4"
DB_CLUSTER="ssltest"
DB_BIN="/usr/lib/postgresql/$DB_VERSION/bin"
BASE_PATH=$PWD
DB_PATH="$BASE_PATH/test"
USER_PATH="/home/$USER/.postgresql"
#export OPENSSL_CONF="/home/$USER/ssl/openssl.cnf"

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
    openssl req -nodes -new -keyout $1.key -out $1.csr \
       -subj "$SUBJ$2"

    if [ $4 == "ca" ]
        then openssl x509 -extfile $OPENSSL_CONF -extensions v3_ca -req -days 1825 -CA $3.crt -CAkey $3.key -CAcreateserial -in $1.csr -out $1.crt;
        else openssl x509 -extfile $OPENSSL_CONF -extensions usr_cert -req -days 1825 -CA $3.crt -CAkey $3.key -set_serial $4 -in $1.csr -out $1.crt
    fi

    rm $1.csr
}

# Generate self-signed root CA cert
openssl req -extensions v3_ca -nodes -new -x509 -keyout $CA.key -out $CA.crt \
   -subj "$SUBJ$ROOT_CNAME"

# Generate intermediate server cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $SERVER_IM ]
    then cert $SERVER_IM "$SERVER-$IM_CNAME" $CA "ca";
fi

# Generate server cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $SERVER_IM ]
    then cert $SERVER $SERVER_CNAME $SERVER_IM "02";
    else cert $SERVER $SERVER_CNAME $CA "03";
fi

# Generate intermediate client cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $CLIENT_IM ]
    then cert $CLIENT_IM "$CLIENT-$IM_CNAME" $CA "ca";
fi

# Generate client cert
if [ $1 == $INTERMEDIATE ] || [ $1 == $CLIENT_IM ]
    then cert $CLIENT $CLIENT_CNAME $CLIENT_IM "05";
    else cert $CLIENT $CLIENT_CNAME $CA "06";
fi

# Stop the test cluster if running
$DB_BIN/pg_ctl stop -D $DB_PATH -m immediate -w
rm -rf $DB_PATH

# Create a new test cluster
mkdir $DB_PATH
$DB_BIN/initdb -D $DB_PATH -A trust
echo -e "hostssl all $USER 127.0.0.1/32 cert" > $DB_PATH/pg_hba.conf

# Move files to Postgres
cp $CA.crt "$DB_PATH/$CA.crt";
cp $SERVER.key "$DB_PATH/$SERVER.key"

if [ $1 == $INTERMEDIATE ] || [ $1 == $SERVER_IM ]
    then cat $SERVER.crt $SERVER_IM.crt $CA.crt > "$DB_PATH/$SERVER.crt";
    else cat $SERVER.crt > "$DB_PATH/$SERVER.crt";
fi

chmod 600 "$DB_PATH/$CA.crt" "$DB_PATH/$SERVER.key" "$DB_PATH/$SERVER.crt"

# Move files to user
cp $CA.crt "$USER_PATH/$ROOT.crt";

cp $CLIENT.key "$USER_PATH/$POSTGRESQL.key"

if [ $1 == $INTERMEDIATE ] || [ $1 == $CLIENT_IM ]
    then cat $CLIENT.crt $CLIENT_IM.crt $CA.crt > "$USER_PATH/$POSTGRESQL.crt";
    else cp $CLIENT.crt "$USER_PATH/$POSTGRESQL.crt";
fi

chmod 600 "$USER_PATH/$ROOT.crt" "$USER_PATH/$POSTGRESQL.key" "$USER_PATH/$POSTGRESQL.crt"

# Start postgres
$DB_BIN/pg_ctl start -D $DB_PATH -l $DB_PATH/postgresql.log -w -s -o " -c unix_socket_directories=$DB_PATH -c ssl=on -c ssl_ca_file=ca.crt -c ssl_cert_file=server.crt -c ssl_key_file=server.key"

# Now try to connect
echo "select count(*) from pg_database" | psql -p 5432 "postgresql://$SERVER_HOST/postgres?sslmode=verify-full"
