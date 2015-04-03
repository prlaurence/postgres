# PostgresSQL SSL Configuration

These instructions will guide you through the process of configuring PostgreSQL to use SSL for secure connections.  We'll be placing an intermediate CA in the chain of trust.  While this is not strictly necessary, it is a good idea as it allows you to keep your root CA certificate safe (i.e. offline).  In the case of a security breach only the intermediate certificate needs to be revoked.

??? We'll create a self-signed root CA for the purpose of demonstration, but feel free to substitute your own root CA 

## Creating certificates

### Create a self-signed CA (optional)

You will likely have a certificate signed by a trusted CA, but for some installations or to just try out these intructions you may want to create a self-signed certificate.

* Create a private key:
```
openssl genrsa -aes256 -out ca.key 4096
```
You'll be required to enter a passphrase.  This should be long and guarded well.

* Create a self-signed certificate:
```
openssl req -new -x509 -sha256 -days 1825 -key ca.key -out ca.crt \
  -subj "/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN=root.crunchydata.com"
```

### Create the intermediate CAs

Now that the root CA is worked out, you'll create the intermediate CAs that will be used to sign server and client certificates.

* Create the server intermediate private key;
```
openssl genrsa -aes256 -out server-intermediate.key 4096
```
You'll be required to enter a passphrase.  Don't reuse the passphrase from your root key.

* Create the server intermediate certificate signing request (CSR):
```
openssl req -new -sha256 -days 1825 -key server-intermediate.key -out server-intermediate.csr \
  -subj "/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN=server.crunchydata.com"
```

* Create the server intermediate certificate by signing with the CA certificate:
```
openssl x509 -req -days 1825 -CA ca.crt -CAkey ca.key -set_serial 01 \
        -in server-intermediate.csr -out server-intermediate.crt
```

* Now repeat the process to create the client intermediate CA:
```
openssl genrsa -aes256 -out client-intermediate.key 4096

openssl req -new -sha256 -days 1825 -key client-intermediate.key -out client-intermediate.csr \
  -subj "/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN=client.crunchydata.com"

openssl x509 -req -days 1825 -CA ca.crt -CAkey ca.key -set_serial 01 \
        -in client-intermediate.csr -out client-intermediate.crt
```

### Create server/client certificate

Server and client certificates are created in exactly the same way as the intermediate CAs except that the intermediate CA is used to sign them instead of the root CA.  Additionally, the common name on server certificates must match the hostname of the server.

* Create a server certificate:
```
openssl genrsa -aes256 -out server.key 4096

openssl req -new -sha256 -days 1825 -key server.key -out server.csr \
  -subj "/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN=server.crunchydata.com"

openssl x509 -req -days 1825 -CA server-intermediate.crt -CAkey server-intermediate.key -set_serial 01 \
        -in server.csr -out server.crt
```

* Create a client certificate:
```
openssl genrsa -aes256 -out client.key 4096

openssl req -new -sha256 -days 1825 -key client.key -out client.csr \
  -subj "/C=US/ST=VA/L=Arlington/O=Crunchy Data Solutions/CN=dsteele"

openssl x509 -req -days 1825 -CA client-intermediate.crt -CAkey client-intermediate.key -set_serial 01 \
        -in client.csr -out client.crt
```

## Configuring PostgreSQL

### Server Configuration

The examples below will use `/var/lib/postgresql/9.4/main` as the `data_directory` setting in `postgresql.conf`.

* You must remove the passphrase from the server key in order for PostgreSQL to start automatically:
```
openssl rsa -in server.key -out /var/lib/postgresql/9.4/main/server.key
```
* Copy the root CA
```
cp ca.crt /var/lib/postgresql/9.4/main/ca.crt
```
* Both the server-intermediate and server certificates need to be copied to server.crt
```
cat server.crt server-intermediate.crt > /var/lib/postgresql/9.4/main/server.crt
```
* Set permissions
```
chown postgres:postgres \
      /var/lib/postgresql/9.4/main/ca.crt \
      /var/lib/postgresql/9.4/main/server.crt \
      /var/lib/postgresql/9.4/main/server.key

chmod 600 \
      /var/lib/postgresql/9.4/main/ca.crt \
      /var/lib/postgresql/9.4/main/server.crt \
      /var/lib/postgresql/9.4/main/server.key
```
* Now configure /etc/postgresql/9.4/main with the SSL settings:

ssl=true
ssl_cert_file=server.crt
ssl_key_file=server.key
ssl_ca_file=ca.crt

* Restart the server for settings to take effect.

### Client Configuration

