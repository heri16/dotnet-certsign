# dotnet-certsign
Minimal tool to do chain-signing of certificates with a TPM using the Windows Platform CNG Provider

## Usage

### Sign CSR at certs/request.req
dotnet run

### Check Certificate
certutil -dump certs\eko.crt

### OCSP verification
certutil -verify -urlfetch certs\yulia.crt

### PKCS12 check password 
certutil -dump -p secretpass certs\ospf1.pfx

### Build a dotnet app
https://dotnetthoughts.net/how-to-create-a-self-contained-dotnet-core-application/
