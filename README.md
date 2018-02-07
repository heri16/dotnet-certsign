# dotnet-certsign
Minimal tool to do chain-signing of certificates with a TPM using the Windows Platform CNG Provider

## Usage

### Create CSR at certs\request.req
```
certmgr.msc
type certs\request.req
-----BEGIN CERTIFICATE REQUEST-----
MIICiDCCAXACAQAwQzEhMB8GCSqGSIb3DQEJARYSaGVyaS5zaW1AbG11LmNvLmlk
MREwDwYDVQQDDAhIZXJpIFNpbTELMAkGA1UEBhMCU0cwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDafAh2JK5jE0bzuO7LC1QF5Cv0LUQAWdflYZkzleOg
RsSGEXsbzbxHv7YlB6oLIk7pst3sQWVEINgtN2mhkIeKQYfU67gjRYWED48F8OGR
iQjvTT2htS3LGMaq178GVm63FstATc1/IT+gxPNxs1+F0GJTuuwWPzdqAiv0Fuyp
yg7tsTUgVdnz6rN+4vKG81fS1kBVx+szG1sej5q0rFw3XnSAhoB+V0C8JdnIIoNz
+BM27smYTe6WqLvfiMLu71YQE8U6SFjChM+NwUGrHI5XzUsIb0mfBB0+JmBXX6op
dlsIyAuJrh5lmQQGj3LJ2GIE3AVIR3GxKMLj3heZmXadk7xdjLoHtIk14Jhv3kPZ
w6ELIFVgCX2Sm+7OuVX36+4OUTWiTiZviynI3aZZprRByUwt0oLfCy4sAA80rpo2
s7OO/tH+r6ykAy1FXBpyfUUkMTaoX6sxQdAgHA==
-----END CERTIFICATE REQUEST-----
```

### Sign CSR at certs\request.req
```
dotnet run
```

### Check Certificate
```
certutil -dump certs\test.crt
```

### OCSP verification
```
certutil -urlcache OCSP delete
certutil -verify -urlfetch certs\test.crt
```

### PKCS12 check password 
```
certutil -dump -p secretpass certs\ospf1.pfx
```

### Build a dotnet app
https://dotnetthoughts.net/how-to-create-a-self-contained-dotnet-core-application/
