# Certificate pinning
Certificate pinning is the practice of setting a custom CA or certificate as permitted in your app.

Certificate pinning can be useful in two major cases:
- In development: enabling self-signed certificates on development servers.
- In production: ensuring that only certificates *you've* pinned to the app are trusted. If some other CA is breached and starts issuing certificates for isam.yourservice.com, you are protected.

Please refer to the relevant platform documentation for best practices.

## Downloading the certificate
If you're working with a development server, this is the easiest way to download a certificate chain:
```sh
# for DER:
openssl s_client -connect <host>:<port> -showcerts 2>/dev/null </dev/null | openssl x509 -inform pem -outform der -out <certificate-name>.der
# for PEM:
openssl s_client -connect <host>:<port> -showcerts 2>/dev/null </dev/null | openssl x509 -inform pem -outform pem -out <certificate-name>.pem
```

## Certificate pinning in Android

> Need to [download your server's certificate](README.md#downloading-the-certificate)?

Our `Context` classes take two components: an [SSLContext](https://developer.android.com/reference/javax/net/ssl/SSLContext.html) and a [HostnameVerifier](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier.html).

Refer to the [Android security documentation](https://developer.android.com/training/articles/security-ssl.html) for more information.

### Pin a custom CA
This sample pins a root CA which it loads from a file.
```java
final String certificatePath = "my-server-certificate.crt";
final String expectedHostname = "192.168.1.99";

ChallengeContext.sharedInstance().setSslContext(makeSslContext(certificatePath));
ChallengeContext.sharedInstance().setHostnameVerifier(makeHostnameVerifier(expectedHostname));

/* Creates a HostnameVerifier which demands a specific hostname.
   Note that this isn't often necessary: https://developer.android.com/training/articles/security-ssl.html#CommonHostnameProbs
*/
HostnameVerifier makeHostnameVerifier(String expectedHostname) {
    return new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return hostname.equalsIgnoreCase(expectedHostname);
        }
    };
}

/* Creates an SSLContext which pins a root CA. Loads the certificate from file. */
SSLContext makeSslContext(String filename) {
    InputStream caInput = null;
    SSLContext context = null;
    try {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream in = getClass().getClassLoader().getResourceAsStream(filename);
        caInput = new BufferedInputStream(in);
        final Certificate ca; // the Certificate Authority we trust (loaded from file)
        ca = cf.generateCertificate(caInput);
        Log.d("test", "makeSslContext: ca=" + ((X509Certificate) ca).getSubjectDN());

        KeyStore keyStore // a KeyStore containing our CA, which is how a TrustManager takes it
            = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("our trusted CA", ca);

        TrustManager customTrustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("This doesn't need to ever succeed");
            }

            /* This is the important part. We compare certificates as byte arrays. */
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                byte[] found = chain[0].getEncoded(); // checking the first certificate means we've pinned a root CA (incl. self-signed)
                byte[] wanted = ca.getEncoded();
                if (!Arrays.equals(found, wanted)) {
                    throw new CertificateException("Presented certificate didn't match pinned certificate");
                }
                // else return, which means "OK"
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {customTrustManager}, null);

    } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | IOException | KeyManagementException e) {
        e.printStackTrace();
        /* Handle these gracefully. */
    } finally {
        if (caInput != null) try { caInput.close(); }
        catch (IOException e) {
            /* an error closing it probably doesn't matter */
            e.printStackTrace();
        }
    }
    return context;
}
```

### Allow all connections
You should only do this during development, and even then, it's usually better to pin the certificate of your development server.

```java
// configuring the SDK:
ChallengeContext.sharedInstance().setSslContext(makeAlwaysVerifySslContext());

/* For test use only! Slot it into our *Context classes. */
public static SSLContext makeAlwaysVerifySSLContext() {
    try {
        SSLContext sc = SSLContext.getInstance("TLS");
        TrustManager[] trustUnconditionally = {new AlwaysApproveTrustManager()};
        sc.init(null, trustUnconditionally, new java.security.SecureRandom());
        return sc;
    } catch (KeyManagementException | NoSuchAlgorithmException e) {
        throw new RuntimeException(e); // this should be static & safe
    }
}

// A TrustManager which approves SSL connections.
public static class AlwaysApproveTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        throw new CertificateException("This doesn't need to ever succeed");
    }

    /* Returning from this method (not throwing CertificateException) will approve the connection. */
    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        return;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
```
