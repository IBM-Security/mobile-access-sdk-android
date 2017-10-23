# Code snippets

## Requirements
Some Android API methods require a [Context](https://developer.android.com/reference/android/content/Context.html) object as a parameter. The SDK has a ```ContextHelper``` class, which holds an application context object. You only have to set it once (as early as possible within your application) and the SDK will retrieve it from there whenever it's needed.

Set the application context:
```java
    // call this as early as possible in your application
    ContextHelper.sharedInstance().setContext(getApplicationContext());
```


## <a name="oauthtoken"></a>Get an OAuth token
The SDK supports the ROPC grant flow.


```java
public void getOAuthToken() {

    final String username = "testuser1";
    final String password = "passw0rd";
    final String hostname = "https://sdk.securitypoc.com/mga/sps/oauth/oauth20/token"
    final String clientId = "IBMVerifySDK"
    final OAuthToken[1] oAuthToken;

    AsyncTask<Void, Void, Void> getOAuthTokenTask = new AsyncTask<Void, Void, Void>() {

        @Override
        protected Void doInBackground(Void... voids) {

            OAuthContext.sharedInstance().getAccessToken(hostname, clientId, username, password, new IAuthenticationCallback() {
                @Override
                public void handleResult(final OAuthResult oAuthResult) {

                    if (oAuthResult.hasError()) {
                        showToast("Something went wrong");
                    } else {
                        oAuthToken[0] = oAuthResult.serializeToToken();
                    }
                }
            });

            return null;
        }
    }.execute();
}

```


## <a name="keypairgen"></a>Key pair generation
Key pairs are used in the SDK to sign challenges, coming from IBM Security Access Manager. The private key remains on the device, whereas the public key gets uploaded to the server as part of the mechanisms enrollment.
The Algorithm used is SHA256withRSA with a Keysize of 2048 and the key pairs are stored in the Android Keystore. 
```java
/**
  Generates a key pair
 */
private void generateKeyPair(final String keyName) {
    final KeyStoreHelper keyStoreHelper = new KeyStoreHelper();
    final boolean requiresAuthentication = false;

    final PublicKey[] publicKey = new PublicKey[1];

    AsyncTask<Void, Void, Void> generateKeyPairTask = new AsyncTask<Void, Void, Void>() {

        @Override
        protected Void doInBackground(Void... voids) {

            keyStoreHelper.createKeyPair(keyName, requiresAuthentication, new IKeyStoreHelperCallbackHandleResult() {
                @Override
                public void handleKeyPairResult(Boolean aBoolean, PublicKey myPublicKey) {

                  publicKey[0] = myPublicKey;
                  // key can be also retrieved later with KeyStoreHelper().exportPublicKey(keyName)
                }
            });

            return null;
        }
    }.execute();
}

private void deleteKeyPair(final String keyName)  {
    KeyStoreHelper.deleteKeyPair(keyName, new IKeyStoreHelperCallbackHandleDelKeyPair() {
        @Override
        public void handleDelKeyPair(Boolean aBoolean) {
            if (aBoolean)
              showToast("Key pair deleted");
            else
              showToast("Something went wrong");
        }
    });
}
```


## <a name="signdata"></a>Signing data
The public key would be stored on a server and provide the challenge text to the client. The client uses the private key to sign the data which is sent back to the server. The server validates the signed data against the public key to verify the keys have not been tampered with.

```java
private void signData()  {

    final String keyName = "mySampleKey";

    generateKeyPair(keyName);
    Log.d("Signed data: ", KeyStoreHelper.signData(keyName, "hello world");
    deleteKeyPair(keyName);
}
```

## <a name="certpin"></a>Certificate pinning
Certificate pinning enables setting a custom CA or certificate as permitted in your app.

Certificate pinning can be useful in two major cases:
- enabling self-signed certificates on development servers.
- ensuring that only certificates you have pinned to the app are trusted.

The `ChallengeContext`, `OAuthContext` and `MfaRegistrationContext` classes contain two relevant attributes: [SSLContext](https://developer.android.com/reference/javax/net/ssl/SSLContext.html) and [HostnameVerifier](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier.html).

### Downloading the certificate
Working with a development server, the following is the easiest way to download a certificate chain:
```sh
# for DER:
openssl s_client -connect <host>:<port> -showcerts 2>/dev/null </dev/null | openssl x509 -inform pem -outform der -out <certificate-name>.der

# for PEM:
openssl s_client -connect <host>:<port> -showcerts 2>/dev/null </dev/null | openssl x509 -inform pem -outform pem -out <certificate-name>.pem
```

#### Pin a custom CA
This sample pins a root CA which it loads from a file.
```java
private final String certificatePath = "my-server-certificate.crt";
private final String expectedHostname = "192.168.1.99";

ChallengeContext.sharedInstance().setSslContext(makeSslContext(certificatePath));
ChallengeContext.sharedInstance().setHostnameVerifier(makeHostnameVerifier(expectedHostname));

HostnameVerifier makeHostnameVerifier(String expectedHostname) {
    return new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return hostname.equalsIgnoreCase(expectedHostname);
        }
    };
}

SSLContext makeSslContext(String filename) {
    InputStream caInput = null;
    SSLContext context = null;
    try {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream in = getClass().getClassLoader().getResourceAsStream(filename);
        caInput = new BufferedInputStream(in);
        final Certificate ca;

        ca = cf.generateCertificate(caInput);
        Log.d("Certificate pinning", "makeSslContext: ca=" + ((X509Certificate) ca).getSubjectDN());

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("our trusted CA", ca);

        TrustManager customTrustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("This doesn't need to ever succeed");
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                byte[] found = chain[0].getEncoded();
                byte[] wanted = ca.getEncoded();
                if (!Arrays.equals(found, wanted)) {
                    throw new CertificateException("Presented certificate didn't match pinned certificate");
                }
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

    } finally {
        if (caInput != null) try { caInput.close(); }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
    return context;
}
```

#### Allow all connections
Be careful when you do this, as it basically turns off SSL checks.

```java
ChallengeContext.sharedInstance().setSslContext(makeAlwaysVerifySslContext());

public static SSLContext makeAlwaysVerifySSLContext() {
    try {
        SSLContext sc = SSLContext.getInstance("TLS");
        TrustManager[] trustUnconditionally = {new AlwaysApproveTrustManager()};
        sc.init(null, trustUnconditionally, new java.security.SecureRandom());
        return sc;
    } catch (KeyManagementException | NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
    }
}

public static class AlwaysApproveTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        throw new CertificateException("This doesn't need to ever succeed");
    }

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
