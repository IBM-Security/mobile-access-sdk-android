package com.ibm.security.demoapps.passwordpolicy;

import android.app.Activity;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.view.Gravity;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.ibm.security.access.mobile.authentication.ChallengeContext;
import com.ibm.security.access.mobile.authentication.ChallengeResult;
import com.ibm.security.access.mobile.authentication.ContextHelper;
import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.IChallenge;
import com.ibm.security.access.mobile.authentication.IChallengeCallbackHandleResult;
import com.ibm.security.access.mobile.authentication.IChallengeCallbackHandleUserInput;
import com.ibm.security.access.mobile.authentication.IChallengeCallbackHandleVerify;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.OAuthToken;
import com.ibm.security.access.mobile.authentication.UsernamePasswordChallenge;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends AppCompatActivity {

    private Activity activity;
    private OAuthToken oAuthToken;
    private String hostname = "https://sdk.securitypoc.com/mga/sps/oauth/oauth20/token";
    private String policyUrl = "https://sdk.securitypoc.com/mga/sps/apiauthsvc?PolicyId=urn:ibm:security:authentication:asf:password";
    private String clientId = "IBMVerifySDK";

    private EditText etUserName;
    private EditText etPassword;


    /*
        Caution: set IGNORE_SSL to 'true' will accept all SSL certificates
    */
    private final boolean IGNORE_SSL = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ContextHelper.sharedInstance().setContext(getApplicationContext());

        activity = this;
        etUserName = (EditText) findViewById(R.id.etUsername);
        etPassword = (EditText) findViewById(R.id.etPassword);

        ChallengeContext.sharedInstance().register(new UsernamePasswordChallenge());
    }

    public void onClickLogin(View v) {

        final String username = etUserName.getText().toString();
        final String password = etPassword.getText().toString();

        //final String username = "testuser1";
        //final String password = "passw0rd";

        if (username.isEmpty()) {
            showToast("Username is required");
            return;
        }

        AsyncTask<Void, Void, Void> getOAuthTokenTask = new AsyncTask<Void, Void, Void>() {

            @Override
            protected Void doInBackground(Void... voids) {

                if (IGNORE_SSL) {
                    OAuthContext.sharedInstance().setSslContext(getSslContextTrustAll());
                    OAuthContext.sharedInstance().setHostnameVerifier(getHostnameVerifierAcceptAll());
                }

                OAuthContext.sharedInstance().getAccessToken(hostname, clientId, username, password, new IAuthenticationCallback() {
                    @Override
                    public void handleResult(final OAuthResult oAuthResult) {

                        if (oAuthResult.hasError()) {
                            showToast("Something went wrong");
                        } else {
                            oAuthToken = oAuthResult.serializeToToken();
                            showDialog(oAuthResult.serializeToJson().toString());
                        }
                    }
                });

                return null;
            }
        }.execute();
    }

    public void onClickInvokePolicy(View v) {

        if (oAuthToken == null) {
            showToast("No OAuth token available");
        } else {

            InvokePolicyTask invokePolicyTask = new InvokePolicyTask();
            invokePolicyTask.execute();
        }
    }

    private class VerifyChallengeTask extends AsyncTask<Void, Void, Void> {

        HashMap hashMap = new HashMap();
        Exception exception;
        IChallenge challenge;

        VerifyChallengeTask(IChallenge challenge, Map<String, Object> map, Exception e) {

            this.challenge = challenge;
            this.exception = e;

            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (entry.getValue() instanceof String) {
                    hashMap.put(entry.getKey(), entry.getValue());
                }
            }
        }

        @Override
        protected Void doInBackground(Void... voids) {

            if (IGNORE_SSL) {
                ChallengeContext.sharedInstance().setSslContext(getSslContextTrustAll());
                ChallengeContext.sharedInstance().setHostnameVerifier(getHostnameVerifierAcceptAll());
            }

            ChallengeContext.sharedInstance().verify(challenge.getPostbackUri(), oAuthToken,
                    hashMap, new IChallengeCallbackHandleVerify() {

                        @Override
                        public void handleVerify(final ChallengeResult challengeResult) {

                            if (challengeResult.hasError()) {
                                showDialog(challengeResult.getMobileKitException().getMessage());
                            } else {

                                final IChallenge nextChallenge = challengeResult.getNextChallenge();

                                if (nextChallenge != null) {

                                    nextChallenge.launchUI(activity, new IChallengeCallbackHandleUserInput() {

                                        @Override
                                        public void handleUserInput(final Map<String, Object> map, Exception e) {

                                            if (map.size() == 0)
                                                return;

                                            // recursion!
                                            VerifyChallengeTask verifyChallengeTask = new VerifyChallengeTask(nextChallenge, map, e);
                                            verifyChallengeTask.execute();
                                        }
                                    });
                                } else
                                    showDialog("Challenge successful");
                            }
                        }
                    });

            return null;
        }
    }

    ;

    private class InvokePolicyTask extends AsyncTask<Void, Void, Void> {

        ChallengeResult challengeResult;

        @Override
        protected Void doInBackground(Void... voids) {

            if (IGNORE_SSL) {
                ChallengeContext.sharedInstance().setSslContext(getSslContextTrustAll());
                ChallengeContext.sharedInstance().setHostnameVerifier(getHostnameVerifierAcceptAll());
            }

            ChallengeContext.sharedInstance().invoke(policyUrl, oAuthToken, new IChallengeCallbackHandleResult() {
                @Override
                public void handleResult(ChallengeResult result) {

                    challengeResult = result;
                }
            });

            return null;
        }

        @Override
        protected void onPostExecute(Void aVoid) {

            if (challengeResult.hasError()) {
                showDialog(challengeResult.getErrorDescription());
            } else {
                final IChallenge challenge = challengeResult.getNextChallenge();

                if (challenge != null) {

                    challenge.launchUI(activity, new IChallengeCallbackHandleUserInput() {

                        @Override
                        public void handleUserInput(final Map<String, Object> map, Exception e) {

                            if (map.size() == 0)
                                return;

                            VerifyChallengeTask verifyChallengeTask = new VerifyChallengeTask(challenge, map, e);
                            verifyChallengeTask.execute();
                        }
                    });
                }
            }
        }
    }

    private void showDialog(final String message) {

        if (message == null || message.isEmpty()) {
            showToast("Something went wrong");
        } else {
            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {

                    AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                    builder.setTitle("Password Policy Sample")
                            .setMessage(message)
                            .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialogInterface, int i) {

                                }
                            });

                    AlertDialog alertDialog = builder.create();
                    alertDialog.show();
                }
            });
        }
    }

    private void showToast(final String message) {

        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {

                Toast toast = Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT);
                toast.setGravity(Gravity.CENTER, 0, 0);
                toast.show();
            }
        });
    }

    private static SSLContext getSslContextTrustAll() {

        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            TrustManager tm = new X509TrustManager() {

                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    boolean silence;
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    boolean silence;
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };

            sslContext.init(null, new TrustManager[]{tm}, null);
            return sslContext;

        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static HostnameVerifier getHostnameVerifierAcceptAll() {

        return new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        };
    }
}
