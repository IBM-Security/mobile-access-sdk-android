package com.ibm.security.demoapps.deviceregistration;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.view.Gravity;
import android.view.View;
import android.widget.Toast;

import com.ibm.security.access.mobile.authentication.ContextHelper;
import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.IMfaRegistrationResultCallback;
import com.ibm.security.access.mobile.authentication.IQRScanResult;
import com.ibm.security.access.mobile.authentication.MfaQRScanResult;
import com.ibm.security.access.mobile.authentication.MfaRegistrationContext;
import com.ibm.security.access.mobile.authentication.MfaRegistrationResult;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.OAuthToken;
import com.ibm.security.access.mobile.authentication.OtpQRScanResult;
import com.ibm.security.access.mobile.authentication.RegistrationAttributes;
import com.ibm.security.access.mobile.authentication.UIQRScanView;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends AppCompatActivity {

    private final int SCAN_QR_REQUEST = 42;
    private Activity activity;

    private String clientId = "IBMVerifySDK";
    private String authorizationCode = "";
    private OAuthResult oAuthResult;
    private OAuthToken oAuthToken;

    private String newLine = System.getProperty("line.separator");

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

    }

    public void onClickScanQRCode(View v) {

        Intent intent = new Intent(getApplicationContext(), UIQRScanView.class);
        startActivityForResult(intent, SCAN_QR_REQUEST);
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {

        if (requestCode == SCAN_QR_REQUEST && data != null) {

            Object resultCandidate = data.getExtras().get(IQRScanResult.class.getName());

            if (resultCandidate instanceof OtpQRScanResult) {
                OtpQRScanResult result = (OtpQRScanResult) resultCandidate;

                StringBuilder stringBuilder = new StringBuilder()
                        .append("Username: " + result.getUsername()).append(newLine)
                        .append("Issuer: " + result.getIssuer()).append(newLine)
                        .append("Secret: " + result.getSecret()).append(newLine)
                        .append("Type: " + result.getType()).append(newLine)
                        .append("Algorithm: " + result.getAlgorithm().name()).append(newLine)
                        .append("Digits: " + result.getDigits()).append(newLine)
                        .append("Counter: " + result.getCounter()).append(newLine)
                        .append("Period: " + result.getPeriod());

                showDialog(stringBuilder.toString());
                showToast("OTP code detected");
            } else if (resultCandidate instanceof MfaQRScanResult) {
                MfaQRScanResult mfaQRScanResult = (MfaQRScanResult) resultCandidate;
                authorizationCode = mfaQRScanResult.getCode();

                StringBuilder stringBuilder = new StringBuilder()
                        .append("Metadata url: " + mfaQRScanResult.getMetadataUrl()).append(newLine)
                        .append("Client id: " + mfaQRScanResult.getClientId()).append(newLine)
                        .append("Code: " + mfaQRScanResult.getCode()).append(newLine)
                        .append("Token url: " + mfaQRScanResult.getTokenUrl());

                showDialog(stringBuilder.toString());

                new RegistrationTask(mfaQRScanResult, activity).execute();

            } else {
                showToast("Unknown type of QR code detected");
            }
        }
    }

    class RegistrationTask extends AsyncTask<Void, Void, Void> {

        MfaQRScanResult mfaQRScanResult;
        Activity activity;
        MfaRegistrationResult mfaRegistrationResult;

        public RegistrationTask(MfaQRScanResult mfaQRScanResult, Activity activity) {

            this.mfaQRScanResult = mfaQRScanResult;
            this.activity = activity;
        }

        @Override
        protected Void doInBackground(Void... params) {

            if (IGNORE_SSL) {
                MfaRegistrationContext.sharedInstance().setSslContext(getSslContextTrustAll());
                MfaRegistrationContext.sharedInstance().setHostnameVerifier(getHostnameVerifierAcceptAll());
            }

            MfaRegistrationContext.sharedInstance().discover(mfaQRScanResult.getMetadataUrl(), new IMfaRegistrationResultCallback() {
                @Override
                public void handleMfaRegistrationResult(MfaRegistrationResult r) {
                    mfaRegistrationResult = r;
                }
            });

            return null;
        }

        @Override
        protected void onPostExecute(Void aVoid) {

            if (!mfaRegistrationResult.hasError()) {

                new OAuthTask(mfaRegistrationResult, activity).execute();

            } else {

                showDialog(mfaRegistrationResult.getMobileKitException().toString());
            }
        }
    }

    class OAuthTask extends AsyncTask<Void, Void, Void> {

        MfaRegistrationResult mfaRegistrationResult;
        HashMap<String, Object> deviceAttributes;
        Context context = ContextHelper.sharedInstance().getContext();
        Activity activity;

        public OAuthTask(MfaRegistrationResult mfaRegistrationResult, Activity activity) {

            this.mfaRegistrationResult = mfaRegistrationResult;
            this.activity = activity;
        }

        @Override
        protected Void doInBackground(Void... params) {

            if (IGNORE_SSL) {
                OAuthContext.sharedInstance().setSslContext(getSslContextTrustAll());
                OAuthContext.sharedInstance().setHostnameVerifier(getHostnameVerifierAcceptAll());
            }

            SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(ContextHelper.sharedInstance().getContext());
            sharedPreferences.edit().putString(RegistrationAttributes.PUSH_NOTIFICATION_IDENTIFIER.toString(), "put your push:token in here").apply();

            OAuthContext.sharedInstance().getAccessToken(mfaRegistrationResult.getOauthTokenUrl(), mfaRegistrationResult.getClientId(),
                    authorizationCode, RegistrationAttributes.getAllAttributeValues(context), new IAuthenticationCallback() {
                        @Override
                        public void handleResult(OAuthResult r) {
                            oAuthResult = r;
                        }
                    });

            return null;
        }

        @Override
        protected void onPostExecute(Void aVoid) {

            if (!oAuthResult.hasError()) {

                oAuthToken = oAuthResult.serializeToToken();
                showDialog(oAuthResult.serializeToJson().toString());
                showToast("Registration successful");

            } else {
                showDialog(oAuthResult.getMobileKitException().toString());
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
                    builder.setTitle("Device Registration Sample")
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
