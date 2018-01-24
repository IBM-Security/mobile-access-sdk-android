package com.ibm.security.demoapps.oauthdemo;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.view.Gravity;
import android.widget.Toast;

import com.ibm.security.access.mobile.authentication.OAuthToken;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Created by Asha on 21/12/2017.
 */

public class UtilityHelper {

    public static final int maxPinLength = 4;
    public static final String OPERATION_REGISTRATION = "REGISTRATION";
    public static final String OPERATION_VALIDATEPIN = "VALIDATEPIN";
    public static final String OPERATION_CHANGEPIN = "CHANGEPIN";
    public static final String OPERATION_ENROLFINGERPRINT = "ENROLFINGERPRINT";
    public static final String OPERATION_VALIDATEFINGERPRINT = "VALIDATEFINGERPRINT";
    public static final String OPERATION_UNENROLFINGERPRINT = "DEREGISTERFINGERPRINT";
    public static final String OPERATION_LOGOUT = "LOGOUT";
    public static final String keyName = "my-key";
   // public static final String hostname = "https://192.168.42.194/mga/sps/oauth/oauth20/token";
   // public static final String clientId = "curlclient1";



    /*
        Caution: set IGNORE_SSL to 'true' will accept all SSL certificates
     */
    public static final boolean IGNORE_SSL = true;


    public void showToast(final String message, final Activity activity) {

        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {

                Toast toast = Toast.makeText(activity, message, Toast.LENGTH_SHORT);
                toast.setGravity(Gravity.CENTER, 0, 0);
                toast.show();
            }
        });
    }

    public void showDialog(final String message,final Activity activity) {

        if (message == null || message.isEmpty()) {
            showToast("Something went wrong",activity);
        } else {
            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {

                    AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                    builder.setTitle("OAuth Sample")
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

    public static SSLContext getSslContextTrustAll() {

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

    public static HostnameVerifier getHostnameVerifierAcceptAll() {

        return new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        };
    }



}
