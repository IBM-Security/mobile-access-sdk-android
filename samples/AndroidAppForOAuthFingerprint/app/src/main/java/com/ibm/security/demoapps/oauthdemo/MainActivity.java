package com.ibm.security.demoapps.oauthdemo;

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
import android.text.InputFilter;
import android.text.InputType;
import android.util.Log;
import android.view.Gravity;
import android.view.Menu;

import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.ibm.security.access.mobile.authentication.ContextHelper;
import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.OAuthToken;

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

public class MainActivity extends AppCompatActivity  {

    private Boolean firstTime = null;
    private Activity activity;
    private OAuthToken oAuthToken;


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


        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());

        if(isFirstTime()==true){
            startActivity(this.getIntent());
        }else{
            Intent intent = new Intent(this, HomePageActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
            startActivity(intent);
            finish();
            //Now home activity decides how to re-authenticate

        }


    }

    public void onClickUseGetOAuthToken(View v) {

        final String username = etUserName.getText().toString();
        final String password = etPassword.getText().toString();
        TextView pinNumView = (TextView)findViewById(R.id.setPinNumber);
        pinNumView.setInputType(InputType.TYPE_CLASS_NUMBER);
        pinNumView.setFilters(new InputFilter[] {new InputFilter.LengthFilter(UtilityHelper.maxPinLength)});

        Integer pinNum = Integer.parseInt(pinNumView.getText().toString());
        final Map<String, Object> params = new HashMap<>();
        params.put("PIN",pinNum);
        params.put("auth_operation_type",UtilityHelper.OPERATION_REGISTRATION);


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
                //TODO: Change all hostnames to use the one from config instead from Utility Helper
                SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                Log.d("INFO: endpoint_url", pref.getString("endpoint_url","no"));
                Log.d("INFO: Client_id", pref.getString("client_id","no"));
                String endpoint_url = pref.getString("endpoint_url","no");
                String client_id = pref.getString("client_id","no");

                OAuthContext.sharedInstance().getAccessToken(endpoint_url, client_id, username, password, params, new IAuthenticationCallback() {
                    @Override
                    public void handleResult(final OAuthResult oAuthResult) {

                        if (oAuthResult.hasError()) {
                            showToast("Something went wrong");
                        } else {
                            oAuthToken = oAuthResult.serializeToToken();
                            //Store
                            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                            SharedPreferences.Editor edit = pref.edit();
                            edit.remove("oauthtoken");
                            edit.putString("oauthtoken",oAuthResult.serializeToJson().toString());
                            edit.commit();
                            //showDialog(oAuthResult.serializeToJson().toString());
                            String unconfigured = "unconfigured";

                            // Pin configured for the app decides which screen to relauch into
                            edit.putString("pin_configured", "yes");
                            edit.putBoolean("first_time",false);
                            edit.commit();

                            //Authenticated successfully show balance
                            Intent intent = new Intent(MainActivity.this, ShowbalanceActivity.class);
                            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
                            startActivity(intent);
                            finish();

                        }
                    }
                });

                return null;
            }
        }.execute();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.action_main_menu,menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item){
        switch (item.getItemId()){
            case R.id.action_settings:
                Intent intent = new Intent(this, ConfigurationActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
                startActivity(intent);
//                finish();
                return true;
        }
        return super.onOptionsItemSelected(item);
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

    private void showDialog(final String message) {

        if (message == null || message.isEmpty()) {
            showToast("Something went wrong");
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

    private boolean isFirstTime(){
        if(firstTime==null){
            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
            firstTime = pref.getBoolean("first_time",true);

        }
        return firstTime;
    }

}
