package com.ibm.security.demoapps.oauthdemo;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.util.Base64;
import android.util.JsonReader;
import android.util.Log;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import android.app.ActionBar;
import android.view.MenuItem;

import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.IKeyStoreHelperCallbackHandleResult;
import com.ibm.security.access.mobile.authentication.KeyStoreHelper;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;

import com.ibm.security.access.mobile.authentication.OAuthToken;
import com.ibm.security.demoapps.oauthdemo.UtilityHelper;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

public class PINAuthnActivity extends AppCompatActivity {

    private Activity activity;
    private OAuthToken oAuthToken ;
    private PublicKey publicKey;
    KeyGenTask mKeyGenTask = null;
    Context mContext = PINAuthnActivity.this;
    UtilityHelper utilHelpInstance;
    KeyStoreHelper keyStoreHelper = new KeyStoreHelper();





    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pinauthn);

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.action_home_page,menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item){
        switch (item.getItemId()){
            case R.id.action_go_home:
                Intent intent = new Intent(this, HomePageActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
                startActivity(intent);
//                finish();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }


    public void onClickAuthenticatewithPin(View v) {
        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        String savedToken = pref.getString("oauthtoken","no");

        TextView enterPinNumView = (TextView)findViewById(R.id.enterPinNumber);
        enterPinNumView.setInputType(InputType.TYPE_CLASS_NUMBER);
        enterPinNumView.setFilters(new InputFilter[] {new InputFilter.LengthFilter(UtilityHelper.maxPinLength)});

        Integer pinNum = Integer.parseInt(enterPinNumView.getText().toString());
        final Map<String, Object> params = new HashMap<>();
        params.put("PIN",pinNum);
        params.put("auth_operation_type",UtilityHelper.OPERATION_VALIDATEPIN);

        try {
            oAuthToken = (OAuthResult.parse(new JSONObject(savedToken))).serializeToToken();
        } catch (JSONException e) {
            e.printStackTrace();
        }

        if (oAuthToken == null) {
            //showToast("No OAuth token available");
            return;
        }

        AsyncTask<Void, Void, Void> refreshOAuthTokenTask = new AsyncTask<Void, Void, Void>() {

            @Override
            protected Void doInBackground(Void... voids) {

                if (UtilityHelper.IGNORE_SSL) {
                    OAuthContext.sharedInstance().setSslContext(utilHelpInstance.getSslContextTrustAll());
                    OAuthContext.sharedInstance().setHostnameVerifier(utilHelpInstance.getHostnameVerifierAcceptAll());
                }
                SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                String endpoint_url = pref.getString("endpoint_url","no");
                String client_id = pref.getString("client_id","no");
                OAuthContext.sharedInstance().refreshAccessToken(endpoint_url, client_id, oAuthToken.getRefreshToken(), params, new IAuthenticationCallback() {
                    @Override
                    public void handleResult(final OAuthResult oAuthResult) {

                        if (oAuthResult.hasError()) {

                            Log.d("", "Something went wrong");
                        } else {
                            oAuthToken = oAuthResult.serializeToToken();
                            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                            SharedPreferences.Editor edit = pref.edit();
                            edit.remove("oauthtoken");
                            edit.putString("oauthtoken",oAuthResult.serializeToJson().toString());
                            edit.commit();

                            Intent intent = new Intent(PINAuthnActivity.this, ShowbalanceActivity.class);
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

    public void onClickEnrolFingerprint(View v){

        //        //put keygen code here

        mKeyGenTask = new KeyGenTask(mContext);
        try {
            Boolean str = mKeyGenTask.execute().get();
        }catch(Exception e){
            Log.d("ERR", "Problem in Keygen task");
        }

        // start PIN authentication process.
        Intent intent = new Intent(this, FingerprintEnrolmentActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();



    }

    public void onClickChangePin(View v){
        Intent intent = new Intent(PINAuthnActivity.this, ChangepinActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();
    }

    /**
     * Generate a keypair called keyName.
     * Upon completion, triggers SendKeyTask.
     */
    public class KeyGenTask extends AsyncTask<Void, Void, Boolean> implements IKeyStoreHelperCallbackHandleResult {
        private final Context mContext;
        private Boolean success = false;

        public KeyGenTask(Context context) {
            mContext = context;
        }

        @Override
        protected Boolean doInBackground(Void... voids) {
            KeyStoreHelper helper = new KeyStoreHelper();
            helper.createKeyPair(UtilityHelper.keyName, true, this);
            String originalKeyString = KeyStoreHelper.exportPublicKey(UtilityHelper.keyName);
            Log.d("INFO", "original key string: " + originalKeyString);
            return null;
        }

        @Override
        protected void onPostExecute(Boolean unused) {
            mKeyGenTask = null;

            if (!success) {
                Toast.makeText(mContext, "Failed to generate keypair.", Toast.LENGTH_SHORT).show();
                return;
            } else {
                Toast.makeText(mContext, "Generated keypair!", Toast.LENGTH_SHORT).show();
            }

            //mKeySendTask = new SendKeyTask(mContext);
           // mKeySendTask.execute();
        }

        @Override
        public void handleKeyPairResult(Boolean success, PublicKey key) {
            this.success = success;
            publicKey = key;
        }
    }




//    private void showToast(final String message) {
//        activity.runOnUiThread(new Runnable() {
//            @Override
//            public void run() {
//
//                Toast toast = Toast.makeText(PINAuthnActivity.this, message, Toast.LENGTH_SHORT);
//                toast.setGravity(Gravity.CENTER, 0, 0);
//                toast.show();
//            }
//        });
//    }

    private void showDialog(final String message) {

        if (message == null || message.isEmpty()) {
            //showToast("Something went wrong");
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

}
