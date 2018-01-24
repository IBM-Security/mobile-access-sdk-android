package com.ibm.security.demoapps.oauthdemo;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.OAuthToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class LogoutActivity extends AppCompatActivity {

    private Activity activity;
    private OAuthToken oAuthToken ;
    Context mContext = LogoutActivity.this;
    UtilityHelper utilHelpInstance;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_logout);
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

    public void onClickLogout(View v){
        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        String savedToken = pref.getString("oauthtoken","no");

        TextView enterPinNumView = (TextView)findViewById(R.id.enterPinNumber);
        enterPinNumView.setInputType(InputType.TYPE_CLASS_NUMBER);
        enterPinNumView.setFilters(new InputFilter[] {new InputFilter.LengthFilter(UtilityHelper.maxPinLength)});

        Integer pinNum = Integer.parseInt(enterPinNumView.getText().toString());
        final Map<String, Object> params = new HashMap<>();
        params.put("PIN",pinNum);
        params.put("auth_operation_type",UtilityHelper.OPERATION_LOGOUT);

        try {
            oAuthToken = (OAuthResult.parse(new JSONObject(savedToken))).serializeToToken();
        } catch (JSONException e) {
            e.printStackTrace();
        }

        if (oAuthToken == null) {
            //showToast("No OAuth token available");
            Log.d("INFO","No OAuth token available");
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
                        Log.d("", "oAuthResult.serializeToJson().length()" + oAuthResult.serializeToJson().length());
                        if(oAuthResult.serializeToJson().length()<=2){
                            Log.d("", "LogoutSuccess");
                            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                            SharedPreferences.Editor edit = pref.edit();
                            edit.remove("oauthtoken");
                            edit.remove("pin_configured");
                            edit.remove("fingerprint_configured");
                            edit.remove("first_time");
                            edit.putBoolean("first_time",true);
                            edit.commit();
                            android.os.Process.killProcess(android.os.Process.myPid());
                        }else if (oAuthResult.hasError()) {
                            //showToast("Something went wrong");
                            Log.d("", "Something went wrong");

                        } else {
                            Log.d("", "LogoutSuccess");
                            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                            SharedPreferences.Editor edit = pref.edit();

                            edit.remove("oauthtoken");
                            edit.remove("pin_configured");
                            edit.remove("fingerprint_configured");
                            edit.remove("first_time");
                            edit.putBoolean("first_time",true);
                            edit.commit();

                        }
                    }
                });

                return null;
            }
        }.execute();
    }

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
