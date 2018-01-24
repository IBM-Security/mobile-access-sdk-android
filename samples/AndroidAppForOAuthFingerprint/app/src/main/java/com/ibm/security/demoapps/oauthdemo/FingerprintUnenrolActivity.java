package com.ibm.security.demoapps.oauthdemo;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.util.Log;
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

public class FingerprintUnenrolActivity extends AppCompatActivity {
    private OAuthToken oAuthToken ;
    Context mContext = FingerprintUnenrolActivity.this;
    UtilityHelper utilHelpInstance;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fingerprint_unenrol);
    }

    public void onClickFingerprintUnenrol(View v) {
        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        String savedToken = pref.getString("oauthtoken","no");

        TextView enterPinNumView = (TextView)findViewById(R.id.enterPinNumber);
        enterPinNumView.setInputType(InputType.TYPE_CLASS_NUMBER);
        enterPinNumView.setFilters(new InputFilter[] {new InputFilter.LengthFilter(UtilityHelper.maxPinLength)});

        Integer pinNum = Integer.parseInt(enterPinNumView.getText().toString());
        final Map<String, Object> params = new HashMap<>();
        params.put("PIN",pinNum);
        params.put("auth_operation_type",UtilityHelper.OPERATION_UNENROLFINGERPRINT);

        try {
            oAuthToken = (OAuthResult.parse(new JSONObject(savedToken))).serializeToToken();
        } catch (JSONException e) {
            e.printStackTrace();
        }

        if (oAuthToken == null) {
            //showToast("No OAuth token available");
            Log.d("WARN","No OAuth token available");
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

                            Log.d("ERR", "Something went wrong");
                        } else {
                            oAuthToken = oAuthResult.serializeToToken();
                            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                            SharedPreferences.Editor edit = pref.edit();
                            edit.remove("oauthtoken");
                            edit.remove("fingerprint_configured");
                            edit.putString("oauthtoken",oAuthResult.serializeToJson().toString());
                            edit.commit();



                            Intent intent = new Intent(FingerprintUnenrolActivity.this, HomePageActivity.class);
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
}
