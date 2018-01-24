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

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class ChangepinActivity extends AppCompatActivity {

    private OAuthToken oAuthToken ;
    Context mContext = ChangepinActivity.this;
    UtilityHelper utilHelpInstance;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_changepin);
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
                return true;
        }
        return super.onOptionsItemSelected(item);
    }


    public void onClickGoToHomepage(View v) {
        //Authenticated successfully show balance
        Intent intent = new Intent(ChangepinActivity.this, HomePageActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();
    }

    public void onClickChangePin(View v) {
        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        String savedToken = pref.getString("oauthtoken","no");

        TextView enterOldPinNumView = (TextView)findViewById(R.id.enterOldPin);
        enterOldPinNumView.setInputType(InputType.TYPE_CLASS_NUMBER);
        enterOldPinNumView.setFilters(new InputFilter[] {new InputFilter.LengthFilter(UtilityHelper.maxPinLength)});
        Integer oldPinNum = Integer.parseInt(enterOldPinNumView.getText().toString());

        TextView enterNewPinNumView = (TextView)findViewById(R.id.enterNewPin);
        enterOldPinNumView.setInputType(InputType.TYPE_CLASS_NUMBER);
        enterOldPinNumView.setFilters(new InputFilter[] {new InputFilter.LengthFilter(UtilityHelper.maxPinLength)});
        Integer newPinNum = Integer.parseInt(enterNewPinNumView.getText().toString());

        final Map<String, Object> params = new HashMap<>();
        params.put("oldPIN",oldPinNum);
        params.put("newPIN",newPinNum);
        params.put("auth_operation_type",UtilityHelper.OPERATION_CHANGEPIN);

        try {
            oAuthToken = (OAuthResult.parse(new JSONObject(savedToken))).serializeToToken();
        } catch (JSONException e) {
            e.printStackTrace();
        }

        if (oAuthToken == null) {
            //showToast("No OAuth token available");
            //Log.d("INFO","No OAuth token available");
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
                            //showToast("Something went wrong");
                            Log.d("", "Something went wrong");
                        } else {
                            oAuthToken = oAuthResult.serializeToToken();
                            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                            SharedPreferences.Editor edit = pref.edit();
                            edit.remove("oauthtoken");
                            edit.putString("oauthtoken",oAuthResult.serializeToJson().toString());
                            edit.commit();

                            Intent intent = new Intent(ChangepinActivity.this, ShowbalanceActivity.class);
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
