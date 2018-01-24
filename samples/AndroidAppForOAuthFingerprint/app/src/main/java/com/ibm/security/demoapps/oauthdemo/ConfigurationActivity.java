package com.ibm.security.demoapps.oauthdemo;

import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

public class ConfigurationActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_configuration);
    }


    public void onClickSaveConfiguration(View v) {

        TextView reverse_proxy = (EditText) findViewById(R.id.auth_endpoint);
        TextView client_id = (EditText) findViewById(R.id.clientid);

        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        SharedPreferences.Editor edit = pref.edit();
        edit.remove("endpoint_url");
        edit.remove("client_id");
        String endpoint_url = "https://" + reverse_proxy.getText().toString() + "/mga/sps/oauth/oauth20/token";
        edit.putString("reverse_proxy_ip",reverse_proxy.getText().toString());
        edit.putString("endpoint_url",endpoint_url);
        edit.putString("client_id",client_id.getText().toString());
        edit.commit();
        finish();


    }

    public void onClickGoToMain(View v) {
        finish();
    }




}
