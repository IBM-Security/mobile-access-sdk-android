package com.ibm.security.demoapps.oauthdemo;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.Switch;

import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;

import org.json.JSONException;
import org.json.JSONObject;

public class HomePageActivity extends AppCompatActivity
    {

    String gotoTouchIDAuthScreen;
    String gotoPinAuthScreen;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_home_page);

            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
            gotoTouchIDAuthScreen = pref.getString("fingerprint_configured","no");
            gotoPinAuthScreen = pref.getString("pin_configured","no");
            Log.i("fingerprint_configured", gotoTouchIDAuthScreen);
            Log.i("pin_configured", gotoPinAuthScreen);
            
            Button unreg_btn = (Button)(findViewById(R.id.button_unregFingerprintAuth))  ;
            Log.i("INFO", String.valueOf(unreg_btn.getVisibility()));
            if(gotoTouchIDAuthScreen=="yes"){
                unreg_btn.setVisibility(View.VISIBLE);
            }else{
                unreg_btn.setVisibility(View.INVISIBLE);
            }


        }

    @Override
    public void onResume() {
        super.onResume();
        Button unreg_btn = (Button)(findViewById(R.id.button_unregFingerprintAuth))  ;
        if(gotoTouchIDAuthScreen=="yes"){
            unreg_btn.setVisibility(View.VISIBLE);
        }else{
            unreg_btn.setVisibility(View.INVISIBLE);
        }
    }

    public void onClickReAuthenticate(View v) {
        if(gotoTouchIDAuthScreen.equalsIgnoreCase("yes")) {
            // start PIN authentication process.
            Intent intent = new Intent(this, FingerprintAuthnActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
            startActivity(intent);
            finish();
        }
        else if (gotoPinAuthScreen.equalsIgnoreCase("yes")){
            // start Fingerprint authentication process.
            Log.d("goto pin screen", "");
            Intent intent = new Intent(this, PINAuthnActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
            startActivity(intent);
            finish();
        }

    }

    public void onClickLogout(View v){
        Log.d("goto logout screen", "");
        Intent intent = new Intent(this, LogoutActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();

    }

    public void onClickUnRegFingerprintAuth(View v){

        // start TouchID Unenrol process.
        Intent intent = new Intent(this, FingerprintUnenrolActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();

    }


}
