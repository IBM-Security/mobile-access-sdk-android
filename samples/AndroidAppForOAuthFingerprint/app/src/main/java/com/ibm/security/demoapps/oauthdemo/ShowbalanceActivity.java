package com.ibm.security.demoapps.oauthdemo;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.webkit.WebView;
import android.widget.Toast;

import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.OAuthToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.os.StrictMode;

import javax.net.ssl.HttpsURLConnection;

public class ShowbalanceActivity extends AppCompatActivity {

    private OAuthToken oAuthToken ;
    WebView web;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_showbalance);


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

    public void onClickShowResource(View v){


        Thread thread = new Thread(new Runnable(){
            public void run() {
                SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                String reverse_proxy_ip = pref.getString("reverse_proxy_ip","no");
                String savedToken = pref.getString("oauthtoken","no");
                Log.d("HELP",reverse_proxy_ip);
                    String resource_url = "https://" + reverse_proxy_ip + "/resource.html";
                    URL url = null;
                    try {

                        try {
                            oAuthToken = (OAuthResult.parse(new JSONObject(savedToken))).serializeToToken();
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        if (oAuthToken == null) {
                            //showToast("No OAuth token available");
                            return;
                        }
                        String tokenData = "access_token="+oAuthToken.getAccessToken();
                        url = new URL(resource_url + "?"+tokenData);
                        HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
                        con.setSSLSocketFactory(UtilityHelper.getSslContextTrustAll().getSocketFactory());
                        con.setHostnameVerifier(UtilityHelper.getHostnameVerifierAcceptAll());
                        con.setRequestMethod("POST");
                        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                        con.setRequestProperty("Authorization", "Bearer "+oAuthToken.getAccessToken());
                        con.setDoOutput(true);
                        DataOutputStream wr = new DataOutputStream(con.getOutputStream());
                        wr.writeBytes(tokenData);
                        wr.flush();
                        wr.close();

                        int responseCode = con.getResponseCode();

                        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
                        String inputLine;
                        StringBuffer response = new StringBuffer();
                        while((inputLine=in.readLine())!=null){
                            response.append(inputLine);
                        }
                        in.close();

                        if(responseCode==200){
                            Activity mActivity = ShowbalanceActivity.this;
                            showToast("BALANCE:1200021",mActivity) ;
                        }



                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

            }
        });

        thread.start();



    }

    public void onClickGoToHomepage(View v) {
        //Authenticated successfully show balance
        Intent intent = new Intent(ShowbalanceActivity.this, HomePageActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();
    }

    public void onClickLaunchWebpage(View v){

        Thread thread = new Thread(new Runnable(){
            public void run() {
                SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
                String reverse_proxy_ip = pref.getString("reverse_proxy_ip","no");
                String savedToken = pref.getString("oauthtoken","no");
                Log.d("HELP",reverse_proxy_ip);
                String resource_url = "https://" + reverse_proxy_ip + "resource.html";
                URL url = null;
                try {

                    try {
                        oAuthToken = (OAuthResult.parse(new JSONObject(savedToken))).serializeToToken();
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }

                    if (oAuthToken == null) {
                        //showToast("No OAuth token available");
                        return;
                    }
                    String tokenData = "access_token="+oAuthToken.getAccessToken();
                    url = new URL("https://"+ reverse_proxy_ip + "/mga/sps/oauth/oauth20/session");
                    HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
                    con.setSSLSocketFactory(UtilityHelper.getSslContextTrustAll().getSocketFactory());
                    con.setHostnameVerifier(UtilityHelper.getHostnameVerifierAcceptAll());
                    con.setRequestMethod("POST");
                    con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                    //con.setRequestProperty("Authorization", "Bearer "+oAuthToken.getAccessToken());
                    con.setDoOutput(true);
                    DataOutputStream wr = new DataOutputStream(con.getOutputStream());
                    wr.writeBytes(tokenData);
                    wr.flush();
                    wr.close();

                    int responseCode = con.getResponseCode();


                    BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
                    String inputLine;
                    StringBuffer response = new StringBuffer();
                    while((inputLine=in.readLine())!=null){
                        response.append(inputLine);
                    }
                    in.close();

                    Log.d("HELP",response.toString());
                    Log.d("HELP",con.getResponseMessage());
                    Map<String,List<String>> map = con.getHeaderFields();
                    for (Map.Entry<String,List<String>> entry: map.entrySet()){
                        Log.d("HELP", "KEY:" + entry.getKey() + " Value " + entry.getValue());
                        if(entry.getKey()!=null && entry.getKey().equalsIgnoreCase("Set-Cookie")){


                            for (String headerValue:entry.getValue()) {
                                headerValue = headerValue.replace("AMWEBJCT!%2Fmga!","");
                                String[] fields = headerValue.split(";\\s*");
                                String cookieValue = fields[0];
                                String expires = null;
                                boolean secure = false;
                                String domain = null;
                                String path = null;

                                if(cookieValue.contains("PD-S-SESSION-ID")) {
                                    SharedPreferences.Editor edit = pref.edit();
                                    edit.remove("ISAM-Session-Cookie");
                                    edit.putString("ISAM-Session-Cookie", cookieValue);
                                    edit.commit();
                                }

                                for(int j=1;j<fields.length;j++){
                                    if("secure".equalsIgnoreCase(fields[j])){
                                        secure=true;
                                    }
                                    else if(fields[j].indexOf("=")>0){
                                        String[] f = fields[j].split("=");
                                        if("expires".equalsIgnoreCase(f[0])){
                                           expires = f[1];
                                        }
                                        else if("domain".equalsIgnoreCase(f[0])){
                                            domain = f[1];
                                        }
                                        else if("path".equalsIgnoreCase(f[0])){
                                            path = f[1];
                                        }
                                    }
                                }

                                Log.d("INFO", "CookieValue " + cookieValue);
                                Log.d("INFO", "expires " + expires);
                                Log.d("INFO", "domain " + domain);
                                Log.d("INFO", "path " + path);
                                Log.d("INFO", "secure " + secure);

                            }
                        }
                    }


                    if(responseCode==200){
                        Activity mActivity = ShowbalanceActivity.this;
                        showToast("SESSION ENDPOINT",mActivity) ;
                    }



                } catch (MalformedURLException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        });

        thread.start();

        //TODO:ASHA check response code and start web activity based on set-cookie

        Intent intent = new Intent(ShowbalanceActivity.this, WebLaunchActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();
    }

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


}
