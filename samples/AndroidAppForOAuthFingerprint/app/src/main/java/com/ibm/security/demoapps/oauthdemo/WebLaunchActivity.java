package com.ibm.security.demoapps.oauthdemo;

import android.app.Activity;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.webkit.*;
public class WebLaunchActivity extends Activity {

    WebView web;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web_launch);

        web = (WebView)findViewById(R.id.webview01);
        web.setWebViewClient(new MyWebClient());
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);

        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        cookieManager.removeAllCookies(new ValueCallback<Boolean>() {
            @Override
            public void onReceiveValue(Boolean aBoolean) {

            }
        });
        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        String isam_session_cookie = pref.getString("ISAM-Session-Cookie","no");

        String ip = pref.getString("reverse_proxy_ip","no");

        final String url = "http://" + ip + "/webpage.html";

        cookieManager.setCookie("https://" + ip + "/",isam_session_cookie);
        cookieManager.setAcceptThirdPartyCookies(web,true);

        web.postDelayed(new Runnable() {
            @Override
            public void run() {
                web.loadUrl(url);
            }
        },500);

    }
    public class MyWebClient extends WebViewClient{
        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon){
            super.onPageStarted(view,url,favicon);
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url){
            view.loadUrl(url);
            return true;
        }
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event){
        if(keyCode == KeyEvent.KEYCODE_BACK){
            web.goBack();
            return true;
        }
        return super.onKeyDown(keyCode,event);
    }

}
