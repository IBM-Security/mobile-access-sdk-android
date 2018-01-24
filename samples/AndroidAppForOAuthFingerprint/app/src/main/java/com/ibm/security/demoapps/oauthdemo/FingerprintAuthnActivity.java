package com.ibm.security.demoapps.oauthdemo;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.CancellationSignal;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import com.ibm.security.access.mobile.authentication.ContextHelper;
import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.KeyStoreHelper;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.OAuthToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;


public class FingerprintAuthnActivity extends AppCompatActivity {

    private PublicKey publicKey;
    PINAuthnActivity.KeyGenTask mKeyGenTask = null;
    private OAuthToken oAuthToken ;
    //private SendKeyTask mKeySendTask = null;
    Context mContext = FingerprintAuthnActivity.this;
    UtilityHelper utilHelpInstance;
    private int tryCounter = 0;
    private final int MAX_TRY = 3;

    private FingerprintRequestDialogFragment fingerprintRequestDialogFragment;
    private FragmentManager fm = this.getFragmentManager();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fingerprint_authn);
    }

    @Override
    protected void onResume()   {
        super.onResume();

        fingerprintRequestDialogFragment = new FingerprintRequestDialogFragment();
        fingerprintRequestDialogFragment.show(fm, "fingerprintDialogFramgment");
    }

    @SuppressLint("ValidFragment")
    private class FingerprintRequestDialogFragment extends DialogFragment {

        private Button cancelButton;
        FingerprintAuthnActivity.FingerprintHandler fingerprintHandler;

        private FingerprintRequestDialogFragment() {
        }

        public void onCreate(Bundle savedInstanceState) {

            super.onCreate(savedInstanceState);
            setRetainInstance(true);
            setCancelable(false);
            setStyle(DialogFragment.STYLE_NO_TITLE, R.style.Theme_AppCompat_Light_Dialog);
        }

        public View onCreateView(LayoutInflater inflater, ViewGroup viewGroup,
                                 Bundle savedInstance) {

            View v = inflater.inflate(R.layout.activity_fingerprint_challenge, viewGroup, false);
            cancelButton = (Button) v.findViewById(R.id.cancel_button);
            cancelButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    dismiss();
                }
            });

            fingerprintHandler = new FingerprintAuthnActivity.FingerprintHandler();
            return v;

        }

        @Override
        public void onResume() {
            super.onResume();
            fingerprintHandler.startAuthentication(UtilityHelper.keyName);
        }

        @Override
        public void onPause() {
            super.onPause();

            if (fingerprintHandler.cancellationSignal != null) {
                fingerprintHandler.cancellationSignal.cancel();
                fingerprintHandler.cancellationSignal = null;
            }
        }

        @Override
        public void onDestroyView() {
            if (getDialog() != null && getRetainInstance()) {
                getDialog().setDismissMessage(null);
            }
            super.onDestroyView();
        }

    }



    @TargetApi(Build.VERSION_CODES.M)
    private class FingerprintHandler extends FingerprintManager.AuthenticationCallback {

        private final String TAG = FingerprintAuthnActivity.FingerprintHandler.class.getCanonicalName() + "(v" + android.support.compat.BuildConfig.VERSION_NAME + ")";
        private Context context = ContextHelper.sharedInstance().getContext();
        CancellationSignal cancellationSignal = new CancellationSignal();

        public FingerprintHandler() {
        }

        public void startAuthentication(String keyName) {

            try {

                tryCounter = 0;

                FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);

                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);

                Signature instance = Signature.getInstance("SHA256withRSA");
                instance.initSign((PrivateKey) keyStore.getKey(keyName, null));
                FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(instance);

                //noinspection MissingPermission
                fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);

            } catch (IOException | UnsupportedOperationException | GeneralSecurityException e) {

                Log.d(TAG, "Failed to start 'authenticate'.", e);
            }
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {

            SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
            String savedToken = pref.getString("oauthtoken","no");

            Log.d("INFO",savedToken);
            try {
                oAuthToken = (OAuthResult.parse(new JSONObject(savedToken))).serializeToToken();
            } catch (JSONException e) {
                e.printStackTrace();
            }

            if (oAuthToken == null) {
                Log.d("INFO","No OAuth token available");
                return;
            }

            Signature s = result.getCryptoObject().getSignature();
            String signatureString = "";

            try {
                s.update(oAuthToken.getRefreshToken().getBytes());
                signatureString = Base64.encodeToString(s.sign(), Base64.URL_SAFE);
                Log.d("INFO", "Signature: " + signatureString);
            } catch (SignatureException se) {
                Log.d("INFO", "Signature creation fialed!", se);
            }

            final Map<String, Object> params = new HashMap<>();
            params.put("auth_operation_type",UtilityHelper.OPERATION_VALIDATEFINGERPRINT);
            params.put("signedData", signatureString);
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
                                edit.putString("fingerprint_configured","yes");
                                edit.commit();
                                Log.d("INFO", "Allgood"+ oAuthToken);
                                //showDialog(oAuthResult.serializeToJson().toString());
                                Intent intent = new Intent(FingerprintAuthnActivity.this, ShowbalanceActivity.class);
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
        public void onAuthenticationFailed() {

            if (++tryCounter >= MAX_TRY) {
                fingerprintRequestDialogFragment.dismiss();
                Intent intent = new Intent(mContext, HomePageActivity.class);
                intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
                startActivity(intent);
            }
        }
    }
}
