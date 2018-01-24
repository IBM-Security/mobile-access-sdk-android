package com.ibm.security.demoapps.oauthdemo;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.DialogFragment;
import android.app.Fragment;
import android.app.FragmentManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.CancellationSignal;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import com.ibm.security.access.mobile.authentication.ContextHelper;
import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.KeyStoreHelper;
import com.ibm.security.access.mobile.authentication.LogHelper;
import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.OAuthToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

public class FingerprintEnrolmentActivity extends AppCompatActivity {

    private PublicKey publicKey;
    PINAuthnActivity.KeyGenTask mKeyGenTask = null;
    private OAuthToken oAuthToken ;
    Context mContext = FingerprintEnrolmentActivity.this;
    UtilityHelper utilHelpInstance;
    private int tryCounter = 0;
    private final int MAX_TRY = 3;

    private FingerprintEnrolmentActivity.FingerprintRequestDialogFragment fingerprintRequestDialogFragment;
    private FragmentManager fm = this.getFragmentManager();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fingerprint_enrolment);
    }


    @Override
    protected void onResume()   {
        super.onResume();

        fingerprintRequestDialogFragment = new FingerprintEnrolmentActivity.FingerprintRequestDialogFragment();
        fingerprintRequestDialogFragment.show(fm, "fingerprintDialogFramgment");
    }

    public void onClickGoToHomepage(View v) {
        Intent intent = new Intent(FingerprintEnrolmentActivity.this, HomePageActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_HISTORY);
        startActivity(intent);
        finish();
    }

    @SuppressLint("ValidFragment")
    private class FingerprintRequestDialogFragment extends DialogFragment {

        private Button cancelButton;
        FingerprintEnrolmentActivity.FingerprintHandler fingerprintHandler;

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

            fingerprintHandler = new FingerprintEnrolmentActivity.FingerprintHandler();
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

        private final String TAG = FingerprintEnrolmentActivity.FingerprintHandler.class.getCanonicalName() + "(v" + android.support.compat.BuildConfig.VERSION_NAME + ")";
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
            final Map<String, Object> params = new HashMap<>();
           // String publicKeyString = Base64.encodeToString(KeyStoreHelper.exportPublicKey(UtilityHelper.keyName).getBytes(), Base64.URL_SAFE);
           // params.put("publicKey",publicKeyString);
            String originalKeyString = KeyStoreHelper.exportPublicKey(UtilityHelper.keyName,Base64.URL_SAFE);



//            String headerFooterKeyString = originalKeyString;
//            headerFooterKeyString = "-----BEGIN PUBLIC KEY-----" + System.lineSeparator() + headerFooterKeyString + "-----END PUBLIC KEY-----";
//
//            String trimmedLastNewlineKeyString = headerFooterKeyString;
//            trimmedLastNewlineKeyString = trimmedLastNewlineKeyString.trim();

           // String trimmedLastNewlineKeyString2 = "-----BEGIN PUBLIC KEY-----" + System.lineSeparator() + publicKeyString + "-----END PUBLIC KEY-----";;
           // trimmedLastNewlineKeyString2 = trimmedLastNewlineKeyString2.trim();

            //Base64.encodeToString(originalKeyString.getBytes(),Base64.URL_SAFE)
            params.put("publicKey",originalKeyString );

            Signature s = result.getCryptoObject().getSignature();
            String signatureString = "";

            try {

                s.update(oAuthToken.getRefreshToken().getBytes());
                signatureString = Base64.encodeToString(s.sign(),Base64.URL_SAFE);
                Log.d("INFO", "Signature: " + signatureString);

            } catch (SignatureException se) {
                Log.d("ERR", "Signature creation fialed!", se);
            }


            params.put("auth_operation_type",UtilityHelper.OPERATION_ENROLFINGERPRINT);
            params.put("signedData",signatureString);

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
                    params.put("access_token",oAuthToken.getAccessToken());
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
                                edit.putString("fingerprint_configured","yes");
                                edit.commit();
                                Log.d("INFO", "Allgood"+ oAuthToken);
                                //showDialog(oAuthResult.serializeToJson().toString());
                                Intent intent = new Intent(FingerprintEnrolmentActivity.this, ShowbalanceActivity.class);
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
        private PublicKey getPublicKey(@NonNull String keyName) {
            if(keyName == null) {
                throw new IllegalArgumentException(LogHelper.getLogString("ghd7Znewg1G4gV2", "aVQStEGkcon0aeo", "QTjjy1DKp2L g 1"));
            } else {
                try {
                    KeyStore var1 = KeyStore.getInstance("AndroidKeyStore");
                    var1.load((KeyStore.LoadStoreParameter)null);
                    if(var1.containsAlias(keyName)) {
                        KeyStore.Entry var2 = var1.getEntry(keyName, (KeyStore.ProtectionParameter)null);
                        if(var2 != null) {
                            return ((KeyStore.PrivateKeyEntry)var2).getCertificate().getPublicKey();
                        }
                    } else {
                        Log.d("INFO", "Key \'" + keyName + "\' not found in Keystore.");
                    }
                } catch (NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableEntryException | KeyStoreException var3) {
                    Log.d("INFO", "Couldn\'t retrieve public key \'" + keyName + "\' from keystore.", var3);
                }

                return null;
            }
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

        public void onClickCancelDialog(View v){
            Fragment fg = fm.findFragmentByTag("FingerprintRequestDialogFragment");
            if(fg!=null){
                DialogFragment df = (DialogFragment)fg;
                df.dismiss();
            }
        }


    }


}


