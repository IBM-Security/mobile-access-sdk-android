/*
 * Copyright 2017 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ibm.security.demoapps.otpdemo;

import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.ibm.security.access.mobile.authentication.IQRScanResult;
import com.ibm.security.access.mobile.authentication.OtpQRScanResult;
import com.ibm.security.access.mobile.authentication.UIQRScanView;
import com.ibm.security.demoapps.R;

import java.util.Timer;
import java.util.TimerTask;

import com.ibm.security.access.mobile.authorization.HmacAlgorithm;
import com.ibm.security.access.mobile.authorization.HotpGeneratorContext;
import com.ibm.security.access.mobile.authorization.TotpGeneratorContext;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    /* Request code for scanning a QR code */
    private final int scanQRrequest = 42;

    /** One of these will be our generator and the other will be null. */
    TotpGeneratorContext totpGenerator = null;
    HotpGeneratorContext hotpGenerator = null;

    /** The settings where we store our simple account. */
    SharedPreferences prefs;
    public static final String preferencePath = "account preferences";
    /** Information about our account. */
    AccountInfo accountInfo;

    View mainLayout;
    View showLayout;
    View emptyLayout;
    TextView tvAccountName;
    TextView tvAccountIssuer;
    TextView tvTimeRemaining;
    TextView tvOtp;
    ImageButton refreshButton;

    /* handler for the 1000ms timer which updates the TOTP view, if present */
    private Handler timerHandler = new Handler();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences(preferencePath, MODE_PRIVATE);

        mainLayout = findViewById(R.id.mainLayout);
        showLayout = findViewById(R.id.showDataLayout);
        emptyLayout = findViewById(R.id.emptyLayout);

        tvAccountName = (TextView) findViewById(R.id.accountName);
        tvAccountIssuer = (TextView) findViewById(R.id.accountIssuer);
        tvTimeRemaining = (TextView) findViewById(R.id.timeRemaining);
        tvOtp = (TextView) findViewById(R.id.otp);
        refreshButton = (ImageButton) findViewById(R.id.refresh);
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateState();
    }

    /**
     * Decides what state the main activity is in.
     * Are we displaying no account, or a HOTP account, or a TOTP account?
     * Calls routines to draw these accordingly.
     */
    private void updateState() {
        loadAccount();
        setDisplay();
        drawAccountToLabels();
        if (accountInfo != null && accountInfo.otpType == AccountInfo.OtpType.TOTP) {
            startUpdateTimer();
        }
    }

    /**
     * Load an account from storage.
     * Returns true if an account was found and loaded successfully, else false.
     * Set 'generatorContext'.
     * Clears the account data if it's corrupted (some validation is performed, but not everything you'd want)
     */
    private boolean loadAccount() {
        if (prefs == null) {
            return false;
        }
        String accName = prefs.getString("name", null);
        String accIssuer = prefs.getString("issuer", null);
        String accSecretKey = prefs.getString("secret", null);
        int accOtpType = prefs.getInt("otptype", 99);
        int accCodeLength = prefs.getInt("codelength", 0);
        int accExtraInfo = prefs.getInt("extrainfo", -1);
        if (accName == null || accSecretKey == null || accOtpType >= AccountInfo.OtpType.values().length
                || (accCodeLength != 6 && accCodeLength != 8) || accExtraInfo == -1) {
            prefs.edit().clear().apply(); // delete the account data from storage
            accountInfo = null;
            return false;
        }
        AccountInfo.OtpType type = AccountInfo.OtpType.values()[accOtpType];
        accountInfo = new AccountInfo(accName, accIssuer, accSecretKey, accCodeLength, type, accExtraInfo);

        if (accountInfo.otpType == AccountInfo.OtpType.TOTP) {
            totpGenerator = new TotpGeneratorContext(accountInfo.secretKey, accountInfo.codeLength, HmacAlgorithm.SHA1, accountInfo.extraInfo);
            hotpGenerator = null;
        } else {
            hotpGenerator = new HotpGeneratorContext(accountInfo.secretKey, accountInfo.codeLength, HmacAlgorithm.SHA1, accountInfo.extraInfo);
            totpGenerator = null;
        }
        return true;
    }

    /**
     * Decide which views should be visible on screen, and set their text based on accountInfo.
     */
    private void setDisplay() {
        if (accountInfo == null) {
            emptyLayout.setVisibility(View.VISIBLE);
            showLayout.setVisibility(View.GONE);
            return;
        }
        emptyLayout.setVisibility(View.GONE);
        showLayout.setVisibility(View.VISIBLE);
        if (accountInfo.otpType == AccountInfo.OtpType.HOTP) {
            tvTimeRemaining.setVisibility(View.GONE);
            refreshButton.setVisibility(View.VISIBLE);
        } else if (accountInfo.otpType == AccountInfo.OtpType.TOTP) {
            tvTimeRemaining.setVisibility(View.VISIBLE);
            refreshButton.setVisibility(View.GONE);
        } // else don't modify
    }

    /**
     * Update text on-screen with the current OTP info (incl. account info as well as OTP details).
     * See also updateRemainingTimeRunnable() which changes the text colour.
     */
    private void drawAccountToLabels() {
        if (accountInfo == null) {
            return;
        } // assume the empty layout is active
        tvAccountName.setText(accountInfo.name);
        tvAccountIssuer.setText(accountInfo.issuer);

        if (accountInfo.otpType == AccountInfo.OtpType.TOTP) {
            tvOtp.setText(totpGenerator.create());
        } else {
            tvOtp.setText(hotpGenerator.create());
        }
    }


    public void onClickRefreshButton(View v) {
        if (accountInfo.otpType == AccountInfo.OtpType.TOTP) {
            Log.w(TAG, "refresh button pressed, but account is in TOTP mode: taking no action");
            return;
        }
        accountInfo.extraInfo++; // this represents the HOTP counter
        AccountInfo.saveAccount(this, accountInfo);
        drawAccountToLabels();
    }

    public void onClickTrashAccount(View v) {
        getSharedPreferences(preferencePath, MODE_PRIVATE).edit().clear().apply();
        updateState();
    }

    /** When the user taps the "scan" button, launch the SDK's scan activity, which returns to onActivityResult. */
    public void onClickScanCode(View v) {
        Intent intent = new Intent(this, UIQRScanView.class);
        startActivityForResult(intent, scanQRrequest);
    }

    /** After the scan returns, if it contains an OtpQRScanResult, set that as the AccountInfo.
     * If that's unsuccessful, do nothing. */
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == scanQRrequest && data != null) {
            Object resultCandidate = data.getExtras().get(IQRScanResult.class.getName());
            if (resultCandidate instanceof OtpQRScanResult) {
                OtpQRScanResult result = (OtpQRScanResult) resultCandidate;
                AccountInfo.OtpType type;
                int periodOrCounter;
                if (result.getType().equals("hotp")) {
                    type = AccountInfo.OtpType.HOTP;
                    periodOrCounter = result.getCounter();
                } else {
                    type = AccountInfo.OtpType.TOTP;
                    periodOrCounter = result.getPeriod();
                }
                AccountInfo accountInfo = new AccountInfo(result.getUsername(), result.getIssuer(), result.getSecret(), result.getDigits(), type, periodOrCounter);
                AccountInfo.saveAccount(this, accountInfo);
                // onActivityResult -> onResume -> updateState(), so generator contexts will be updated
                return;
            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }





    /**
     * Kick off the timer which runs updateRemainingTimeRunnable every second.
     * Runs immediately and every second after.
     */
    private void startUpdateTimer() {
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                timerHandler.post(updateRemainingTimeRunnable);
            }
        }, 1000, 1000);
        timerHandler.post(updateRemainingTimeRunnable);
    }

    /**
     * Update the 'time remaining' label.
     */
    private Runnable updateRemainingTimeRunnable = new Runnable() {
        @Override
        public void run() {
            if (accountInfo == null || accountInfo.otpType == AccountInfo.OtpType.HOTP) {
                return;
            }
            int interval = accountInfo.extraInfo;
            int remainingTime = TotpGeneratorContext.remainingTime(interval);
            if (remainingTime <= 10) {
                tvTimeRemaining.setTextColor(Color.rgb(255, 128, 0));
            } else {
                tvTimeRemaining.setTextColor(Color.BLACK);
            }
            tvTimeRemaining.setText(getResources().getQuantityString(R.plurals.seconds_remaining, remainingTime, remainingTime));
            if (remainingTime >= interval) {
                tvOtp.setText(totpGenerator.create());
            }
        }
    };


    /** The barcode detection requires Google Play Services, so we check && show the update prompt.
     * If you're using an emulator, it's almost certainly unable to update.
     * https://code.google.com/p/android/issues/detail?id=212879 */
    @Override
    protected void onStart() {
        super.onStart();
        int hasPlayServices = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this);
        if (hasPlayServices != ConnectionResult.SUCCESS) {
            GoogleApiAvailability.getInstance().getErrorDialog(this, hasPlayServices, 0).show();
        }
    }

}
