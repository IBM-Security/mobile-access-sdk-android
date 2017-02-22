/*
 * Copyright 2016 International Business Machines
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
import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.Nullable;
import android.util.Log;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Information about the singleton OTP account stored in SharedPreferences.
 * Doesn't do all the validation you'll want to do in a production app.
 */
class AccountInfo {

    public String name;
    public String issuer;
    public String secretKey;
    public OtpType otpType;
    public int codeLength;
    public int extraInfo; // if HOTP, interval; if TOTP, counter

    private static Pattern sPattern = Pattern.compile("otpauth://([ht]otp)/([^\\?]+)\\?(.*)");

    private static final String TAG = "AccountInfo";

    enum OtpType {
        HOTP, TOTP
    }

    /** Does not validate parameters!
     * */
    AccountInfo(String name, String issuer, String secretKey, int codeLength, OtpType otpType, int extraInfo) {
        this.name = name;
        this.issuer = issuer;
        this.secretKey = secretKey;
        this.otpType = otpType;
        this.codeLength = codeLength;
        this.extraInfo = extraInfo;
    }

    static void saveAccount(Context context, AccountInfo accountInfo) {
        if (accountInfo == null) { Log.d(TAG, "saveAccount: Called without a valid account; this method expects a valid accountInfo instance"); return; }
        SharedPreferences prefs = context.getSharedPreferences(MainActivity.preferencePath, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("name", accountInfo.name);
        editor.putString("issuer", accountInfo.issuer);
        editor.putString("secret", accountInfo.secretKey);
        editor.putInt("otptype", accountInfo.otpType.ordinal());
        editor.putInt("codelength", accountInfo.codeLength);
        editor.putInt("extrainfo", accountInfo.extraInfo);
        editor.commit();
    }

}
