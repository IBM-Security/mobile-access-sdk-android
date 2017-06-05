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

package com.ibm.security.demoapps.oauthdemo;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.TargetApi;
import android.os.AsyncTask;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;

import org.json.JSONException;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import com.ibm.security.access.mobile.authentication.OAuthContext;
import com.ibm.security.access.mobile.authentication.OAuthResult;
import com.ibm.security.access.mobile.authentication.IAuthenticationCallback;
import com.ibm.security.access.mobile.authentication.OAuthToken;

import static com.android.volley.toolbox.Volley.newRequestQueue;

/**
 * Explore the OAuth token received from a successful login in LoginActivity.
 * Gets an access token upon start, and the user can refresh it repeatedly.
 * We have up to one {@link AsyncTask} running at a time and only one {@link OAuthResult}.
 */
public class TokenViewActivity extends AppCompatActivity {

    /** Authentication settings: see oauth_credentials.xml */
    private String username;
    private String password;
    private String host;
    private String clientId;
    private String clientSecret;
    private String protectedResourcePath;
    private String tokenEndpoint;

    /** View handles */
    private View mTokenProgressView = null;
    private View mResourceProgressView = null;
    private View mTokenStatsView = null;
    private View mResourceStatsView = null;
    private TextView tokenPrettyPrint = null;
    private TextView tokenErrorInfo = null;
    private TextView resourcePrettyPrint = null;
    private TextView resourceErrorInfo = null;

    /** The currently-running task - either a GetAccessTokenTask or RefreshAccessTokenTask - or null if no task is running.
     * This activity should only have one current task. Yours may need to be more complex. */
    private AsyncTask<Void, Void, Void> mAuthTask = null;
    /** The most recent authentication result. Upon start, this activity makes a request and populates the result.
     * This activity only has one: yours may need to be more complex. */
    private OAuthResult authResult = null;
    /** The Mobile Access SDK does not provide a means to access a protected resource, but does provide an authorization header.
     * It's up to the developer. In this case, we use the Android Volley library. This is a RequestQueue to put those resource requests into. */
    private RequestQueue requestQueue = null;

    /**
     * Activity automatically triggers an access-token request on start.
     *
     * @param savedInstanceState Android state for the activity.
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_token_view);

        initAuthDetails();
        OAuthContext.sharedInstance().setClientSecret(clientSecret);
        OAuthContext.sharedInstance().setConnectionTimeOut(5000);
        OAuthContext.sharedInstance().setReadTimeOut(5000);

        // get handles on views
        mTokenProgressView = findViewById(R.id.token_progress);
        mResourceProgressView = findViewById(R.id.resource_progress);
        mTokenStatsView = findViewById(R.id.token_stats);
        mResourceStatsView = findViewById(R.id.resource_stats);
        tokenPrettyPrint = (TextView) findViewById(R.id.token_prettyprint);
        tokenErrorInfo = (TextView) findViewById(R.id.token_error);
        resourcePrettyPrint = (TextView) findViewById(R.id.resource_prettyprint);
        resourceErrorInfo = (TextView) findViewById(R.id.resource_error);

        // initialise queue
        requestQueue = newRequestQueue(this);

        // kick off a background task to get the access token
        showTokenProgress(true);
        mAuthTask = new GetAccessTokenTask(username, password, tokenEndpoint, clientId);
        mAuthTask.execute((Void) null);
    }

    /**
     * Request a refreshed access token. This uses the OAuth refresh flow.
     */
    public void onClickRenewButton(View v) {
        if (authResult == null) {
            // the initial task hasn't returned yet: discard this input
            return;
        }
        if (authResult.hasError()) {
            Toast.makeText(TokenViewActivity.this, "Can't refresh a failed token", Toast.LENGTH_SHORT).show();
            return;
        }
        /** kick off a refresh task as the {@link mAuthTask} */
        mAuthTask = new RefreshAccessTokenTask(authResult, tokenEndpoint, clientId);
        showTokenProgress(true);
        mAuthTask.execute();
    }

    /**
     * Request the protected resource using the current access token.
     * Uses an {@link AuthenticatedStringRequest}, which is a simple example of using the Authorization header.
     * This is not part of the SDK: there are many ways to request a resource using a token and it's up to the individual developer.
     */
    public void onClickRequestResourceButton(View v) {
        if (authResult == null) {
            // the initial task hasn't returned yet: discard this input
            return;
        }
        if (authResult.hasError()) {
            Toast.makeText(TokenViewActivity.this, "Can't request with a failed token", Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            URL url = new URL(protectedResourcePath);
        } catch (MalformedURLException e) {
            Toast.makeText(TokenViewActivity.this, "Protected resource path is invalid (change in Android Studio): " + protectedResourcePath, Toast.LENGTH_SHORT).show();
            return;
        }
        // create a new request, including completion & error handlers
        AuthenticatedStringRequest request = new AuthenticatedStringRequest(Request.Method.GET, protectedResourcePath, new Response.Listener<String>() {
            @Override
            public void onResponse(String response) {
                resourcePrettyPrint.setText(response);
                resourceErrorInfo.setText(null);
                showResourceProgress(false);
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                resourcePrettyPrint.setText(null);
                resourceErrorInfo.setText(error.getMessage());
                showResourceProgress(false);
                if (error.networkResponse == null) {
                    Log.d("OAuthDemo", "onErrorResponse: Volley passed null network response");
                    if (error.getMessage() == null || error.getMessage().length() == 0) {
                        resourceErrorInfo.setText("Unknown error receiving resource response.");
                    }
                    return;
                }
                if (error.getMessage() == null || error.getMessage().length() < 1) {
                    Toast.makeText(TokenViewActivity.this, "Volley error (check the log)", Toast.LENGTH_SHORT).show();
                    resourceErrorInfo.setText("Volley error (check the log)");
                }
                else {
                    Toast.makeText(TokenViewActivity.this, error.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
                }
            }
        });
        request.setAuthorizationToken(authResult.serializeToToken().getAccessToken());
        // kick off the request
        requestQueue.add(request);
        showResourceProgress(true);
    }

    /**
     * An asynchronous login task used to get an access token.
     * The activity-scoped mAuthTask should be set to an instance of this.
     * Triggered once at the start of the TokenViewActivity.
     * {@link RefreshAccessTokenTask} is very similar.
     * This doesn't need to be <Void, Void, OAuthResult> because the callback assigns the global {@code authResult} separately.
     */
    public class GetAccessTokenTask extends AsyncTask<Void, Void, Void> {

        private final String username;
        private final String password;
        private final String tokenEndpoint;
        private final String clientId;

        GetAccessTokenTask(String username, String password, String tokenEndpoint, String clientId) {
            this.username = username;
            this.password = password;
            this.tokenEndpoint = tokenEndpoint;
            this.clientId = clientId;
        }

        /**
         * Request an access token from the host.
         * The IAuthenticationCallback in OAuthContext.getAccessToken() will assign authResult to the global scope.
         */
        @Override
        protected Void doInBackground(Void... params) {
            // Set *the* authResult to null (remember there's only one).
            // UI-wise, the caller should probably set a progress indicator before calling this.
            //  - We could do it in here, but let's give the caller the choice.
            authResult = null;
            OAuthContext.sharedInstance().getAccessToken(tokenEndpoint, clientId, username, password, new IAuthenticationCallback() {
                // Craig: what *should* it do? I think it should accept it and just do no callback
                @Override
                public void handleResult(OAuthResult OAuthResult) {
                    authResult = OAuthResult; // make the result available at activity scope
                    // Note that the callback can't update the UI directly:
                    // "android.view.ViewRootImpl$CalledFromWrongThreadException: Only the original thread that created a view hierarchy can touch its views."
                }
            });
            return null;
        }

        /*
         * Update the UI with the results of the operation.
         * NOTE: The reason we don't do this in the {@link IAuthenticationCallback} to the
         *  {@link OAuthContext.getAccessToken()} call
         *  is that that thread cannot update UI elements.
         */
        @Override
        protected void onPostExecute(Void v) {
            mAuthTask = null; // we're done, so there is no current auth task
            showTokenProgress(false); // hide the progress animation, show the results view
            updateTokenInfo();
        }

        @Override
        protected void onCancelled() {
            mAuthTask = null;
            tokenPrettyPrint.setText(null);
            tokenErrorInfo.setText("Task cancelled");
            showTokenProgress(false);
        }
    }

    /**
     * Similar to {@link GetAccessTokenTask} but with a dependency on the initial result and its refresh token.
     * The resulting messages are slightly different.
     * Triggered by pressing the refresh button in the TokenViewActivity.
     */
    public class RefreshAccessTokenTask extends AsyncTask<Void, Void, Void> {
        private String tokenEndpoint;
        private String clientId;
        private OAuthToken previousToken;
        private String previousRefreshToken;

        /**
         * initialResult must be a successful result (not null, not .hasError()) with a refresh token
         */
        RefreshAccessTokenTask(OAuthResult initialResult, String tokenEndpoint, String clientId) {
            if (initialResult == null) {
                throw new IllegalArgumentException("initial result cannot be null");
            }
            if (initialResult.hasError()) {
                throw new IllegalArgumentException("Cannot refresh from a failed token");
            }
            previousToken = initialResult.serializeToToken();
            if (previousToken == null) {
                throw new IllegalArgumentException("Failed to get previous refresh token");
            }
            previousRefreshToken = previousToken.getRefreshToken();
            if (previousRefreshToken == null || previousRefreshToken.length() == 0) {
                throw new IllegalArgumentException("No refresh token was issued in the first place");
            }
            this.tokenEndpoint = tokenEndpoint;
            this.clientId = clientId;
        }

        @Override
        protected Void doInBackground(Void... params) {
            OAuthContext.sharedInstance().refreshAccessToken(tokenEndpoint, clientId, authResult.serializeToToken().getRefreshToken(), new IAuthenticationCallback() {
                @Override
                public void handleResult(OAuthResult OAuthResult) {
                    authResult = OAuthResult; // assign it into the parent scope
                }
            });
            return null;
        }

        /**
         * Once the task is complete, this is triggered.
         */
        @Override
        protected void onPostExecute(final Void v) {
            mAuthTask = null;
            showTokenProgress(false);
            updateTokenInfo();

            if (authResult.hasError()) {
                Toast.makeText(getApplicationContext(), "Failed to refresh token", Toast.LENGTH_SHORT).show();
                // possible causes include sending the wrong refresh token to the server
            }
        }

        @Override
        protected void onCancelled() {
            mAuthTask = null;
            authResult = new OAuthResult(new InterruptedException("Task interrupted"));
            tokenPrettyPrint.setText(null);
            tokenErrorInfo.setText("Task cancelled");
            showTokenProgress(false);
        }
    }

    /**
     * A = {@link StringRequest} which can also send a bearer token.
     */
    private class AuthenticatedStringRequest extends StringRequest {
        private Map<String, String> headers;

        public AuthenticatedStringRequest(int method, String url, Response.Listener<String> listener, Response.ErrorListener errorListener) {
            super(method, url, listener, errorListener);
            headers = new HashMap<>();
        }

        /**
         * overrules any existing token
         */
        public void setAuthorizationToken(String token) {
            headers.put("Authorization", "Bearer " + token);
        }

        @Override
        public Map<String, String> getHeaders() throws AuthFailureError {
            return headers;
        }
    }

    /**
     * UI: Show token info & error based on the current authResult
     */
    private void updateTokenInfo() {
        tokenPrettyPrint.setVisibility(View.VISIBLE);
        tokenErrorInfo.setVisibility(View.VISIBLE);
        if (authResult.hasError()) {
            tokenPrettyPrint.setText(null);
            tokenErrorInfo.setText(authResult.getErrorDescription());
        } else {
            try {
                tokenErrorInfo.setText(null);
                tokenPrettyPrint.setText(authResult.serializeToJson().toString(4));
            } catch (JSONException e) {
                Toast.makeText(getApplicationContext(), "Malformed result (internal or server error)", Toast.LENGTH_LONG).show();
                tokenErrorInfo.setText(e.getMessage());
            }
        }
    }

    /**
     * Show the token progress UI and hide the results display.
     * This is purely UI - not SDK-related.
     */
    private void showTokenProgress(final boolean show) {
        int shortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

        mTokenStatsView.setVisibility(show ? View.INVISIBLE : View.VISIBLE);
        mTokenStatsView.animate().setDuration(shortAnimTime).alpha(
                show ? 0 : 1).setListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                mTokenStatsView.setVisibility(show ? View.INVISIBLE : View.VISIBLE);
            }
        });

        mTokenProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
        mTokenProgressView.animate().setDuration(shortAnimTime).alpha(
                show ? 1 : 0).setListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                mTokenProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            }
        });
    }


    /**
     * Show the resource progress UI and hide the results display.
     * This is purely UI - not SDK-related.
     */
    private void showResourceProgress(final boolean show) {
        int shortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

        mResourceStatsView.setVisibility(show ? View.GONE : View.VISIBLE);
        resourcePrettyPrint.setVisibility(View.VISIBLE);
        resourceErrorInfo.setVisibility(View.VISIBLE);
        mResourceStatsView.animate().setDuration(shortAnimTime).alpha(
                show ? 0 : 1).setListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                mResourceStatsView.setVisibility(show ? View.INVISIBLE : View.VISIBLE);
            }
        });

        mResourceProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
        mResourceProgressView.animate().setDuration(shortAnimTime).alpha(
                show ? 1 : 0).setListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                mResourceProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            }
        });
    }

    /**
     * Retrieve auth details out of the oauth_credentials file.
     */
    private void initAuthDetails() {
        username = getString(R.string.username);
        password = getString(R.string.password);
        host = getString(R.string.host);
        clientId = getString(R.string.clientId);
        clientSecret = getString(R.string.clientSecret);
        protectedResourcePath = getString(R.string.protectedResourcePath);
        String endpoint = getString(R.string.endpoint);
        tokenEndpoint = "https://" + host + endpoint;
    }
}
