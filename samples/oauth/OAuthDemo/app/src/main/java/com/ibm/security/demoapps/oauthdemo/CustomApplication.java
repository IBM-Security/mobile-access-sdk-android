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

package com.ibm.security.demoapps.oauthdemo;

import android.app.Application;

import com.ibm.security.access.mobile.authentication.ContextHelper;

/**
 * The custom Application implementation hooks into the Mobile Access SDK's ContextHelper.
 */

public class CustomApplication extends Application {
    @Override
    public void onCreate() {
        ContextHelper.sharedInstance().setContext(getApplicationContext()); // done once by the app
        super.onCreate();
    }
}
