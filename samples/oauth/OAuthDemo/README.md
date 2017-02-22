IBM OAuth demo app
------------------

This app is intended as a practical demonstration on using the OAuth features of the IBM Access Mobile SDK.

It can request and refresh OAuth tokens using the Resource Owner Protected Credentials (ROPC) grant.

### Setup

Follow the **download steps** in [Getting the SDK](../../../../samples/getting-the-sdk.md) and drop it into `app/libs`. You won't need the **configuration steps**.


### App notes
- Set your OAuth defaults in `oauth_credentials.xml`. It's intended to minimise time spent reconfiguring.
- Pay attention to the `AsyncTask` implementations in TokenViewActivity.

### Tips for debugging
- If you see a `CertPathValidatorException`, there's something wrong with the test server's certificate chain: commonly it's self-signed. The SDK allows you to do [custom certificate validation](../../../../documentation/certificate-pinning.md).
- The activity-scope handling of `authResult` and `mAuthTask` are intended to simplify the code, but remember that they're done that way.

## Licence

    Copyright 2016 International Business Machines

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
