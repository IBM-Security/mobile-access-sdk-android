# Simple Authenticator

This sample app can:

- scan a QR code using the SDK's `UIQRScanView`
- parse it using `OtpQRScanResult`
- generate OTPs using `TotpGeneratorContext` and `HotpGeneratorContext`

It supports one account at a time.

### Setup

Follow the **download steps** in [Getting the SDK](../../getting-the-sdk.md) and drop it into `app/libs`. You won't need the **configuration steps**.

### Caveats

It's best to run this on a real phone, for Google Play Services and a real camera.

It depends on Google Play Services for QR code detection, and the emulator images provided are frequently out of date ([it keeps happening](https://code.google.com/p/android/issues/detail?id=212879)). In this case, the barcode detector will refuse to run without an update, and the emulator will be unable to update. So it's effectively unable to scan QR codes.

If you use an emulator and Google Play Services is up to date on that image, be sure to hook up a camera (AVD Manager -> edit device -> show advanced -> rear camera).

## Licence

    Copyright 2017 International Business Machines

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
