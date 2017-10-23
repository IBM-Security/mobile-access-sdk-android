package com.ibm.security.demoapps.qrcodescan;

import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.ibm.security.access.mobile.authentication.ContextHelper;
import com.ibm.security.access.mobile.authentication.IQRScanResult;
import com.ibm.security.access.mobile.authentication.OtpQRScanResult;
import com.ibm.security.access.mobile.authentication.UIQRScanView;

public class MainActivity extends AppCompatActivity {

    private final int SCAN_QR_REQUEST = 42;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ContextHelper.sharedInstance().setContext(getApplicationContext());
    }

    public void onClickScanQRCode(View v) {

        Intent intent = new Intent(getApplicationContext(), UIQRScanView.class);
        startActivityForResult(intent, SCAN_QR_REQUEST);
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {

        String newLine = System.getProperty("line.separator");

        if (requestCode == SCAN_QR_REQUEST && data != null) {

            Object resultCandidate = data.getExtras().get(IQRScanResult.class.getName());

            if (resultCandidate instanceof OtpQRScanResult) {
                OtpQRScanResult result = (OtpQRScanResult) resultCandidate;

                StringBuilder stringBuilder = new StringBuilder()
                        .append("Username: " + result.getUsername()).append(newLine)
                        .append("Issuer: " + result.getIssuer()).append(newLine)
                        .append("Secret: " + result.getSecret()).append(newLine)
                        .append("Type: " + result.getType()).append(newLine)
                        .append("Algorithm: " + result.getAlgorithm().name()).append(newLine)
                        .append("Digits: " + result.getDigits()).append(newLine)
                        .append("Counter: " + result.getCounter()).append(newLine)
                        .append("Period: " + result.getPeriod());

                showDialog(stringBuilder.toString());
            } else {
                showToast("Unknown type of QR code detected");
            }
        }
    }

    private void showToast(final String message) {

        Toast toast = Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT);
        toast.setGravity(Gravity.CENTER, 0, 0);
        toast.show();
    }

    private void showDialog(final String message) {

        if (message == null || message.isEmpty()) {
            showToast("Something went wrong");
        } else {
            TextView tvTitle = new TextView(this);
            tvTitle.setText("QR Code Scan Sample");
            tvTitle.setPadding(10, 30, 10, 30);
            tvTitle.setGravity(Gravity.CENTER);
            tvTitle.setTextColor(Color.BLACK);
            tvTitle.setTextSize(20);

            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setCustomTitle(tvTitle)
                    .setMessage(message)
                    .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialogInterface, int i) {

                        }
                    });

            AlertDialog alertDialog = builder.create();
            alertDialog.show();

            Button okButton = alertDialog.getButton(DialogInterface.BUTTON_POSITIVE);
            okButton.setTextColor(Color.BLACK);
        }
    }
}
