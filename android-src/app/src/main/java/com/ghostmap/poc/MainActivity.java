package com.ghostmap.poc;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.view.Gravity;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        layout.setPadding(48, 48, 48, 48);

        TextView title = new TextView(this);
        title.setText("GhostMap PoC");
        title.setTextSize(24f);
        title.setGravity(Gravity.CENTER);

        TextView info = new TextView(this);
        info.setText("If you can see this screen, the device did NOT crash.\n\nThe GhostMap vulnerability triggers during package intake, before this activity ever runs.");
        info.setTextSize(14f);
        info.setGravity(Gravity.CENTER);
        info.setPadding(0, 32, 0, 0);

        layout.addView(title);
        layout.addView(info);
        setContentView(layout);
    }
}
