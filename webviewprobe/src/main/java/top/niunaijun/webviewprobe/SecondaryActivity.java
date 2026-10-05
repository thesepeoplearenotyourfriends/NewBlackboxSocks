package top.niunaijun.webviewprobe;

import android.os.Bundle;
import android.webkit.WebView;

public final class SecondaryActivity extends ProbeActivity {
    @Override
    protected void onCreate(Bundle state) {
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            WebView.setDataDirectorySuffix("wv2");
        }
        super.onCreate(state);
    }

    @Override
    protected boolean isSecondary() {
        return true;
    }
}
