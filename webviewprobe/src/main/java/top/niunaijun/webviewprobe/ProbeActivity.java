package top.niunaijun.webviewprobe;

import android.app.Activity;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.app.role.RoleManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.ConsoleMessage;
import android.webkit.CookieManager;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.HttpsURLConnection;

/** An intentionally ordinary Android/WebView diagnostic application. */
public abstract class ProbeActivity extends Activity {
    private static final String TAG = "WVPROBE";
    private static final String LOCAL = "file:///android_asset/webviewprobe.html";
    private static final int MAX_LINES = 180;
    private static final AtomicLong ACTIONS = new AtomicLong();

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ArrayDeque<String> lines = new ArrayDeque<>();
    private LinearLayout webSlot;
    private EditText destination;
    private TextView eventLog;
    private WebView webView;
    private volatile long webAction;

    protected abstract boolean isSecondary();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        buildUi();
        emit(0, "APP", "READY process=" + processName());
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(8);
        root.setPadding(pad, pad, pad, pad);

        destination = new EditText(this);
        destination.setSingleLine(true);
        destination.setText("https://example.com/");
        destination.setHint("HTTPS test URL");
        root.addView(destination, matchWrap());

        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.VERTICAL);
        add(buttons, "ENV", this::environment);
        add(buttons, "DNS ONLY", () -> dns(null));
        add(buttons, "RAW TCP", this::rawTcp);
        add(buttons, "HTTP URLCONNECTION", () -> http(null));
        add(buttons, "CREATE WEBVIEW", this::createWebView);
        add(buttons, "DESTROY WEBVIEW", this::destroyWebView);
        add(buttons, "RESET WEBVIEW STATE", this::resetWebView);
        add(buttons, "LOAD LOCAL HARNESS", this::loadLocal);
        add(buttons, "TOP LEVEL LOAD", () -> topLevel(false));
        add(buttons, "TOP LEVEL POST", () -> topLevel(true));
        add(buttons, "JS LOCATION", () -> js("JS_LOCATION", "goLocation", true));
        add(buttons, "FETCH", () -> js("FETCH", "doFetch", true));
        add(buttons, "XHR", () -> js("XHR", "doXhr", true));
        add(buttons, "IMG", () -> js("IMG", "addImg", true));
        add(buttons, "IFRAME", () -> js("IFRAME", "addFrame", true));
        add(buttons, "FORM GET", () -> form("GET"));
        add(buttons, "FORM POST", () -> form("POST"));
        add(buttons, "RUN CORE MATRIX", this::coreMatrix);
        add(buttons, "ROLE CHECK", this::roleCheck);
        add(buttons, "JOBSCHEDULER CHECK", this::jobCheck);
        if (!isSecondary()) add(buttons, "OPEN SECONDARY PROCESS", this::openSecondary);
        add(buttons, "CLEAR LOG", this::clearLog);
        add(buttons, "KILL SELF", this::killSelf);

        ScrollView controls = new ScrollView(this);
        controls.addView(buttons);
        root.addView(controls, new LinearLayout.LayoutParams(-1, 0, 0.34f));

        webSlot = new LinearLayout(this);
        webSlot.setOrientation(LinearLayout.VERTICAL);
        root.addView(webSlot, new LinearLayout.LayoutParams(-1, 0, 0.36f));

        eventLog = new TextView(this);
        eventLog.setTextIsSelectable(true);
        eventLog.setTextSize(11);
        ScrollView logScroll = new ScrollView(this);
        logScroll.addView(eventLog);
        root.addView(logScroll, new LinearLayout.LayoutParams(-1, 0, 0.30f));
        setContentView(root);
    }

    private void add(LinearLayout parent, String text, Runnable action) {
        Button b = new Button(this);
        b.setText(text);
        b.setOnClickListener(v -> action.run());
        parent.addView(b, matchWrap());
    }

    private LinearLayout.LayoutParams matchWrap() { return new LinearLayout.LayoutParams(-1, -2); }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }

    private long begin(String type) {
        long id = ACTIONS.incrementAndGet();
        emit(id, type, "ENTER");
        return id;
    }

    private void emit(long id, String type, String message) {
        String line = "action=" + id + " type=" + type + " " + message;
        Log.i(TAG, line);
        main.post(() -> {
            if (eventLog == null) return;
            lines.addLast(line);
            while (lines.size() > MAX_LINES) lines.removeFirst();
            StringBuilder out = new StringBuilder();
            for (String item : lines) out.append(item).append('\n');
            eventLog.setText(out);
        });
    }

    private void clearLog() {
        long id = begin("CLEAR_LOG");
        lines.clear();
        eventLog.setText("");
        emit(id, "CLEAR_LOG", "EXIT");
    }

    private URL testUrl(long id) throws Exception {
        Uri parsed = Uri.parse(destination.getText().toString().trim());
        if (!"https".equalsIgnoreCase(parsed.getScheme()) || parsed.getHost() == null) {
            throw new IllegalArgumentException("destination must be an HTTPS URL with a host");
        }
        return new URL(parsed.buildUpon().appendQueryParameter("wvprobe_action", Long.toString(id)).build().toString());
    }

    private void environment() {
        long id = begin("ENV");
        String provider = "unavailable";
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                android.content.pm.PackageInfo p = WebView.getCurrentWebViewPackage();
                if (p != null) provider = p.packageName + "/" + p.versionName;
            }
        } catch (RuntimeException e) { provider = "error:" + e.getClass().getSimpleName(); }
        emit(id, "ENV", "pid=" + Process.myPid() + " uid=" + Process.myUid()
                + " process=" + processName() + " package=" + getPackageName()
                + " api=" + Build.VERSION.SDK_INT + " webviewProvider=" + provider);
        emit(id, "ENV", "EXIT");
    }

    private String processName() {
        if (Build.VERSION.SDK_INT >= 28) return android.app.Application.getProcessName();
        return getPackageName() + (isSecondary() ? ":wv2" : "");
    }

    private void dns(Runnable done) {
        long id = begin("DNS_ONLY");
        final String host;
        try { host = testUrl(id).getHost(); }
        catch (Exception e) { failure(id, "DNS_ONLY", e); runDone(done); return; }
        worker.execute(() -> {
            try {
                InetAddress[] values = InetAddress.getAllByName(host);
                int v4 = 0, v6 = 0;
                for (InetAddress value : values) {
                    if (value.getAddress().length == 4) v4++; else v6++;
                }
                emit(id, "DNS_ONLY", "RESULT count=" + values.length + " ipv4=" + v4 + " ipv6=" + v6);
            } catch (Exception e) { failure(id, "DNS_ONLY", e); }
            emit(id, "DNS_ONLY", "EXIT"); runDone(done);
        });
    }

    private void rawTcp() {
        long id = begin("RAW_TCP");
        final URL url;
        try { url = testUrl(id); } catch (Exception e) { failure(id, "RAW_TCP", e); return; }
        worker.execute(() -> {
            try (Socket socket = new Socket()) {
                int port = url.getPort() > 0 ? url.getPort() : 443;
                socket.connect(new InetSocketAddress(url.getHost(), port), 10000);
                emit(id, "RAW_TCP", "CONNECT_SUCCESS");
            } catch (Exception e) { failure(id, "RAW_TCP", e); }
            emit(id, "RAW_TCP", "EXIT");
        });
    }

    private void http(Runnable done) {
        long id = begin("HTTP_URLCONNECTION");
        final URL url;
        try { url = testUrl(id); } catch (Exception e) { failure(id, "HTTP_URLCONNECTION", e); runDone(done); return; }
        worker.execute(() -> {
            HttpURLConnection c = null;
            try {
                c = (HttpURLConnection) url.openConnection();
                c.setConnectTimeout(10000); c.setReadTimeout(10000);
                c.setUseCaches(false); c.setRequestMethod("GET");
                int status = c.getResponseCode();
                InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
                int bytes = 0;
                if (in != null) { byte[] buf = new byte[256]; bytes = Math.max(0, in.read(buf)); in.close(); }
                emit(id, "HTTP_URLCONNECTION", "RESPONSE status=" + status + " sampleBytes=" + bytes);
            } catch (Exception e) { failure(id, "HTTP_URLCONNECTION", e); }
            finally { if (c != null) c.disconnect(); }
            emit(id, "HTTP_URLCONNECTION", "EXIT"); runDone(done);
        });
    }

    private void failure(long id, String type, Throwable e) {
        String errno = e.getCause() == null ? "none" : e.getCause().getClass().getSimpleName();
        emit(id, type, "FAIL exception=" + e.getClass().getSimpleName() + " cause=" + errno);
    }

    private void runDone(Runnable done) { if (done != null) main.post(done); }

    @SuppressWarnings("SetJavaScriptEnabled")
    private void createWebView() {
        long id = begin("CREATE_WEBVIEW");
        if (webView != null) { emit(id, "CREATE_WEBVIEW", "ALREADY_CREATED EXIT"); return; }
        try {
            webView = new WebView(this);
            WebSettings s = webView.getSettings();
            s.setJavaScriptEnabled(true);
            s.setCacheMode(WebSettings.LOAD_NO_CACHE);
            s.setDomStorageEnabled(true);
            webView.setWebViewClient(new ObserverClient());
            webView.setWebChromeClient(new ObserverChrome());
            webSlot.addView(webView, new LinearLayout.LayoutParams(-1, -1));
            emit(id, "CREATE_WEBVIEW", "CREATED EXIT");
        } catch (RuntimeException e) { failure(id, "CREATE_WEBVIEW", e); emit(id, "CREATE_WEBVIEW", "EXIT"); }
    }

    private void destroyWebView() {
        long id = begin("DESTROY_WEBVIEW");
        if (webView == null) { emit(id, "DESTROY_WEBVIEW", "NOT_CREATED EXIT"); return; }
        webSlot.removeView(webView); webView.stopLoading(); webView.destroy(); webView = null;
        emit(id, "DESTROY_WEBVIEW", "DESTROYED EXIT");
    }

    private void resetWebView() {
        long id = begin("RESET_WEBVIEW_STATE");
        try {
            if (webView != null) { webView.stopLoading(); webView.clearCache(true); webView.clearHistory(); webView.clearFormData(); }
            CookieManager.getInstance().removeAllCookies(value -> emit(id, "RESET_WEBVIEW_STATE", "COOKIES_REMOVED=" + value));
            CookieManager.getInstance().flush();
            android.webkit.WebStorage.getInstance().deleteAllData();
            emit(id, "RESET_WEBVIEW_STATE", "EXIT");
        } catch (RuntimeException e) { failure(id, "RESET_WEBVIEW_STATE", e); emit(id, "RESET_WEBVIEW_STATE", "EXIT"); }
    }

    private boolean requireWeb(long id, String type) {
        if (webView != null) return true;
        emit(id, type, "NOT_CREATED EXIT"); return false;
    }

    private void loadLocal() {
        long id = begin("LOAD_LOCAL_HARNESS");
        if (!requireWeb(id, "LOAD_LOCAL_HARNESS")) return;
        webAction = id; webView.loadUrl(LOCAL); emit(id, "LOAD_LOCAL_HARNESS", "REQUESTED");
    }

    private void topLevel(boolean post) {
        String type = post ? "TOP_LEVEL_POST" : "TOP_LEVEL_LOAD";
        long id = begin(type);
        if (!requireWeb(id, type)) return;
        try {
            String url = testUrl(id).toString(); webAction = id;
            if (post) webView.postUrl(url, "webviewprobe=1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            else webView.loadUrl(url);
            emit(id, type, "REQUESTED");
        } catch (Exception e) { failure(id, type, e); emit(id, type, "EXIT"); }
    }

    private void js(String type, String function, boolean argument) {
        long id = begin(type);
        if (!requireWeb(id, type)) return;
        try {
            String code = function + "(" + (argument ? org.json.JSONObject.quote(testUrl(id).toString()) : "") + ")";
            webAction = id;
            webView.evaluateJavascript(code, value -> emit(id, type, "JS_COMPLETION EXIT"));
            emit(id, type, "REQUESTED");
        } catch (Exception e) { failure(id, type, e); emit(id, type, "EXIT"); }
    }

    private void form(String method) {
        String type = "FORM_" + method;
        long id = begin(type);
        if (!requireWeb(id, type)) return;
        try {
            String code = "submitForm(" + org.json.JSONObject.quote(testUrl(id).toString()) + "," + org.json.JSONObject.quote(method) + ")";
            webAction = id; webView.evaluateJavascript(code, value -> emit(id, type, "JS_COMPLETION EXIT"));
            emit(id, type, "REQUESTED");
        } catch (Exception e) { failure(id, type, e); emit(id, type, "EXIT"); }
    }

    private void coreMatrix() {
        long id = begin("CORE_MATRIX");
        if (!requireWeb(id, "CORE_MATRIX")) return;
        emit(id, "CORE_MATRIX", "STEP native-dns");
        dns(() -> { emit(id, "CORE_MATRIX", "STEP native-https"); http(() -> matrixWeb(id)); });
    }

    private void matrixWeb(long matrixId) {
        emit(matrixId, "CORE_MATRIX", "STEP top-level"); topLevel(false);
        main.postDelayed(() -> { emit(matrixId, "CORE_MATRIX", "STEP local-harness"); loadLocal(); }, 8000);
        main.postDelayed(() -> { emit(matrixId, "CORE_MATRIX", "STEP img"); js("IMG", "addImg", true); }, 10000);
        main.postDelayed(() -> { emit(matrixId, "CORE_MATRIX", "STEP local-harness-reload"); loadLocal(); }, 18000);
        main.postDelayed(() -> { emit(matrixId, "CORE_MATRIX", "STEP fetch"); js("FETCH", "doFetch", true); emit(matrixId, "CORE_MATRIX", "EXIT"); }, 20000);
    }

    private void roleCheck() {
        long id = begin("ROLE_CHECK");
        if (Build.VERSION.SDK_INT < 29) { emit(id, "ROLE_CHECK", "UNSUPPORTED EXIT"); return; }
        try {
            RoleManager r = (RoleManager) getSystemService(Context.ROLE_SERVICE);
            boolean available = r != null && r.isRoleAvailable(RoleManager.ROLE_BROWSER);
            boolean held = r != null && r.isRoleHeld(RoleManager.ROLE_BROWSER);
            emit(id, "ROLE_CHECK", "available=" + available + " held=" + held + " EXIT");
        } catch (RuntimeException e) { failure(id, "ROLE_CHECK", e); emit(id, "ROLE_CHECK", "EXIT"); }
    }

    private void jobCheck() {
        long id = begin("JOBSCHEDULER_CHECK");
        try {
            JobScheduler scheduler = (JobScheduler) getSystemService(JOB_SCHEDULER_SERVICE);
            JobInfo info = new JobInfo.Builder(41001, new ComponentName(this, ProbeJobService.class))
                    .setMinimumLatency(1000).setOverrideDeadline(10000).build();
            int result = scheduler.schedule(info);
            emit(id, "JOBSCHEDULER_CHECK", "scheduleResult=" + result + " EXIT");
        } catch (RuntimeException e) { failure(id, "JOBSCHEDULER_CHECK", e); emit(id, "JOBSCHEDULER_CHECK", "EXIT"); }
    }

    private void openSecondary() {
        long id = begin("OPEN_SECONDARY");
        try { startActivity(new Intent(this, SecondaryActivity.class)); emit(id, "OPEN_SECONDARY", "REQUESTED EXIT"); }
        catch (RuntimeException e) { failure(id, "OPEN_SECONDARY", e); emit(id, "OPEN_SECONDARY", "EXIT"); }
    }

    private void killSelf() {
        long id = begin("KILL_SELF"); emit(id, "KILL_SELF", "EXIT killing pid=" + Process.myPid());
        main.postDelayed(() -> Process.killProcess(Process.myPid()), 100);
    }

    @Override protected void onDestroy() {
        if (webView != null) { webSlot.removeView(webView); webView.destroy(); webView = null; }
        worker.shutdownNow(); super.onDestroy();
    }

    private final class ObserverClient extends WebViewClient {
        private void callback(String name, boolean mainFrame, String method, String scheme) {
            emit(webAction, "WEBVIEW_CALLBACK", "callback=" + name + " mainFrame=" + mainFrame
                    + " method=" + safe(method) + " scheme=" + safe(scheme));
        }
        @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            callback("shouldOverrideUrlLoading", request.isForMainFrame(), request.getMethod(), request.getUrl().getScheme()); return false;
        }
        @Override public boolean shouldOverrideUrlLoading(WebView view, String url) {
            callback("shouldOverrideUrlLoadingLegacy", true, "unknown", Uri.parse(url).getScheme()); return false;
        }
        @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
            callback("shouldInterceptRequest", request.isForMainFrame(), request.getMethod(), request.getUrl().getScheme()); return null;
        }
        @Override public WebResourceResponse shouldInterceptRequest(WebView view, String url) {
            callback("shouldInterceptRequestLegacy", false, "unknown", Uri.parse(url).getScheme()); return null;
        }
        @Override public void onPageStarted(WebView view, String url, Bitmap favicon) {
            callback("onPageStarted", true, "unknown", Uri.parse(url).getScheme());
        }
        @Override public void onPageFinished(WebView view, String url) {
            callback("onPageFinished", true, "unknown", Uri.parse(url).getScheme());
        }
        @Override public void onReceivedError(WebView view, WebResourceRequest req, WebResourceError error) {
            callback("onReceivedError(code=" + error.getErrorCode() + ")", req.isForMainFrame(), req.getMethod(), req.getUrl().getScheme());
        }
        @Override public void onReceivedHttpError(WebView view, WebResourceRequest req, WebResourceResponse response) {
            callback("onReceivedHttpError(status=" + response.getStatusCode() + ")", req.isForMainFrame(), req.getMethod(), req.getUrl().getScheme());
        }
        @Override public void onReceivedSslError(WebView view, SslErrorHandler handler, android.net.http.SslError error) {
            callback("onReceivedSslError(cancelled,primary=" + error.getPrimaryError() + ")", true, "unknown", "https"); handler.cancel();
        }
        @Override public boolean onRenderProcessGone(WebView view, RenderProcessGoneDetail detail) {
            emit(webAction, "WEBVIEW_CALLBACK", "callback=onRenderProcessGone didCrash=" + detail.didCrash()); return false;
        }
    }

    private final class ObserverChrome extends WebChromeClient {
        private int lastBucket = -1;
        @Override public boolean onConsoleMessage(ConsoleMessage message) {
            String text = message.message() == null ? "" : message.message();
            if (text.startsWith("WVPROBE_JS ")) text = text.substring(11);
            else text = "page-console";
            emit(webAction, "WEBVIEW_CONSOLE", "level=" + message.messageLevel() + " message=" + scrub(text));
            return false;
        }
        @Override public void onProgressChanged(WebView view, int progress) {
            int bucket = progress / 25;
            if (bucket != lastBucket || progress == 100) { lastBucket = bucket; emit(webAction, "WEBVIEW_PROGRESS", "value=" + progress); }
        }
    }

    private static String safe(String value) { return value == null ? "unknown" : value; }
    private static String scrub(String text) {
        String result = text.replaceAll("(?i)https?://\\S+", "[url]").replaceAll("[\\r\\n]+", " ");
        return result.length() > 120 ? result.substring(0, 120) : result;
    }
}
