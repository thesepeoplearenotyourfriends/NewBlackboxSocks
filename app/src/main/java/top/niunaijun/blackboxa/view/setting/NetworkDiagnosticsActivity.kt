package top.niunaijun.blackboxa.view.setting

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import top.niunaijun.blackbox.proxy.ProxyVpnService
import top.niunaijun.blackboxa.R
import top.niunaijun.blackboxa.databinding.ActivityNetworkDiagnosticsBinding
import top.niunaijun.blackboxa.util.inflate
import top.niunaijun.blackboxa.util.toast
import top.niunaijun.blackboxa.view.base.BaseActivity

class NetworkDiagnosticsActivity : BaseActivity() {
    private val viewBinding: ActivityNetworkDiagnosticsBinding by inflate()
    private val handler = Handler(Looper.getMainLooper())
    private val refresh = object : Runnable {
        override fun run() {
            refreshSummary()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(viewBinding.root)
        initToolbar(viewBinding.toolbarLayout.toolbar, R.string.network_diagnostics, true)
        viewBinding.resetDiagnostics.setOnClickListener {
            ProxyVpnService.resetDiagnostics()
            refreshSummary()
            toast(R.string.network_diagnostics_reset_done)
        }
        viewBinding.copyDiagnostics.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText(getString(R.string.network_diagnostics), summary()))
            toast(R.string.network_diagnostics_copied)
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    private fun summary(): String {
        return ProxyVpnService.getDiagnosticsSnapshot().toPlainText(true)
    }

    private fun refreshSummary() {
        val current = summary()
        // Avoid replacing selectable text or disturbing accessibility when idle.
        if (viewBinding.diagnosticsText.text.toString() != current) {
            viewBinding.diagnosticsText.text = current
        }
    }
}
