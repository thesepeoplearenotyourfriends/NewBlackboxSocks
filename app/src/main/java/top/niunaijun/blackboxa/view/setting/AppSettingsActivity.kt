package top.niunaijun.blackboxa.view.setting

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.core.os.bundleOf
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import top.niunaijun.blackboxa.R
import top.niunaijun.blackboxa.biz.cache.AppInstancePreferences
import top.niunaijun.blackboxa.databinding.ActivitySettingBinding
import top.niunaijun.blackboxa.util.inflate
import top.niunaijun.blackboxa.view.base.BaseActivity

class AppSettingsActivity : BaseActivity() {
    private val viewBinding: ActivitySettingBinding by inflate()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val packageName = intent.getStringExtra(PACKAGE_NAME)
        val userId = intent.getIntExtra(USER_ID, -1)
        if (packageName.isNullOrBlank() || userId < 0) {
            finish()
            return
        }
        setContentView(viewBinding.root)
        initToolbar(viewBinding.toolbarLayout.toolbar, R.string.app_settings, true)
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.fragment, AppSettingsFragment().apply {
                    arguments = bundleOf(
                        PACKAGE_NAME to packageName,
                        USER_ID to userId,
                        APP_LABEL to intent.getStringExtra(APP_LABEL)
                    )
                }).commit()
        }
    }

    companion object {
        internal const val PACKAGE_NAME = "package_name"
        internal const val USER_ID = "user_id"
        internal const val APP_LABEL = "app_label"

        fun start(context: Context, packageName: String, userId: Int, appLabel: String) {
            context.startActivity(Intent(context, AppSettingsActivity::class.java).apply {
                putExtra(PACKAGE_NAME, packageName)
                putExtra(USER_ID, userId)
                putExtra(APP_LABEL, appLabel)
            })
        }
    }
}

class AppSettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        val args = requireArguments()
        val packageName = requireNotNull(args.getString(AppSettingsActivity.PACKAGE_NAME))
        val userId = args.getInt(AppSettingsActivity.USER_ID, -1)
        // All future controls on this screen persist to the same instance-specific store.
        preferenceManager.sharedPreferencesName = AppInstancePreferences.name(packageName, userId)
        AppInstancePreferences.open(requireContext(), packageName, userId).edit()
            .putInt("schema_version", 1).apply()
        preferenceScreen = preferenceManager.createPreferenceScreen(requireContext()).apply {
            addPreference(Preference(context).apply {
                title = args.getString(AppSettingsActivity.APP_LABEL) ?: packageName
                summary = getString(R.string.app_settings_empty)
                isSelectable = false
            })
            addPreference(Preference(context).apply {
                setTitle(R.string.app_settings_package)
                summary = packageName
                isSelectable = false
            })
            addPreference(Preference(context).apply {
                setTitle(R.string.app_settings_user)
                summary = userId.toString()
                isSelectable = false
            })
        }
    }
}
