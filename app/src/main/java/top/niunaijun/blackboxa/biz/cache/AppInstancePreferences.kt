package top.niunaijun.blackboxa.biz.cache

import android.content.Context
import android.content.SharedPreferences

/** Host-owned policy storage for one virtual app, independent of guest app data. */
object AppInstancePreferences {
    fun name(packageName: String, userId: Int): String {
        require(packageName.isNotBlank() && '/' !in packageName && '\\' !in packageName)
        require(userId >= 0)
        return "AppInstancePreferences_${userId}_$packageName"
    }

    fun open(context: Context, packageName: String, userId: Int): SharedPreferences =
        context.getSharedPreferences(name(packageName, userId), Context.MODE_PRIVATE)
}
