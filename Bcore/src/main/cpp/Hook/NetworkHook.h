#ifndef BLACKBOX_NETWORKHOOK_H
#define BLACKBOX_NETWORKHOOK_H

#include <jni.h>

class NetworkHook {
public:
    // Configuration is copied during guest bootstrap; connect() never calls Java.
    static void configure(JNIEnv *env, bool enabled, jstring host, int port,
                          jstring user, jstring password, jstring flowSocketPath);
    static void init();
};

#endif
