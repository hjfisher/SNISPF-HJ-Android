// Android NDK JNI wrapper for android.system.Os.setsocknetwork (API level 26+)
// Required for raw socket injection on Android (AF_PACKET lift)

#include <jni.h>
#include <android/api-level.h>
#include <android/system/core/jni/android_system_os.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>

// Cache for the JNI method reference
static jmethodID g_setsocknetwork_method = nullptr;
static jclass g_android_os_class = nullptr;

// Forward declarations
static jint get_setsocknetwork_method(JNIEnv *env);

// This function is the JNI implementation of SetSockNetwork.
// It calls android.system.Os.setsocknetwork(int) to grant CAP_NET_RAW-like permissions.
// Returns: 0 on success, <0 on JNI exception (set via exception) or fd error.

static jint jni_set_sock_network(JNIEnv *env, jclass, jint fd) {
    if (fd < 0) {
        return -EINVAL;
    }

    jobject androidOsObject = nullptr;
    if (g_android_os_class != nullptr && g_setsocknetwork_method != nullptr) {
        androidOsObject = env->AllocObject(g_android_os_class);
        if (androidOsObject == nullptr) {
            return -ENOMEM;
        }
    }

    jint result = 0;
    if (androidOsObject != nullptr) {
        // Call android.system.Os.setsocknetwork(fd)
        result = env->CallIntMethod(androidOsObject, g_setsocknetwork_method, fd);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            result = -EACCES;
        }
        env->DeleteLocalRef(androidOsObject);
    } else {
        // On older Android versions or if JNI binding fails, treat as soft failure
        result = -ENOTSUP;
    }

    if (result != 0) {
        return -errno;
    }

    // Successfully lifted the restriction.
    return 0;
}

// Initialize JNI references
static jint init_jni_refs(JNIEnv *env) {
    // Find android/system/core/jni/android_system_os class
    jclass local_android_os_class = env->FindClass("android/system/core/jni/android_system_os");
    if (local_android_os_class == nullptr) {
        return -ENOENT;
    }

    // Get the setsocknetwork method ID
    jmethodID local_method = env->GetStaticMethodID(local_android_os_class, "setsocknetwork", "(I)I");
    if (local_method == nullptr) {
        env->DeleteLocalRef(local_android_os_class);
        return -ENOENT;
    }

    g_android_os_class = (jclass)env->NewGlobalRef(local_android_os_class);
    g_setsocknetwork_method = (jmethodID)env->NewGlobalRef(local_method);
    env->DeleteLocalRef(local_android_os_class);

    return 0;
}

// JNI registration
static JNINativeMethod methods[] = {
    {"SetSockNetwork", "(I)I", (void*)jni_set_sock_network}
};

// Register the native method with the Android class.
JNIEXPORT jint JNICALL Java_com_snispf_android_androidnative_AndroidNative_setSockNetwork(
    JNIEnv *env, jclass clazz, jint fd) {

    // Initialize JNI references on first call
    static bool initialized = false;
    if (!initialized) {
        if (init_jni_refs(env) != 0) {
            return -ENOMEM;
        }
        initialized = true
    }

    jint result = jni_set_sock_network(env, clazz, fd);
    return result;
}

// JNI_OnLoad for automatic initialization
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    init_jni_refs(env);
    return JNI_VERSION_1_6;
}