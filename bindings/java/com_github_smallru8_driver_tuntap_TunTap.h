/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
#include "converter.h"
#include "tuntap.h"

#include <Windows.h>

/* Header for class com_github_smallru8_driver_tuntap_TunTap */

#ifndef _Included_com_github_smallru8_driver_tuntap_TunTap
#define _Included_com_github_smallru8_driver_tuntap_TunTap
#ifdef __cplusplus
extern "C" {
#endif

static void onRead(char* , int);
JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1startReadWrite(JNIEnv*, jobject);
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1writeWIN(JNIEnv*, jobject,jbyteArray);
/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_init
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1init
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_version
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1version
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_destroy
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1destroy
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_release
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1release
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_start
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1start
  (JNIEnv *, jobject, jint, jint);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_ifname
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1ifname
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_ifname
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1ifname
  (JNIEnv *, jobject, jstring);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_hwaddr
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1hwaddr
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_hwaddr
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1hwaddr
  (JNIEnv *, jobject, jstring);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_descr
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1descr
  (JNIEnv *, jobject, jstring);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_descr
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1descr
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_up
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1up
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_down
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1down
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_mtu
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1mtu
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_mtu
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1mtu
  (JNIEnv *, jobject,jint);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_ip
 * Signature: (Ljava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1ip
  (JNIEnv *, jobject, jstring, jint);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_read
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1read
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_write
 * Signature: ([BI)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1write
  (JNIEnv *, jobject, jbyteArray, jint);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_readable
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1readable
  (JNIEnv *, jobject);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_nonblocking
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1nonblocking
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_debug
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1debug
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_fd
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1fd
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif
