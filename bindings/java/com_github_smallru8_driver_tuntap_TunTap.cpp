#include "com_github_smallru8_driver_tuntap_TunTap.h"

struct device *dev;
char *cData_r = (char*)malloc(sizeof(char)*1560);
char *cData_w = (char*)malloc(sizeof(char)*1560);

JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1init
  (JNIEnv *env, jobject obj){
	dev = tuntap_init();
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_version
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1version
  (JNIEnv *env, jobject obj){
	return tuntap_version();
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_destroy
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1destroy
  (JNIEnv *env, jobject obj){
	tuntap_destroy(dev);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_release
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1release
  (JNIEnv *env, jobject obj){
	tuntap_release(dev);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_start
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1start
  (JNIEnv *env, jobject obj, jint mode, jint id){//0x0001 257
	return tuntap_start(dev,mode,id);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_ifname
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1ifname
  (JNIEnv *env, jobject obj){
	return charTojstring(env,tuntap_get_ifname(dev));
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_ifname
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1ifname
  (JNIEnv *env, jobject obj, jstring ifname){
	return tuntap_set_ifname(dev,jstringToChar(env,ifname));
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_hwaddr
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1hwaddr
  (JNIEnv *env, jobject obj){
	return charTojstring(env,tuntap_get_hwaddr(dev));
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_hwaddr
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1hwaddr
  (JNIEnv *env, jobject obj, jstring hwaddr){
	return tuntap_set_hwaddr(dev,jstringToChar(env,hwaddr));
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_descr
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1descr
  (JNIEnv *env, jobject obj, jstring descr){
	return tuntap_set_descr(dev,jstringToChar(env,descr));
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_descr
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1descr
  (JNIEnv *env, jobject obj){
	return charTojstring(env,tuntap_get_descr(dev));
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_up
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1up
  (JNIEnv *env, jobject obj){
	return tuntap_up(dev);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_down
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1down
  (JNIEnv *env, jobject obj){
	return tuntap_down(dev);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_mtu
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1mtu
  (JNIEnv *env, jobject obj){
	return tuntap_get_mtu(dev);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_mtu
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1mtu
  (JNIEnv *env, jobject obj,jint mtu){
	return tuntap_set_mtu(dev,mtu);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_ip
 * Signature: (Ljava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1ip
  (JNIEnv *env, jobject obj, jstring ipaddr, jint mask){
	return tuntap_set_ip(dev,jstringToChar(env,ipaddr),mask);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_read
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1read
  (JNIEnv *env, jobject obj, jint len){
	int ret = 1560;
	if(len>0)
		ret = len;
	//char *cData = (char*)malloc(sizeof(char)*ret);//要修正#######
# if defined Windows //windows
	ret = tuntap_read(dev,&cData_r,ret);
# else //unix
    ret = tuntap_read(dev, cData_r, ret);
#endif
	if(ret==-1||ret==0)
        return NULL;
	
	jbyteArray jData = env->NewByteArray(ret);
	env->SetByteArrayRegion(jData, 0, ret, (jbyte*)cData_r);
	//free(cData);
	return jData;
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_write
 * Signature: ([BI)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1write
  (JNIEnv *env, jobject obj, jbyteArray data, jint len){
	jbyte *jData;
	jData = env->GetByteArrayElements(data, 0);
	//char *cData = (char*)malloc(sizeof(char)*len);

	memcpy(cData_w, jData, len);
	env->ReleaseByteArrayElements(data, jData, 0);
	int ret = tuntap_write(dev,cData_w,len);
	//free(cData);

	//return 0 means no problem
	//return -1 means error
	return ret;
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_readable
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1readable
  (JNIEnv *env, jobject obj){
	return tuntap_get_readable(dev);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_nonblocking
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1nonblocking
  (JNIEnv *env, jobject obj, jint set){
	return tuntap_set_nonblocking(dev,set);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_set_debug
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1set_1debug
  (JNIEnv *env, jobject obj, jint set){
	return tuntap_set_debug(dev,set);
}

/*
 * Class:     com_github_smallru8_driver_tuntap_TunTap
 * Method:    tuntap_get_fd
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1fd
  (JNIEnv *env, jobject obj){
	return (int)tuntap_get_fd(dev);
}