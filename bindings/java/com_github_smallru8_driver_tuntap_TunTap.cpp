#include "com_github_smallru8_driver_tuntap_TunTap.h"
#include "private.h"

static LPWSTR
formated_error(LPWSTR pMessage, DWORD m, ...) {
	LPWSTR pBuffer = NULL;

	va_list args = NULL;
	va_start(args, pMessage);

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_ALLOCATE_BUFFER,
		pMessage,
		m,
		0,
		(LPSTR)&pBuffer,
		0,
		&args);

	va_end(args);

	return pBuffer;
}

struct device *dev;
int RWflag;

struct PairQ{
    char* first;
    int second;//len
	struct PairQ* next;
};

void pushPair(struct PairQ* q,char* data,int len) {
    struct PairQ* item = (struct PairQ*)malloc(sizeof(PairQ));
    item->first = data;
    item->second = len;
    item->next = NULL;
    if (q == NULL) {
        q = item;
    }
    else {
        struct PairQ* tmpQ = q;
        while (tmpQ->next != NULL) {
            tmpQ = tmpQ->next;
        }
        tmpQ->next = item;
    }
}
struct PairQ* popPair(struct PairQ* q) {
    struct PairQ* ret = q;
    q = q->next;
    return ret;
}

int isEmpty(struct PairQ* q) {
    if (q == NULL)
        return 1;
    return 0;
}

struct PairQ* writeQ;

struct JNIObj{
    jmethodID JNI_onRead;
    JavaVM* g_jvm;
    JNIEnv* g_ThreadEnv;
    jclass g_class;
    jobject g_obj;
};

static JNIObj* jniobj;

static void onRead(char* data,int len) {
    if(jniobj->g_ThreadEnv == NULL)
        jniobj->g_jvm->AttachCurrentThread((void**)&(jniobj->g_ThreadEnv), NULL);
    jbyteArray jData = jniobj->g_ThreadEnv->NewByteArray(len);
    jniobj->g_ThreadEnv->SetByteArrayRegion(jData, 0, len, (jbyte*)data);
    jniobj->g_ThreadEnv->CallVoidMethod(jniobj->g_obj, jniobj->JNI_onRead, jData);//回傳data
    
    jniobj->g_jvm->DetachCurrentThread();
    jniobj->g_ThreadEnv = NULL;
}

JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1startReadWrite(JNIEnv* env, jobject obj) {
	//一直從tap read傳到onRead,一直從writeQ pop資料出來寫到tap
    
	RWflag = 1;
	char buffer_read[1500];
	char buffer_write[1500];
	DWORD buffer_read_len;//成功讀取回傳值
	DWORD buffer_write_len;//成功寫入回傳值
	HANDLE event_read = CreateEvent(NULL, FALSE, FALSE, NULL);
	HANDLE event_write = CreateEvent(NULL, FALSE, FALSE, NULL);
	OVERLAPPED overlapped_read = { 0 };
	OVERLAPPED overlapped_write = { 0 };
	overlapped_read.hEvent = INVALID_HANDLE_VALUE;
	overlapped_write.hEvent = INVALID_HANDLE_VALUE;
    
	while (RWflag) {
		if (!isEmpty(writeQ)&&overlapped_write.hEvent == INVALID_HANDLE_VALUE) {//write
            struct PairQ* writeItem = popPair(writeQ);
            int len = writeItem->second;
			memcpy(buffer_write, writeItem->first, len);
            free(writeItem->first);
            free(writeItem);
			memset(&overlapped_write, 0, sizeof overlapped_write);
			overlapped_write.hEvent = event_write;

			if (WriteFile(dev->tun_fd, buffer_write, len, &buffer_write_len, &overlapped_write) == 0) {
				int errcode = GetLastError();
                printf("ERROR TunTapJNI 112\n");
				//tuntap_log(TUNTAP_LOG_ERR, (const char *)formated_error(L"%1%0", errcode));
			}
		}
        
		if (overlapped_read.hEvent == INVALID_HANDLE_VALUE) {//read

			memset(&overlapped_read, 0, sizeof overlapped_read);
			overlapped_read.hEvent = event_read;
			if (ReadFile(dev->tun_fd, buffer_read, sizeof buffer_read, &buffer_read_len, &overlapped_read) == 0) {
				int errcode = GetLastError();
                printf("ERROR TunTapJNI 123\n");
				//tuntap_log(TUNTAP_LOG_ERR, (const char *)formated_error(L"%1%0", errcode));
                
			}
		}
        
		//waiting for event
		HANDLE events[] = { event_read, event_write };
		const size_t event_count = sizeof(events) / sizeof(HANDLE);

		DWORD result = WaitForMultipleObjects(event_count, events, FALSE, INFINITE);
 
		if (result < WAIT_OBJECT_0 || result >= WAIT_OBJECT_0 + event_count)
			printf("Unable to wait for multiple objects");
		result -= WAIT_OBJECT_0;

		if (events[result] == event_read){//Read done.
			if (GetOverlappedResult(dev->tun_fd, &overlapped_read, &buffer_read_len, FALSE) == 0)
				printf("Unable to get overlapped result");
			overlapped_read.hEvent = INVALID_HANDLE_VALUE;
            //printf("Read done : %d\n",buffer_read_len);
			onRead(buffer_read, buffer_read_len);//Callback
		}
        
		if (events[result] == event_write){//Write done.
			if (GetOverlappedResult(dev->tun_fd, &overlapped_write, &buffer_write_len, FALSE) == 0)
				printf("Unable to get overlapped result");
			overlapped_write.hEvent = INVALID_HANDLE_VALUE;
		}
	}
	CloseHandle(overlapped_read.hEvent);
	CloseHandle(overlapped_write.hEvent);
}

JNIEXPORT jint JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1writeWIN(JNIEnv* env, jobject obj, jbyteArray data) {
    jbyte* jData;
    int len = env->GetArrayLength(data);
    jData = env->GetByteArrayElements(data, 0);
    char* cData = (char*)malloc(sizeof(char) * len);
    printf("A\n");
    memcpy(cData, jData, len);
    env->ReleaseByteArrayElements(data, jData, 0);

    pushPair(writeQ, cData,len);
    return len;
}

JNIEXPORT void JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1init
  (JNIEnv *env, jobject obj){
	dev = tuntap_init();
    jniobj = (struct JNIObj*)malloc(sizeof(JNIObj));
    env->GetJavaVM(&(jniobj->g_jvm));
    jniobj->g_obj = env->NewGlobalRef(obj);

    static const char* const DL_CLASS_NAME = "com/github/smallru8/driver/tuntap/TunTap";
    jniobj->g_class = env->FindClass(DL_CLASS_NAME);
    jniobj->g_ThreadEnv = NULL;
    jniobj->JNI_onRead = env->GetMethodID(jniobj->g_class, "tuntap_onRead","([B)V");

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
JNIEXPORT jbyteArray JNICALL Java_com_github_smallru8_driver_tuntap_TunTap_tuntap_1get_1hwaddr
  (JNIEnv *env, jobject obj){
	jbyteArray jData = env->NewByteArray(6);
	env->SetByteArrayRegion(jData, 0, 6, (jbyte*)tuntap_get_hwaddr(dev));

	return jData;
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
	RWflag = 0;
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
	int ret = tuntap_get_mtu(dev);
	if(len>0)
		ret = len;
	char *cData = (char*)malloc(sizeof(char)*ret);

	ret = tuntap_read(dev,cData,ret);
	if(ret==-1){
		ret = 0;
	}
	jbyteArray jData = env->NewByteArray(ret);
	env->SetByteArrayRegion(jData, 0, ret, (jbyte*)cData);
	free(cData);
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
	char *cData = (char*)malloc(sizeof(char)*len);

	memcpy(cData, jData, len);
	env->ReleaseByteArrayElements(data, jData, 0);
	int ret = tuntap_write(dev,cData,len);
	free(cData);
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
