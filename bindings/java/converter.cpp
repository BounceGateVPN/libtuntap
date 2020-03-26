#include "converter.h"

jstring charTojstring(JNIEnv* env, const char* pat) {
    /*jstring jstrBuf = env->NewStringUTF(pat);
	
    return jstrBuf;*/
    jclass strClass = env->FindClass("Ljava/lang/String;");
    jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
    jbyteArray bytes = env->NewByteArray(strlen(pat));
    env->SetByteArrayRegion(bytes, 0, strlen(pat), (jbyte*)pat);
    jstring encoding = env->NewStringUTF("utf-8");
    return (jstring)env->NewObject(strClass, ctorID, bytes, encoding);
}
char* jstringToChar(JNIEnv* env, jstring jstr) {
    /*const char* rtn = env->GetStringUTFChars(jstr,0);
    if (rtn == NULL)
        return NULL;

    char* str = (char*)malloc(strlen(rtn)*sizeof(char));
    strcpy(str, rtn);
	env->ReleaseStringUTFChars(jstr, rtn);
    
    return str;*/
    char* rtn = NULL;
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("utf-8");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray)env->CallObjectMethod(jstr, mid, strencode);
    jsize alen = env->GetArrayLength(barr);
    jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0)
    {
        rtn = (char*)malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);
    return rtn;
}

