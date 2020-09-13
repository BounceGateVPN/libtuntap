/*
 *  TAP-Win32 -- A kernel driver to provide virtual tap device functionality
 *               on Windows.  Originally derived from the CIPE-Win32
 *               project by Damion K. Wilson, with extensive modifications by
 *               James Yonan.
 *
 *  All source code which derives from the CIPE-Win32 project is
 *  Copyright (C) Damion K. Wilson, 2003, and is released under the
 *  GPL version 2 (see below).
 *
 *  All other source code is Copyright (C) James Yonan, 2003-2004,
 *  and is released under the GPL version 2 (see below).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include "tuntap.h"
#include "private.h"

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE (10, METHOD_BUFFERED)

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

typedef unsigned long IPADDR;
#define TUN_ASYNCHRONOUS_WRITES 1

static tap_win32_overlapped_t tap_overlapped;

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

static tun_buffer_t* get_buffer_from_free_list(tap_win32_overlapped_t* const overlapped)
{
    tun_buffer_t* buffer = NULL;
    WaitForSingleObject(overlapped->free_list_semaphore, INFINITE);
    EnterCriticalSection(&overlapped->free_list_cs);
    buffer = overlapped->free_list;

    overlapped->free_list = buffer->next;
    LeaveCriticalSection(&overlapped->free_list_cs);
    buffer->next = NULL;
    return buffer;
}

static void put_buffer_on_free_list(tap_win32_overlapped_t* const overlapped, tun_buffer_t* const buffer)
{
    EnterCriticalSection(&overlapped->free_list_cs);
    buffer->next = overlapped->free_list;
    overlapped->free_list = buffer;
    LeaveCriticalSection(&overlapped->free_list_cs);
    ReleaseSemaphore(overlapped->free_list_semaphore, 1, NULL);
}

static tun_buffer_t* get_buffer_from_output_queue(tap_win32_overlapped_t* const overlapped, const int block)
{
    tun_buffer_t* buffer = NULL;
    DWORD result, timeout = block ? INFINITE : 0L;

    // Non-blocking call
    result = WaitForSingleObject(overlapped->output_queue_semaphore, timeout);

    switch (result)
    {
        // The semaphore object was signaled.
        case WAIT_OBJECT_0:
            EnterCriticalSection(&overlapped->output_queue_cs);

            buffer = overlapped->output_queue_front;
            overlapped->output_queue_front = buffer->next;

            if(overlapped->output_queue_front == NULL) {
                overlapped->output_queue_back = NULL;
            }

            LeaveCriticalSection(&overlapped->output_queue_cs);
            break;

        // Semaphore was nonsignaled, so a time-out occurred.
        case WAIT_TIMEOUT:
            // Cannot open another window.
            break;
    }

    return buffer;
}

static tun_buffer_t* get_buffer_from_output_queue_immediate (tap_win32_overlapped_t* const overlapped)
{
    return get_buffer_from_output_queue(overlapped, 0);
}

static void put_buffer_on_output_queue(tap_win32_overlapped_t* const overlapped, tun_buffer_t* const buffer)
{
    EnterCriticalSection(&overlapped->output_queue_cs);

    if(overlapped->output_queue_front == NULL && overlapped->output_queue_back == NULL) {
        overlapped->output_queue_front = overlapped->output_queue_back = buffer;
    } else {
        buffer->next = NULL;
        overlapped->output_queue_back->next = buffer;
        overlapped->output_queue_back = buffer;
    }

    LeaveCriticalSection(&overlapped->output_queue_cs);

    ReleaseSemaphore(overlapped->output_queue_semaphore, 1, NULL);
}

static int is_tap_win32_dev(const char *guid)
{
    HKEY netcard_key;
    LONG status;
    DWORD len;
    int i = 0;

    status = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        ADAPTER_KEY,
        0,
        KEY_READ,
        &netcard_key);

    if (status != ERROR_SUCCESS) {
        return FALSE;
    }

    for (;;) {
        char enum_name[256];
        char unit_string[256];
        HKEY unit_key;
        char component_id_string[] = "ComponentId";
        char component_id[256];
        char net_cfg_instance_id_string[] = "NetCfgInstanceId";
        char net_cfg_instance_id[256];
        DWORD data_type;

        len = sizeof (enum_name);
        status = RegEnumKeyEx(
            netcard_key,
            i,
            enum_name,
            &len,
            NULL,
            NULL,
            NULL,
            NULL);

        if (status == ERROR_NO_MORE_ITEMS)
            break;
        else if (status != ERROR_SUCCESS) {
            return FALSE;
        }

        snprintf (unit_string, sizeof(unit_string), "%s\\%s",
                  ADAPTER_KEY, enum_name);

        status = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            unit_string,
            0,
            KEY_READ,
            &unit_key);

        if (status != ERROR_SUCCESS) {
            return FALSE;
        } else {
            len = sizeof (component_id);
            status = RegQueryValueEx(
                unit_key,
                component_id_string,
                NULL,
                &data_type,
                (LPBYTE)component_id,
                &len);

            if (!(status != ERROR_SUCCESS || data_type != REG_SZ)) {
                len = sizeof (net_cfg_instance_id);
                status = RegQueryValueEx(
                    unit_key,
                    net_cfg_instance_id_string,
                    NULL,
                    &data_type,
                    (LPBYTE)net_cfg_instance_id,
                    &len);

                if (status == ERROR_SUCCESS && data_type == REG_SZ) {
                    if (
                        !strcmp (net_cfg_instance_id, guid)) {
                        RegCloseKey (unit_key);
                        RegCloseKey (netcard_key);
                        return TRUE;
                    }
                }
            }
            RegCloseKey (unit_key);
        }
        ++i;
    }

    RegCloseKey (netcard_key);
    return FALSE;
}

static int tap_win32_set_status(HANDLE handle, int status)
{
    unsigned long len = 0;

    return DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS,
                &status, sizeof (status),
                &status, sizeof (status), &len, NULL);
}

static void tap_win32_overlapped_init(tap_win32_overlapped_t* const overlapped, const HANDLE handle)
{
    overlapped->handle = handle;

    overlapped->read_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    overlapped->write_event = CreateEvent(NULL, FALSE, FALSE, NULL);

    overlapped->read_overlapped.Offset = 0;
    overlapped->read_overlapped.OffsetHigh = 0;
    overlapped->read_overlapped.hEvent = overlapped->read_event;

    overlapped->write_overlapped.Offset = 0;
    overlapped->write_overlapped.OffsetHigh = 0;
    overlapped->write_overlapped.hEvent = overlapped->write_event;

    InitializeCriticalSection(&overlapped->output_queue_cs);
    InitializeCriticalSection(&overlapped->free_list_cs);

    overlapped->output_queue_semaphore = CreateSemaphore(
        NULL,   // default security attributes
        0,   // initial count
        TUN_MAX_BUFFER_COUNT,   // maximum count
        NULL);  // unnamed semaphore

    if(!overlapped->output_queue_semaphore)  {
        fprintf(stderr, "error creating output queue semaphore!\n");
    }

    overlapped->free_list_semaphore = CreateSemaphore(
        NULL,   // default security attributes
        TUN_MAX_BUFFER_COUNT,   // initial count
        TUN_MAX_BUFFER_COUNT,   // maximum count
        NULL);  // unnamed semaphore

    if(!overlapped->free_list_semaphore)  {
        fprintf(stderr, "error creating free list semaphore!\n");
    }

    overlapped->free_list = overlapped->output_queue_front = overlapped->output_queue_back = NULL;

    {
        unsigned index;
        for(index = 0; index < TUN_MAX_BUFFER_COUNT; index++) {
            tun_buffer_t* element = &overlapped->buffers[index];
            element->next = overlapped->free_list;
            overlapped->free_list = element;
        }
    }
    /* To count buffers, initially no-signal. */
    overlapped->tap_semaphore = CreateSemaphore(NULL, 0, TUN_MAX_BUFFER_COUNT, NULL);
    if(!overlapped->tap_semaphore)
        fprintf(stderr, "error creating tap_semaphore.\n");
}

static int tap_win32_write(tap_win32_overlapped_t *overlapped,
                           const void *buffer, unsigned long size)
{
    unsigned long write_size;
    BOOL result;
    DWORD error;

    result = GetOverlappedResult( overlapped->handle, &overlapped->write_overlapped,
                                  &write_size, FALSE);

    if (!result && GetLastError() == ERROR_IO_INCOMPLETE)
        WaitForSingleObject(overlapped->write_event, INFINITE);

    result = WriteFile(overlapped->handle, buffer, size,
                       &write_size, &overlapped->write_overlapped);

    if (!result) {
        switch (error = GetLastError())
        {
        case ERROR_IO_PENDING:
#ifndef TUN_ASYNCHRONOUS_WRITES
            WaitForSingleObject(overlapped->write_event, INFINITE);
#endif
            break;
        default:
            return -1;
        }
    }

    return 0;
}

static DWORD WINAPI tap_win32_thread_entry(LPVOID param)
{
    tap_win32_overlapped_t *overlapped = (tap_win32_overlapped_t*)param;
    unsigned long read_size;
    BOOL result;
    DWORD dwError;
    tun_buffer_t* buffer = get_buffer_from_free_list(overlapped);


    for (;;) {
        result = ReadFile(overlapped->handle,
                          buffer->buffer,
                          sizeof(buffer->buffer),
                          &read_size,
                          &overlapped->read_overlapped);
        if (!result) {
            dwError = GetLastError();
            if (dwError == ERROR_IO_PENDING) {
                WaitForSingleObject(overlapped->read_event, INFINITE);
                result = GetOverlappedResult( overlapped->handle, &overlapped->read_overlapped,
                                              &read_size, FALSE);
                if (!result) {
#ifdef DEBUG_TAP_WIN32
                    LPVOID lpBuffer;
                    dwError = GetLastError();
                    FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                   NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   (LPTSTR) & lpBuffer, 0, NULL );
                    fprintf(stderr, "Tap-Win32: Error GetOverlappedResult %d - %s\n", dwError, lpBuffer);
                    LocalFree( lpBuffer );
#endif
                }
            } else {
#ifdef DEBUG_TAP_WIN32
                LPVOID lpBuffer;
                FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                               NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               (LPTSTR) & lpBuffer, 0, NULL );
                fprintf(stderr, "Tap-Win32: Error ReadFile %d - %s\n", dwError, lpBuffer);
                LocalFree( lpBuffer );
#endif
            }
        }

        if(read_size > 0) {
            buffer->read_size = read_size;
            put_buffer_on_output_queue(overlapped, buffer);
            ReleaseSemaphore(overlapped->tap_semaphore, 1, NULL);
            buffer = get_buffer_from_free_list(overlapped);
        }
    }

    return 0;
}

static int tap_win32_read(tap_win32_overlapped_t *overlapped,
                          uint8_t **pbuf, int max_size)
{
    int size = 0;

    tun_buffer_t* buffer = get_buffer_from_output_queue_immediate(overlapped);

    if(buffer != NULL) {
        *pbuf = buffer->buffer;
        size = (int)buffer->read_size;
        if(size > max_size) {
            size = max_size;
        }
    }

    return size;
}

static void tap_win32_free_buffer(tap_win32_overlapped_t *overlapped,
                                  uint8_t *pbuf)
{
    tun_buffer_t* buffer = (tun_buffer_t*)pbuf;
    put_buffer_on_free_list(overlapped, buffer);
}

static char *
reg_query(char *key_name) {
	HKEY adapters, adapter;
	DWORD i, ret, len;
	char *deviceid = NULL;
	DWORD sub_keys = 0;

	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(key_name), 0, KEY_READ, &adapters);
	if (ret != ERROR_SUCCESS) {
		tuntap_log(TUNTAP_LOG_ERR, (const char *)formated_error(L"%1%0", ret));
		return NULL;
	}

	ret = RegQueryInfoKey(adapters, NULL, NULL, NULL, &sub_keys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (ret != ERROR_SUCCESS) {
		tuntap_log(TUNTAP_LOG_ERR, (const char *)formated_error(L"%1%0", ret));
		return NULL;
	}

	if (sub_keys <= 0) {
		tuntap_log(TUNTAP_LOG_DEBUG, "Wrong registry key");
		return NULL;
	}

	/* Walk througt all adapters */
	for (i = 0; i < sub_keys; i++) {
		char new_key[255];
		char data[256];
		TCHAR key[255];
		DWORD keylen = 255;

		/* Get the adapter key name */
		ret = RegEnumKeyEx(adapters, i, key, &keylen, NULL, NULL, NULL, NULL);
		if (ret != ERROR_SUCCESS) {
			continue;
		}

		/* Append it to NETWORK_ADAPTERS and open it */
		snprintf(new_key, sizeof new_key, "%s\\%s", key_name, key);
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(new_key), 0, KEY_READ, &adapter);
		if (ret != ERROR_SUCCESS) {
			continue;
		}

		/* Check its values */
		len = sizeof data;
		ret = RegQueryValueEx(adapter, "ComponentId", NULL, NULL, (LPBYTE)data, &len);
		if (ret != ERROR_SUCCESS) {
			/* This value doesn't exist in this adaptater tree */
			goto clean;
		}
		/* If its a tap adapter, its all good */
		if (strncmp(data, "tap", 3) == 0) {
			DWORD type;

			len = sizeof data;
			ret = RegQueryValueEx(adapter, "NetCfgInstanceId", NULL, &type, (LPBYTE)data, &len);
			if (ret != ERROR_SUCCESS) {
				tuntap_log(TUNTAP_LOG_INFO, (const char *)formated_error(L"%1", ret));
				goto clean;
			}
			deviceid = strdup(data);
			break;
		}
	clean:
		RegCloseKey(adapter);
	}
	RegCloseKey(adapters);
	return deviceid;
}

/*±Ò°ÊTap device*/
int tuntap_start(struct device* dev, int mode, int tun)
{
    //char prefered_name = NULL;
	char *deviceid;
    char device_path[256];
    int rc;
    HANDLE handle;
    BOOL bret;
    char name_buffer[0x100] = {0, };
    struct {
        unsigned long major;
        unsigned long minor;
        unsigned long debug;
    } version;
    DWORD version_len;
    DWORD idThread;
    HANDLE hThread;

	deviceid = reg_query(ADAPTER_KEY);

    snprintf (device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap",deviceid);

    handle = CreateFile (
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
        0 );

    if (handle == INVALID_HANDLE_VALUE) {
		printf("handle == INVALID_HANDLE_VALUE\n");
        return -1;
    }

    bret = DeviceIoControl(handle, TAP_IOCTL_GET_VERSION,
                           &version, sizeof (version),
                           &version, sizeof (version), &version_len, NULL);

    if (bret == FALSE) {
        CloseHandle(handle);
		printf("bret == FALSE\n");
        return -1;
    }

    if (!tap_win32_set_status(handle, TRUE)) {
		printf("!tap_win32_set_status(handle, TRUE)\n");
        return -1;
    }

    tap_win32_overlapped_init(&tap_overlapped, handle);

	dev->tun_fd = handle;
    dev->tap_overlapped = &tap_overlapped;
    //*phandle = &tap_overlapped;

    hThread = CreateThread(NULL, 0, tap_win32_thread_entry,(LPVOID)&tap_overlapped, 0, &idThread);
    return 0;
}

/*------------------------------------------------------------------------------------------------*/

//return 0 means no problem
int
tuntap_write(struct device *dev, void *buf, size_t size) {
	return tap_win32_write(dev->tap_overlapped, buf, size);
}

//return recv size
int
tuntap_read(struct device *dev, void *buf, size_t size) {
	return tap_win32_read(dev->tap_overlapped, buf, size);
}

void
tuntap_release(struct device* dev) {
    (void)CloseHandle(dev->tun_fd);
    free(dev);
}

char*
tuntap_get_hwaddr(struct device* dev) {
    static unsigned char hwaddr[ETHER_ADDR_LEN];
    DWORD len;

    if (DeviceIoControl(dev->tun_fd, TAP_IOCTL_GET_MAC, &hwaddr, sizeof(hwaddr), &hwaddr, sizeof(hwaddr), &len, NULL) == 0) {
        int errcode = GetLastError();

        tuntap_log(TUNTAP_LOG_ERR, (const char*)formated_error(L"%1%0", errcode));
        return NULL;
    }
    else {
        char buf[128];

        (void)_snprintf_s(buf, sizeof buf, sizeof buf, "MAC address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
        tuntap_log(TUNTAP_LOG_DEBUG, buf);
    }
    return (char*)hwaddr;
}

int
tuntap_set_hwaddr(struct device* dev, const char* hwaddr) {
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_set_hwaddr()");
    return -1;
}

static int
tuntap_sys_set_updown(struct device* dev, ULONG flag) {
    DWORD len;

    if (DeviceIoControl(dev->tun_fd, TAP_IOCTL_SET_MEDIA_STATUS, &flag, sizeof(flag), &flag, sizeof(flag), &len, NULL) == 0) {
        int errcode = GetLastError();

        tuntap_log(TUNTAP_LOG_ERR, (const char*)formated_error(L"%1%0", errcode));
        return -1;
    }
    else {
        char buf[32];

        (void)_snprintf_s(buf, sizeof buf, sizeof buf, "Status: %s", flag ? "Up" : "Down");
        tuntap_log(TUNTAP_LOG_DEBUG, buf);
        return 0;
    }
}

int
tuntap_up(struct device* dev) {
    ULONG flag;

    flag = 1;
    return tuntap_sys_set_updown(dev, flag);
}

int
tuntap_down(struct device* dev) {
    ULONG flag;

    flag = 0;
    return tuntap_sys_set_updown(dev, flag);
}

int
tuntap_get_mtu(struct device* dev) {
    ULONG mtu;
    DWORD len;

    if (DeviceIoControl(dev->tun_fd, TAP_IOCTL_GET_MTU, &mtu, sizeof(mtu), &mtu, sizeof(mtu), &len, NULL) == 0) {
        int errcode = GetLastError();

        tuntap_log(TUNTAP_LOG_ERR, (const char*)formated_error(L"%1%0", errcode));
        return -1;
    }
    return 0;
}

int
tuntap_set_mtu(struct device* dev, int mtu) {
    (void)dev;
    (void)mtu;
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_set_mtu()");
    return -1;
}

int
tuntap_sys_set_ipv4(struct device* dev, t_tun_in_addr* s, uint32_t mask) {
    IPADDR psock[4];
    DWORD len;

    /* Address + Netmask */
    psock[0] = s->S_un.S_addr;
    psock[1] = mask;
    /* DHCP server address (We don't want it) */
    psock[2] = 0;
    /* DHCP lease time */
    psock[3] = 0;

    if (DeviceIoControl(dev->tun_fd, TAP_IOCTL_CONFIG_DHCP_MASQ, &psock, sizeof(psock), &psock, sizeof(psock), &len, NULL) == 0) {
        int errcode = GetLastError();

        tuntap_log(TUNTAP_LOG_ERR, (const char*)formated_error(L"%1%0", errcode));
        return -1;
    }
    return 0;
}

int
tuntap_sys_set_ipv6(struct device* dev, t_tun_in6_addr* s, uint32_t mask) {
    (void)dev;
    (void)s;
    (void)mask;
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_sys_set_ipv6()");
    return -1;
}

int
tuntap_get_readable(struct device* dev) {
    (void)dev;
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_get_readable()");
    return -1;
}

int
tuntap_set_nonblocking(struct device* dev, int set) {
    (void)dev;
    (void)set;
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_set_nonblocking()");
    return -1;
}

int
tuntap_set_debug(struct device* dev, int set) {
    (void)dev;
    (void)set;
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_set_debug()");
    return -1;
}

int
tuntap_set_descr(struct device* dev, const char* descr) {
    (void)dev;
    (void)descr;
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_set_descr()");
    return -1;
}

int
tuntap_set_ifname(struct device* dev, const char* name) {
    /* TODO: Check Windows API to know how to rename an interface */
    (void)dev;
    (void)name;
    tuntap_log(TUNTAP_LOG_NOTICE, "Your system does not support tuntap_set_ifname()");
    return -1;
}

char*
tuntap_get_descr(struct device* dev) {
    (void)dev;
    tuntap_log(TUNTAP_LOG_NOTICE,
        "Your system does not support tuntap_get_descr()");
    return NULL;
}

void
tuntap_sys_destroy(struct device* dev) {
    (void)dev;
    return;
}