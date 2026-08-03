//go:build darwin && cgo

package securestore

/*
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef coned_keychain_string(const char *value) {
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static CFDataRef coned_keychain_data(const unsigned char *value, size_t length) {
	static const unsigned char empty = 0;
	if (length == 0 && value == NULL) {
		value = &empty;
	}
	return CFDataCreate(kCFAllocatorDefault, value, (CFIndex)length);
}

static OSStatus coned_sec_item_copy_matching(const char *service, const char *account, unsigned char **out_data, size_t *out_length) {
	CFStringRef service_ref = NULL;
	CFStringRef account_ref = NULL;
	CFDictionaryRef query = NULL;
	CFTypeRef result = NULL;
	OSStatus status = errSecParam;

	*out_data = NULL;
	*out_length = 0;
	service_ref = coned_keychain_string(service);
	account_ref = coned_keychain_string(account);
	if (service_ref == NULL || account_ref == NULL) {
		goto cleanup;
	}

	const void *keys[] = {
		kSecClass,
		kSecAttrService,
		kSecAttrAccount,
		kSecReturnData,
		kSecMatchLimit,
	};
	const void *values[] = {
		kSecClassGenericPassword,
		service_ref,
		account_ref,
		kCFBooleanTrue,
		kSecMatchLimitOne,
	};
	query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, sizeof(keys) / sizeof(keys[0]), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		goto cleanup;
	}

	status = SecItemCopyMatching(query, &result);
	if (status == errSecSuccess) {
		if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
			status = errSecParam;
			goto cleanup;
		}

		CFDataRef data = (CFDataRef)result;
		CFIndex length = CFDataGetLength(data);
		const UInt8 *bytes = CFDataGetBytePtr(data);
		if (length < 0 || (length > 0 && bytes == NULL)) {
			status = errSecParam;
			goto cleanup;
		}
		if (length > 0) {
			*out_data = (unsigned char *)malloc((size_t)length);
			if (*out_data == NULL) {
				status = errSecParam;
				goto cleanup;
			}
			memcpy(*out_data, bytes, (size_t)length);
		}
		*out_length = (size_t)length;
	}

cleanup:
	if (result != NULL) {
		CFRelease(result);
	}
	if (query != NULL) {
		CFRelease(query);
	}
	if (account_ref != NULL) {
		CFRelease(account_ref);
	}
	if (service_ref != NULL) {
		CFRelease(service_ref);
	}
	return status;
}

static OSStatus coned_sec_item_update(const char *service, const char *account, const unsigned char *value, size_t value_length) {
	CFStringRef service_ref = NULL;
	CFStringRef account_ref = NULL;
	CFDataRef value_ref = NULL;
	CFDictionaryRef query = NULL;
	CFDictionaryRef attributes = NULL;
	OSStatus status = errSecParam;

	service_ref = coned_keychain_string(service);
	account_ref = coned_keychain_string(account);
	value_ref = coned_keychain_data(value, value_length);
	if (service_ref == NULL || account_ref == NULL || value_ref == NULL) {
		goto cleanup;
	}

	const void *query_keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
	const void *query_values[] = {kSecClassGenericPassword, service_ref, account_ref};
	query = CFDictionaryCreate(kCFAllocatorDefault, query_keys, query_values, sizeof(query_keys) / sizeof(query_keys[0]), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		goto cleanup;
	}

	const void *attribute_keys[] = {kSecValueData};
	const void *attribute_values[] = {value_ref};
	attributes = CFDictionaryCreate(kCFAllocatorDefault, attribute_keys, attribute_values, sizeof(attribute_keys) / sizeof(attribute_keys[0]), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (attributes == NULL) {
		goto cleanup;
	}

	status = SecItemUpdate(query, attributes);

cleanup:
	if (attributes != NULL) {
		CFRelease(attributes);
	}
	if (query != NULL) {
		CFRelease(query);
	}
	if (value_ref != NULL) {
		CFRelease(value_ref);
	}
	if (account_ref != NULL) {
		CFRelease(account_ref);
	}
	if (service_ref != NULL) {
		CFRelease(service_ref);
	}
	return status;
}

static OSStatus coned_sec_item_add(const char *service, const char *account, const unsigned char *value, size_t value_length) {
	CFStringRef service_ref = NULL;
	CFStringRef account_ref = NULL;
	CFDataRef value_ref = NULL;
	CFDictionaryRef attributes = NULL;
	OSStatus status = errSecParam;

	service_ref = coned_keychain_string(service);
	account_ref = coned_keychain_string(account);
	value_ref = coned_keychain_data(value, value_length);
	if (service_ref == NULL || account_ref == NULL || value_ref == NULL) {
		goto cleanup;
	}

	const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData};
	const void *values[] = {kSecClassGenericPassword, service_ref, account_ref, value_ref};
	attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, sizeof(keys) / sizeof(keys[0]), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (attributes == NULL) {
		goto cleanup;
	}

	status = SecItemAdd(attributes, NULL);

cleanup:
	if (attributes != NULL) {
		CFRelease(attributes);
	}
	if (value_ref != NULL) {
		CFRelease(value_ref);
	}
	if (account_ref != NULL) {
		CFRelease(account_ref);
	}
	if (service_ref != NULL) {
		CFRelease(service_ref);
	}
	return status;
}

static OSStatus coned_sec_item_delete(const char *service, const char *account) {
	CFStringRef service_ref = NULL;
	CFStringRef account_ref = NULL;
	CFDictionaryRef query = NULL;
	OSStatus status = errSecParam;

	service_ref = coned_keychain_string(service);
	account_ref = coned_keychain_string(account);
	if (service_ref == NULL || account_ref == NULL) {
		goto cleanup;
	}

	const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
	const void *values[] = {kSecClassGenericPassword, service_ref, account_ref};
	query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, sizeof(keys) / sizeof(keys[0]), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		goto cleanup;
	}

	status = SecItemDelete(query);

cleanup:
	if (query != NULL) {
		CFRelease(query);
	}
	if (account_ref != NULL) {
		CFRelease(account_ref);
	}
	if (service_ref != NULL) {
		CFRelease(service_ref);
	}
	return status;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	darwinSecItemSuccess   int32 = 0
	darwinSecItemNotFound  int32 = -25300
	darwinSecItemDuplicate int32 = -25299
)

var errDarwinKeyringOperation = errors.New("secure keychain operation failed")

type darwinSecItemResult struct {
	data    []byte
	release func()
}

type darwinSecItemOps interface {
	copyMatching(service, account string) (darwinSecItemResult, int32)
	update(service, account string, value []byte) int32
	add(service, account string, value []byte) int32
	delete(service, account string) int32
}

type darwinKeyringDriver struct {
	ops darwinSecItemOps
}

func newKeyringDriver() keyringDriver {
	return darwinKeyringDriver{ops: darwinSecItemCgoOps{}}
}

func (driver darwinKeyringDriver) operations() darwinSecItemOps {
	if driver.ops != nil {
		return driver.ops
	}
	return darwinSecItemCgoOps{}
}

func (driver darwinKeyringDriver) Get(service, account string) ([]byte, error) {
	result, status := driver.operations().copyMatching(service, account)
	if result.release != nil {
		defer result.release()
	}
	if err := reduceDarwinSecItemStatus(status); err != nil {
		return nil, err
	}
	decoded, err := decodeKeyringValue(result.data)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), decoded...), nil
}

func (driver darwinKeyringDriver) Set(service, account string, value []byte) error {
	encoded := encodeKeyringValue(value)
	operations := driver.operations()
	status := operations.update(service, account, encoded)
	if status == darwinSecItemSuccess {
		return nil
	}
	if status != darwinSecItemNotFound {
		return reduceDarwinSecItemStatus(status)
	}

	status = operations.add(service, account, encoded)
	if status == darwinSecItemSuccess {
		return nil
	}
	if status != darwinSecItemDuplicate {
		return reduceDarwinSecItemStatus(status)
	}

	return reduceDarwinSecItemStatus(operations.update(service, account, encoded))
}

func (driver darwinKeyringDriver) Delete(service, account string) error {
	return reduceDarwinSecItemStatus(driver.operations().delete(service, account))
}

func reduceDarwinSecItemStatus(status int32) error {
	switch status {
	case darwinSecItemSuccess:
		return nil
	case darwinSecItemNotFound:
		return ErrNotFound
	default:
		return errDarwinKeyringOperation
	}
}

type darwinSecItemCgoOps struct{}

func (darwinSecItemCgoOps) copyMatching(service, account string) (darwinSecItemResult, int32) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	var data *C.uchar
	var length C.size_t
	status := C.coned_sec_item_copy_matching(cService, cAccount, &data, &length)
	if data == nil {
		return darwinSecItemResult{}, int32(status)
	}
	value := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))...)
	C.free(unsafe.Pointer(data))
	return darwinSecItemResult{data: value}, int32(status)
}

func (darwinSecItemCgoOps) update(service, account string, value []byte) int32 {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	cValue, valueLength := cKeyringBytes(value)
	if cValue != nil {
		defer C.free(cValue)
	}
	return int32(C.coned_sec_item_update(cService, cAccount, (*C.uchar)(cValue), valueLength))
}

func (darwinSecItemCgoOps) add(service, account string, value []byte) int32 {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	cValue, valueLength := cKeyringBytes(value)
	if cValue != nil {
		defer C.free(cValue)
	}
	return int32(C.coned_sec_item_add(cService, cAccount, (*C.uchar)(cValue), valueLength))
}

func (darwinSecItemCgoOps) delete(service, account string) int32 {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	return int32(C.coned_sec_item_delete(cService, cAccount))
}

func cKeyringBytes(value []byte) (unsafe.Pointer, C.size_t) {
	if len(value) == 0 {
		return nil, 0
	}
	return C.CBytes(value), C.size_t(len(value))
}
