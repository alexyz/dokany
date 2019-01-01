#include "../../dokan/dokan.h"
#include "../../dokan/fileinfo.h"

#include <stdio.h>
#include <winbase.h>
#include <strsafe.h>

#include <string>

#include "util.h"

LPBYTE newpage() {
	return new BYTE[4096];
}

void freepage(LPBYTE p) {
	delete p;
}

std::wstring NameString(const LPCWSTR path) {
	std::vector<std::wstring> v = PathVector(path);
	return v.size() > 0 ? v[v.size() - 1] : std::wstring();
}

std::vector<std::wstring> PathVector(const LPCWSTR path) {
	//wprintf(L"parse %s\n", path);
	std::vector<std::wstring> v;
	if (path) {
		WCHAR c = 0;
		int x = 0;
		for (int n = 0; c = path[n]; n++) {
			if (c == L'\\' || c == L'/') {
				x = 0;
			}
			else {
				if (!x) {
					v.push_back(std::wstring());
					x = 1;
				}
				v.back() += c;
			}
		}
	}
	//wprintf(L"parse %s -> %s\n", path, vectortos(&v).c_str());
	//wprintf(L"\tv=%s\n", );
	return v;
}

std::wstring NowString() {
	SYSTEMTIME st;
	GetSystemTime(&st);
	return SystemTimeString(&st);
}

std::wstring IntTimeString(const INT64 t) {
	return FileTimeString(IntToFiletime(t));
}

std::wstring FileTimeString(const FILETIME ft) {
	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);
	return SystemTimeString(&st);
}

std::wstring SystemTimeString(const SYSTEMTIME* t) {
	WCHAR v[32];
	if (t) {
		StringCbPrintfW(v, sizeof(v),
			L"%02d-%02d-%02d %02d:%02d:%02d.%03d",
			t->wYear, t->wMonth, t->wDay,
			t->wHour, t->wMinute, t->wSecond, t->wMilliseconds);
	}
	else {
		StringCbPrintfW(v, sizeof(v), L"%s", L"null");
	}
	return std::wstring(v);
}

INT64 NowInt() {
	SYSTEMTIME st;
	GetSystemTime(&st);
	FILETIME ft;
	SystemTimeToFileTime(&st, &ft);
	return FiletimeToInt(ft);
}

FILETIME IntToFiletime(const INT64 t) {
	LARGE_INTEGER li;
	li.QuadPart = t;
	FILETIME ft;
	ft.dwLowDateTime = li.LowPart;
	ft.dwHighDateTime = li.HighPart;
	return ft;
}

INT64 FiletimeToInt(const FILETIME t) {
	LARGE_INTEGER li;
	li.HighPart = t.dwHighDateTime;
	li.LowPart = t.dwLowDateTime;
	return li.QuadPart;
}

#define test(v) case v: return L#v;

const WCHAR *NtCreateDispositionString(const ULONG v) {
	switch (v) {
		test(FILE_SUPERSEDE);
		test(FILE_CREATE);
		test(FILE_OPEN);
		test(FILE_OPEN_IF);
		test(FILE_OVERWRITE);
		test(FILE_OVERWRITE_IF);
		default: return L"unknown";
	}
}

const WCHAR *CreateDispositionString(const ULONG v) {
	switch (v) {
		test(CREATE_NEW);
		test(OPEN_ALWAYS);
		test(CREATE_ALWAYS);
		test(OPEN_EXISTING);
		test(TRUNCATE_EXISTING);
		default: return L"unknown";
	}
}

const WCHAR *DokanError(const int v) {
	switch (v) {
		test(DOKAN_SUCCESS);
		test(DOKAN_ERROR);
		test(DOKAN_DRIVE_LETTER_ERROR);
		test(DOKAN_DRIVER_INSTALL_ERROR);
		test(DOKAN_START_ERROR);
		test(DOKAN_MOUNT_ERROR);
		test(DOKAN_MOUNT_POINT_ERROR);
		test(DOKAN_VERSION_ERROR);
		default: return L"unknown";
	}
}

/*
const WCHAR *ErrorString(const DWORD v) {
	switch (v) {
		test(ERROR_SUCCESS);
		test(ERROR_INVALID_FUNCTION);
		test(ERROR_FILE_NOT_FOUND);
		test(ERROR_PATH_NOT_FOUND);
		test(ERROR_TOO_MANY_OPEN_FILES);
		test(ERROR_ACCESS_DENIED);
		test(ERROR_INVALID_HANDLE);
		default: return L"unknown";
	}
}
*/

#undef test

//#define test(f) if ((v & f) == f) { if (s.length() > 0) { s += L"|"; } s += L#f; }
#define test(f) if ((v & f) == f) append(&s, L#f);

static void append(std::wstring* s, const wchar_t* v) {
	if (s->length() > 0) s->append(L"|");
	s->append(v);
}

std::wstring CreateOptionsString(const ULONG v) {
	std::wstring s;
	// in order
	test(FILE_DIRECTORY_FILE);
	test(FILE_WRITE_THROUGH);
	test(FILE_SEQUENTIAL_ONLY);
	test(FILE_NO_INTERMEDIATE_BUFFERING);
	test(FILE_SYNCHRONOUS_IO_ALERT);
	test(FILE_SYNCHRONOUS_IO_NONALERT);
	test(FILE_NON_DIRECTORY_FILE);
	test(FILE_CREATE_TREE_CONNECTION);
	test(FILE_COMPLETE_IF_OPLOCKED);
	test(FILE_NO_EA_KNOWLEDGE);
	test(FILE_OPEN_REMOTE_INSTANCE);
	test(FILE_RANDOM_ACCESS);
	test(FILE_DELETE_ON_CLOSE);
	test(FILE_OPEN_BY_FILE_ID);
	test(FILE_OPEN_FOR_BACKUP_INTENT);
	test(FILE_NO_COMPRESSION);
	test(FILE_OPEN_REQUIRING_OPLOCK);
	test(FILE_DISALLOW_EXCLUSIVE);
	test(FILE_SESSION_AWARE);
	test(FILE_RESERVE_OPFILTER);
	test(FILE_OPEN_REPARSE_POINT);
	test(FILE_OPEN_NO_RECALL);
	test(FILE_OPEN_FOR_FREE_SPACE_QUERY);
	return s;
}

std::wstring SecurityInformationString(const PSECURITY_INFORMATION p) {
	std::wstring s;
	if (!p) s += L"null";
	SECURITY_INFORMATION v = p ? *p : 0;
	// in order
	test(OWNER_SECURITY_INFORMATION);
	test(GROUP_SECURITY_INFORMATION);
	test(DACL_SECURITY_INFORMATION);
	test(SACL_SECURITY_INFORMATION);
	test(LABEL_SECURITY_INFORMATION);
	test(ATTRIBUTE_SECURITY_INFORMATION);
	test(SCOPE_SECURITY_INFORMATION);
	test(PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
	test(ACCESS_FILTER_SECURITY_INFORMATION);
	test(BACKUP_SECURITY_INFORMATION);
	test(UNPROTECTED_SACL_SECURITY_INFORMATION);
	test(UNPROTECTED_DACL_SECURITY_INFORMATION);
	test(PROTECTED_SACL_SECURITY_INFORMATION);
	test(PROTECTED_DACL_SECURITY_INFORMATION);
	return s;
}

std::wstring FileAttributesString(const DWORD v) {
	std::wstring s;
	// in order
	test(FILE_ATTRIBUTE_READONLY);
	test(FILE_ATTRIBUTE_HIDDEN);
	test(FILE_ATTRIBUTE_SYSTEM);
	test(FILE_ATTRIBUTE_DIRECTORY);
	test(FILE_ATTRIBUTE_ARCHIVE);
	test(FILE_ATTRIBUTE_DEVICE);
	test(FILE_ATTRIBUTE_NORMAL);
	test(FILE_ATTRIBUTE_TEMPORARY);
	test(FILE_ATTRIBUTE_SPARSE_FILE);
	test(FILE_ATTRIBUTE_REPARSE_POINT);
	test(FILE_ATTRIBUTE_COMPRESSED);
	test(FILE_ATTRIBUTE_OFFLINE);
	test(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	test(FILE_ATTRIBUTE_ENCRYPTED);
	test(FILE_ATTRIBUTE_INTEGRITY_STREAM);
	test(FILE_ATTRIBUTE_VIRTUAL);
	test(FILE_ATTRIBUTE_NO_SCRUB_DATA);
	test(FILE_ATTRIBUTE_EA); // same as FILE_ATTRIBUTE_RECALL_ON_OPEN
	test(FILE_ATTRIBUTE_PINNED);
	test(FILE_ATTRIBUTE_UNPINNED);
	test(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS);
	return s;
}

std::wstring ShareAccessString(const ULONG v) {
	std::wstring s;
	// in order
	test(FILE_SHARE_READ);
	test(FILE_SHARE_WRITE);
	test(FILE_SHARE_DELETE);
	return s;
}

std::wstring DesiredAccessString(const ULONG v) {
	std::wstring s;
	// all types - in order
	test(DELETE);
	test(READ_CONTROL);
	test(WRITE_DAC);
	test(WRITE_OWNER);
	test(SYNCHRONIZE);
	// generic - in order
	test(GENERIC_ALL);
	test(GENERIC_EXECUTE);
	test(GENERIC_WRITE);
	test(GENERIC_READ);
	// file specific - in order
	test(FILE_READ_DATA); // FILE_LIST_DIRECTORY
	test(FILE_WRITE_DATA); // FILE_ADD_FILE
	test(FILE_APPEND_DATA); // FILE_ADD_SUBDIRECTORY, FILE_CREATE_PIPE_INSTANCE
	test(FILE_READ_EA);
	test(FILE_WRITE_EA);
	test(FILE_EXECUTE); // FILE_TRAVERSE
	test(FILE_DELETE_CHILD);
	test(FILE_READ_ATTRIBUTES);
	test(FILE_WRITE_ATTRIBUTES);
	// combinations
	//test(STANDARD_RIGHTS_READ);
	//test(STANDARD_RIGHTS_WRITE);
	//test(STANDARD_RIGHTS_EXECUTE);
	return s;
}

/*
std::wstring FileAttributesAndFlagsString(const ULONG v) {
	std::wstring s;
	test(FILE_ATTRIBUTE_ARCHIVE);
	test(FILE_ATTRIBUTE_COMPRESSED);
	test(FILE_ATTRIBUTE_DEVICE);
	test(FILE_ATTRIBUTE_DIRECTORY);
	test(FILE_ATTRIBUTE_ENCRYPTED);
	test(FILE_ATTRIBUTE_HIDDEN);
	test(FILE_ATTRIBUTE_INTEGRITY_STREAM);
	test(FILE_ATTRIBUTE_NORMAL);
	test(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	test(FILE_ATTRIBUTE_NO_SCRUB_DATA);
	test(FILE_ATTRIBUTE_OFFLINE);
	test(FILE_ATTRIBUTE_READONLY);
	test(FILE_ATTRIBUTE_REPARSE_POINT);
	test(FILE_ATTRIBUTE_SPARSE_FILE);
	test(FILE_ATTRIBUTE_SYSTEM);
	test(FILE_ATTRIBUTE_TEMPORARY);
	test(FILE_ATTRIBUTE_VIRTUAL);
	test(FILE_FLAG_WRITE_THROUGH);
	test(FILE_FLAG_OVERLAPPED);
	test(FILE_FLAG_NO_BUFFERING);
	test(FILE_FLAG_RANDOM_ACCESS);
	test(FILE_FLAG_SEQUENTIAL_SCAN);
	test(FILE_FLAG_DELETE_ON_CLOSE);
	test(FILE_FLAG_BACKUP_SEMANTICS);
	test(FILE_FLAG_POSIX_SEMANTICS);
	test(FILE_FLAG_OPEN_REPARSE_POINT);
	test(FILE_FLAG_OPEN_NO_RECALL);
	test(SECURITY_ANONYMOUS);
	test(SECURITY_IDENTIFICATION);
	test(SECURITY_IMPERSONATION);
	test(SECURITY_DELEGATION);
	test(SECURITY_CONTEXT_TRACKING);
	test(SECURITY_EFFECTIVE_ONLY);
	test(SECURITY_SQOS_PRESENT);
	return s;
}
*/

#undef test
