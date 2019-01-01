
#pragma once
#ifndef UTILH
#define UTILH

// alawys have to nclude this before winbase.h
#include "../../dokan/dokan.h"
#include <winbase.h>
#include <vector>

template <class T> std::wstring VectorString(const std::vector<T> *v) {
	std::wstring s;
	if (v) {
		s += L"[";
		for (int n = 0; n < v->size(); n++) {
			if (n > 0) {
				s += L", ";
			}
			s += (*v)[n];
		}
		s += L"]";
	}
	else {
		s += L"null";
	}
	return s;
}

INT64 NowInt();
FILETIME IntToFiletime(const INT64 t);
INT64 FiletimeToInt(const FILETIME t);

std::vector<std::wstring> PathVector(const LPCWSTR path);
std::wstring NameString(const LPCWSTR path);
std::wstring IntTimeString(const INT64 t);
std::wstring FileTimeString(const FILETIME ft);
std::wstring NowString();
std::wstring SystemTimeString(const SYSTEMTIME* t);
std::wstring ShareAccessString(const ULONG v);
std::wstring DesiredAccessString(const ULONG v);
//std::wstring FileAttributesAndFlagsString(const ULONG v);
std::wstring FileAttributesString(const DWORD v);
std::wstring SecurityInformationString(const PSECURITY_INFORMATION p);
std::wstring CreateOptionsString(const ULONG v);

const WCHAR *DokanError(const int v);
const WCHAR *CreateDispositionString(const ULONG v);
//const WCHAR *ErrorString(const DWORD v);
const WCHAR *NtCreateDispositionString(const ULONG v);

LPBYTE newpage();
void freepage(LPBYTE p);

#endif
