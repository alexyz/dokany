
#include "../../dokan/dokan.h"
#include "../../dokan/fileinfo.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <string.h>

WCHAR *ShareAccessString(ULONG v);
WCHAR *DesiredAccessString(ULONG v);
WCHAR *FlagString(ULONG v);
const WCHAR *CreateDispositionString(ULONG v);
WCHAR *FileAttributesString(DWORD v);
WCHAR *SecurityInformationString(PSECURITY_INFORMATION p);
const WCHAR *ErrorString(DWORD v);

//#define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

//BOOL g_UseStdErr;
//BOOL g_DebugMode;
BOOL g_HasSeSecurityPrivilege;

static WCHAR RootDirectory[DOKAN_MAX_PATH] = L"C:";
static WCHAR MountPoint[DOKAN_MAX_PATH] = L"M:\\";
static WCHAR UNCName[DOKAN_MAX_PATH] = L"";

static void GetFilePath(PWCHAR filePath, ULONG numberOfElements, LPCWSTR FileName) {
	wcsncpy_s(filePath, numberOfElements, RootDirectory, wcslen(RootDirectory));
	size_t unclen = wcslen(UNCName);
	if (unclen > 0 && _wcsnicmp(FileName, UNCName, unclen) == 0) {
		if (_wcsnicmp(FileName + unclen, L".", 1) != 0) {
			wcsncat_s(filePath, numberOfElements, FileName + unclen,
				wcslen(FileName) - unclen);
		}
	}
	else {
		wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
	}
}

static BOOL AddSeSecurityNamePrivilege() {
	HANDLE token = 0;
	//wprintf(L"## Attempting to add SE_SECURITY_NAME privilege to process token ##\n");
	DWORD err;
	LUID luid;
	if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &luid)) {
		err = GetLastError();
		if (err != ERROR_SUCCESS) {
			wprintf(L"* AddSeSecurityNamePrivilege: Unable to lookup privilege value: %u\n", err);
			return FALSE;
		}
	}

	LUID_AND_ATTRIBUTES attr;
	attr.Attributes = SE_PRIVILEGE_ENABLED;
	attr.Luid = luid;

	TOKEN_PRIVILEGES priv;
	priv.PrivilegeCount = 1;
	priv.Privileges[0] = attr;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		err = GetLastError();
		if (err != ERROR_SUCCESS) {
			wprintf(L"* AddSeSecurityNamePrivilege: Unable obtain process token. error = %u\n", err);
			return FALSE;
		}
	}

	TOKEN_PRIVILEGES oldPriv;
	DWORD retSize;
	AdjustTokenPrivileges(token, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), &oldPriv,
		&retSize);
	err = GetLastError();
	if (err != ERROR_SUCCESS) {
		wprintf(L"* AddSeSecurityNamePrivilege: Unable to adjust token privileges: %u\n", err);
		CloseHandle(token);
		return FALSE;
	}

	BOOL privAlreadyPresent = FALSE;
	for (unsigned int i = 0; i < oldPriv.PrivilegeCount; i++) {
		if (oldPriv.Privileges[i].Luid.HighPart == luid.HighPart &&
			oldPriv.Privileges[i].Luid.LowPart == luid.LowPart) {
			privAlreadyPresent = TRUE;
			break;
		}
	}
	//wprintf(privAlreadyPresent ? L"  success: privilege already present\n" : L"  success: privilege added\n");
	if (token)
		CloseHandle(token);
	return TRUE;
}

/*
	CreateFile is called each time a request is made on a file system object.
	In case OPEN_ALWAYS & CREATE_ALWAYS are successfully opening an existing file, STATUS_OBJECT_NAME_COLLISION should be returned instead of STATUS_SUCCESS. 
	This will inform Dokan that the file has been opened and not created during the request.
	If the file is a directory, CreateFile is also called. 
	In this case, CreateFile should return STATUS_SUCCESS when that directory can be opened and DOKAN_FILE_INFO.IsDirectory has to be set to TRUE. 
	On the other hand, if DOKAN_FILE_INFO.IsDirectory is set to TRUE but the path targets a file, STATUS_NOT_A_DIRECTORY must be returned.
	DOKAN_FILE_INFO.Context can be used to store Data (like HANDLE) that can be retrieved in all other requests related to the Context. 
	To avoid memory leak, Context needs to be released in DOKAN_OPERATIONS.Cleanup.
*/
static NTSTATUS DOKAN_CALLBACK MirrorCreateFile (
	LPCWSTR FileName,
	PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PDOKAN_FILE_INFO DokanFileInfo) {

	
	NTSTATUS status = STATUS_SUCCESS;

	SECURITY_ATTRIBUTES securityAttrib;
	securityAttrib.nLength = sizeof(securityAttrib);
	securityAttrib.lpSecurityDescriptor = SecurityContext->AccessState.SecurityDescriptor;
	securityAttrib.bInheritHandle = FALSE;

	DWORD creationDisposition;
	DWORD fileAttributesAndFlags;
	ACCESS_MASK genericDesiredAccess;
	DokanMapKernelToUserCreateFileFlags(
		DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
		&genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorCreateFile: %s da: %x %s sa: %x %s cd: %x %s fl: %x %s\n", 
		filePath, 
		DesiredAccess, DesiredAccessString(DesiredAccess), 
		ShareAccess, ShareAccessString(ShareAccess), 
		CreateDisposition, CreateDispositionString(CreateDisposition),
		fileAttributesAndFlags, FlagString(fileAttributesAndFlags));

	// When filePath is a directory, needs to change the flag so that the file can
	// be opened.
	DWORD fileAttr = GetFileAttributes(filePath);

	if (fileAttr != INVALID_FILE_ATTRIBUTES && fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
		if (!(CreateOptions & FILE_NON_DIRECTORY_FILE)) {
			DokanFileInfo->IsDirectory = TRUE;
			// Needed by FindFirstFile to list files in it
			// TODO: use ReOpenFile in MirrorFindFiles to set share read temporary
			ShareAccess |= FILE_SHARE_READ;
		}
		else { // FILE_NON_DIRECTORY_FILE - Cannot open a dir as a file
			wprintf(L"\tCannot open a dir as a file\n");
			return STATUS_FILE_IS_A_DIRECTORY;
		}
	}

	if (DokanFileInfo->IsDirectory) {
		// It is a create directory request
		
		if (creationDisposition == CREATE_NEW || creationDisposition == OPEN_ALWAYS) {
			//We create folder
			if (!CreateDirectory(filePath, &securityAttrib)) {
				DWORD error = GetLastError();
				// Fail to create folder for OPEN_ALWAYS is not an error
				if (error != ERROR_ALREADY_EXISTS || creationDisposition == CREATE_NEW) {
					wprintf(L"\tCreateDirectory error code = %d\n", error);
					status = DokanNtStatusFromWin32(error);
				}
			}
		}

		if (status == STATUS_SUCCESS) {

			//Check first if we're trying to open a file as a directory.
			if (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY) && (CreateOptions & FILE_DIRECTORY_FILE)) {
				wprintf(L"\tnot a directory");
				return STATUS_NOT_A_DIRECTORY;
			}

			// FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
			HANDLE handle;
			handle = CreateFile(filePath, genericDesiredAccess, ShareAccess, &securityAttrib, OPEN_EXISTING, fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);

			if (handle == INVALID_HANDLE_VALUE) {
				DWORD error = GetLastError();
				wprintf(L"\tCreateFile error code = %d\n", error);
				status = DokanNtStatusFromWin32(error);
			}
			else {
				DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context

				// Open succeed but we need to inform the driver
				// that the dir open and not created by returning STATUS_OBJECT_NAME_COLLISION
				if (creationDisposition == OPEN_ALWAYS && fileAttr != INVALID_FILE_ATTRIBUTES) {
					wprintf(L"\tname collision");
					return STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}
	}
	else {
		// It is a create file request

		// Cannot overwrite a hidden or system file if flag not set
		if (fileAttr != INVALID_FILE_ATTRIBUTES &&
			((!(fileAttributesAndFlags & FILE_ATTRIBUTE_HIDDEN) &&
			(fileAttr & FILE_ATTRIBUTE_HIDDEN)) ||
				(!(fileAttributesAndFlags & FILE_ATTRIBUTE_SYSTEM) &&
				(fileAttr & FILE_ATTRIBUTE_SYSTEM))) &&
					(creationDisposition == TRUNCATE_EXISTING ||
						creationDisposition == CREATE_ALWAYS)) {
			wprintf(L"\taccess denied");
			return STATUS_ACCESS_DENIED;
		}

		// Cannot delete a read only file
		if ((fileAttr != INVALID_FILE_ATTRIBUTES &&
			(fileAttr & FILE_ATTRIBUTE_READONLY) ||
			(fileAttributesAndFlags & FILE_ATTRIBUTE_READONLY)) &&
			(fileAttributesAndFlags & FILE_FLAG_DELETE_ON_CLOSE)) {
			wprintf(L"\tcannot delete");
			return STATUS_CANNOT_DELETE;
		}

		// Truncate should always be used with write access
		if (creationDisposition == TRUNCATE_EXISTING)
			genericDesiredAccess |= GENERIC_WRITE;

		HANDLE handle;
		handle = CreateFile(
			filePath,
			genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
			ShareAccess,
			&securityAttrib, // security attribute
			creationDisposition,
			fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
			NULL);                  // template file handle

		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			wprintf(L"\tCreateFile error code = %d\n", error);
			status = DokanNtStatusFromWin32(error);
		}
		else {

			//Need to update FileAttributes with previous when Overwrite file
			if (fileAttr != INVALID_FILE_ATTRIBUTES &&
				creationDisposition == TRUNCATE_EXISTING) {
				SetFileAttributes(filePath, fileAttributesAndFlags | fileAttr);
			}

			DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context

			if (creationDisposition == OPEN_ALWAYS ||
				creationDisposition == CREATE_ALWAYS) {
				DWORD error = GetLastError();
				if (error == ERROR_ALREADY_EXISTS) {
					wprintf(L"\tSetFileAttributes Open an already existing file\n");
					// Open succeed but we need to inform the driver
					// that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
					status = STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}
	}

	return status;
}

/*
	Clean remaining Context
	CloseFile is called at the end of the life of the context. Anything remaining in DOKAN_FILE_INFO::Context must be cleared before returning.
*/
static void DOKAN_CALLBACK MirrorCloseFile (
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorCloseFile: %s\n", filePath);

	if (DokanFileInfo->Context) {
		wprintf(L"\terror : not cleanuped file\n");
		CloseHandle((HANDLE)DokanFileInfo->Context);
		DokanFileInfo->Context = 0;
	}
}

/*
	Cleanup request before CloseFile is called.
	When DOKAN_FILE_INFO.DeleteOnClose is TRUE, the file in Cleanup must be deleted. 
	See DeleteFile documentation for explanation.
*/
static void DOKAN_CALLBACK MirrorCleanup (
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorCleanup: %s (del: %d)\n", filePath, DokanFileInfo->DeleteOnClose);

	if (DokanFileInfo->Context) {
		CloseHandle((HANDLE)(DokanFileInfo->Context));
		DokanFileInfo->Context = 0;
	}
	else {
		wprintf(L"\tinvalid handle\n");
	}

	if (DokanFileInfo->DeleteOnClose) {
		// Should already be deleted by CloseHandle
		// if open with FILE_FLAG_DELETE_ON_CLOSE
		//wprintf(L"\tDeleteOnClose\n");
		if (DokanFileInfo->IsDirectory) {
			//wprintf(L"  DeleteDirectory ");
			if (!RemoveDirectory(filePath)) {
				wprintf(L"\tRemoveDirectory error code = %d\n", GetLastError());
			}
			else {
				//wprintf(L"success\n");
			}
		}
		else {
			//wprintf(L"  DeleteFile ");
			if (DeleteFile(filePath) == 0) {
				wprintf(L"\tDeleteFile error code = %d\n", GetLastError());
			}
			else {
				//wprintf(L"success\n");
			}
		}
	}
}

/*
	ReadFile callback on the file previously opened in DOKAN_OPERATIONS.ZwCreateFile. 
	It can be called by different threads at the same time, so the read/context has to be thread safe.
*/
static NTSTATUS DOKAN_CALLBACK MirrorReadFile (
	LPCWSTR FileName,
	LPVOID Buffer,
	DWORD BufferLength,
	LPDWORD ReadLength,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) {

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	ULONG offset = (ULONG)Offset;
	BOOL opened = FALSE;

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	wprintf(L"MirrorReadFile: %s buf: %d read: %d off: %lld\n", filePath, BufferLength, *ReadLength, Offset);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle, cleanuped?\n");
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			wprintf(L"\tCreateFile error : %d\n", error);
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
	}

	LARGE_INTEGER distanceToMove;
	distanceToMove.QuadPart = Offset;
	if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		wprintf(L"\tSetFilePointerEx error, offset = %d\n", offset);
		if (opened)
			CloseHandle(handle);
		return DokanNtStatusFromWin32(error);
	}

	if (!ReadFile(handle, Buffer, BufferLength, ReadLength, NULL)) {
		DWORD error = GetLastError();
		wprintf(L"\tReadFile error = %u %s, buffer length = %d, read length = %d\n", error, ErrorString(error), BufferLength, *ReadLength);
		if (opened)
			CloseHandle(handle);
		return DokanNtStatusFromWin32(error);

	}
	else {
		//wprintf(L"\tByte to read: %d, Byte read %d, offset %d\n", BufferLength, *ReadLength, offset);
	}

	if (opened)
		CloseHandle(handle);

	return STATUS_SUCCESS;
}

/*
	WriteFile callback on the file previously opened in DOKAN_OPERATIONS.ZwCreateFile.
	It can be called by different threads at the same time, sp the write/context has to be thread safe.
*/
static NTSTATUS DOKAN_CALLBACK MirrorWriteFile (
	LPCWSTR FileName,
	LPCVOID Buffer,
	DWORD NumberOfBytesToWrite,
	LPDWORD NumberOfBytesWritten,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) {

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	wprintf(L"MirrorWriteFile: %s, offset %lld, length %d\n", filePath, Offset, NumberOfBytesToWrite);

	// reopen the file
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle, cleanuped?\n");
		handle = CreateFile(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			wprintf(L"\tCreateFile error : %d\n", error);
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
	}

	UINT64 fileSize = 0;
	DWORD fileSizeLow = 0;
	DWORD fileSizeHigh = 0;
	fileSizeLow = GetFileSize(handle, &fileSizeHigh);
	if (fileSizeLow == INVALID_FILE_SIZE) {
		DWORD error = GetLastError();
		wprintf(L"\tGetFileSize error = %d\n", error);
		if (opened)
			CloseHandle(handle);
		return DokanNtStatusFromWin32(error);
	}

	fileSize = ((UINT64)fileSizeHigh << 32) | fileSizeLow;

	LARGE_INTEGER distanceToMove;
	if (DokanFileInfo->WriteToEndOfFile) {
		LARGE_INTEGER z;
		z.QuadPart = 0;
		if (!SetFilePointerEx(handle, z, NULL, FILE_END)) {
			DWORD error = GetLastError();
			wprintf(L"\tSetFilePointerEx error, offset = EOF, error = %d\n", error);
			if (opened)
				CloseHandle(handle);
			return DokanNtStatusFromWin32(error);
		}
	}
	else {
		// Paging IO cannot write after allocate file size.
		if (DokanFileInfo->PagingIo) {
			if ((UINT64)Offset >= fileSize) {
				*NumberOfBytesWritten = 0;
				if (opened)
					CloseHandle(handle);
				return STATUS_SUCCESS;
			}

			if (((UINT64)Offset + NumberOfBytesToWrite) > fileSize) {
				UINT64 bytes = fileSize - Offset;
				if (bytes >> 32) {
					NumberOfBytesToWrite = (DWORD)(bytes & 0xFFFFFFFFUL);
				}
				else {
					NumberOfBytesToWrite = (DWORD)bytes;
				}
			}
		}

		if ((UINT64)Offset > fileSize) {
			// In the mirror sample helperZeroFileData is not necessary. NTFS will
			// zero a hole.
			// But if user's file system is different from NTFS( or other Windows's
			// file systems ) then  users will have to zero the hole themselves.
		}

		distanceToMove.QuadPart = Offset;
		if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
			DWORD error = GetLastError();
			wprintf(L"\tSetFilePointerEx error, offset = %I64d, error = %d\n", Offset, error);
			if (opened)
				CloseHandle(handle);
			return DokanNtStatusFromWin32(error);
		}
	}

	if (!WriteFile(handle, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten,
		NULL)) {
		DWORD error = GetLastError();
		wprintf(L"\tWriteFile error = %u, buffer length = %d, write length = %d\n", error, NumberOfBytesToWrite, *NumberOfBytesWritten);
		if (opened)
			CloseHandle(handle);
		return DokanNtStatusFromWin32(error);

	}
	else {
		//wprintf(L"\twrite %d, offset %I64d\n", *NumberOfBytesWritten, Offset);
	}

	// close the file when it is reopened
	if (opened)
		CloseHandle(handle);

	return STATUS_SUCCESS;
}

/*
	Clears buffers for this context and causes any buffered data to be written to the file.
*/
static NTSTATUS DOKAN_CALLBACK MirrorFlushFileBuffers (
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {

	HANDLE handle = (HANDLE)DokanFileInfo->Context;

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"FlushFileBuffers : %s\n", filePath);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_SUCCESS;
	}

	if (FlushFileBuffers(handle)) {
		return STATUS_SUCCESS;
	}
	else {
		DWORD error = GetLastError();
		wprintf(L"\tflush error code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}
}

/*
	Get specific information on a file.
*/
static NTSTATUS DOKAN_CALLBACK MirrorGetFileInformation (
	LPCWSTR FileName,
	LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorGetFileInformation: %s\n", filePath);

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle, cleanuped?\n");
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			wprintf(L"\tCreateFile error : %d\n", error);
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
	}

	if (!GetFileInformationByHandle(handle, HandleFileInformation)) {
		DWORD error = GetLastError();
		wprintf(L"\tGetFileInformationByHandle error = %d\n", error);

		// FileName is a root directory
		// in this case, FindFirstFile can't get directory information
		if (wcslen(FileName) == 1) {
			wprintf(L"\troot dir\n");
			HandleFileInformation->dwFileAttributes = GetFileAttributes(filePath);
		}
		else {
			WIN32_FIND_DATAW find;
			ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
			HANDLE findHandle = FindFirstFile(filePath, &find);
			if (findHandle == INVALID_HANDLE_VALUE) {
				DWORD error = GetLastError();
				wprintf(L"\tFindFirstFile error = %d\n", error);
				if (opened)
					CloseHandle(handle);
				return DokanNtStatusFromWin32(error);
			}
			HandleFileInformation->dwFileAttributes = find.dwFileAttributes;
			HandleFileInformation->ftCreationTime = find.ftCreationTime;
			HandleFileInformation->ftLastAccessTime = find.ftLastAccessTime;
			HandleFileInformation->ftLastWriteTime = find.ftLastWriteTime;
			HandleFileInformation->nFileSizeHigh = find.nFileSizeHigh;
			HandleFileInformation->nFileSizeLow = find.nFileSizeLow;
			//wprintf(L"\tFindFiles OK, file size = %d\n", find.nFileSizeLow);
			FindClose(findHandle);
		}
	}
	else {
		//wprintf(L"\tGetFileInformationByHandle success, file size = %d\n", HandleFileInformation->nFileSizeLow);
		/*
		wprintf(L"\tattr=%x %s index=%d,%d size=%d,%d links=%d\n",
			HandleFileInformation->dwFileAttributes, FileAttributesString(HandleFileInformation->dwFileAttributes),
			HandleFileInformation->nFileIndexHigh, HandleFileInformation->nFileIndexLow,
			HandleFileInformation->nFileSizeHigh, HandleFileInformation->nFileSizeLow,
			HandleFileInformation->nNumberOfLinks);*/
	}

	//wprintf(L"FILE ATTRIBUTE  = %d\n", HandleFileInformation->dwFileAttributes);

	if (opened)
		CloseHandle(handle);

	return STATUS_SUCCESS;
}

/*
	List all files in the requested path DOKAN_OPERATIONS::FindFilesWithPattern is checked first. 
	If it is not implemented or returns STATUS_NOT_IMPLEMENTED, then FindFiles is called, if implemented.
*/
static NTSTATUS DOKAN_CALLBACK MirrorFindFiles (
	LPCWSTR FileName,
	PFillFindData FillFindData, // function pointer
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	size_t fileLen;
	HANDLE hFind;
	WIN32_FIND_DATAW findData;
	DWORD error;
	int count = 0;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	wprintf(L"MirrorFindFiles: %s\n", filePath);

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') {
		filePath[fileLen++] = L'\\';
	}
	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		wprintf(L"\tinvalid file handle. Error is %u\n", error);
		return DokanNtStatusFromWin32(error);
	}

	// Root folder does not have . and .. folder - we remove them
	BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);
	do {
		if (!rootFolder || (wcscmp(findData.cFileName, L".") != 0 &&
			wcscmp(findData.cFileName, L"..") != 0))
			FillFindData(&findData, DokanFileInfo);
		count++;
	} while (FindNextFile(hFind, &findData) != 0);

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		wprintf(L"\tFindNextFile error. Error is %u\n", error);
		return DokanNtStatusFromWin32(error);
	}

	wprintf(L"\tFindFiles return %d entries in %s\n", count, filePath);

	return STATUS_SUCCESS;
}

/*
	Check if it is possible to delete a file.
	DeleteFile will also be called with DOKAN_FILE_INFO.DeleteOnClose set to FALSE to notify the driver when the file is no longer requested to be deleted.
	The file in DeleteFile should not be deleted, but instead the file must be checked as to whether or not it can be deleted, and STATUS_SUCCESS should be returned (when it can be deleted) or appropriate error codes, such as STATUS_ACCESS_DENIED or STATUS_OBJECT_NAME_NOT_FOUND, should be returned.
	When STATUS_SUCCESS is returned, a Cleanup call is received afterwards with DOKAN_FILE_INFO.DeleteOnClose set to TRUE. Only then must the closing file be deleted.
*/
static NTSTATUS DOKAN_CALLBACK MirrorDeleteFile (
	LPCWSTR FileName, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorDeleteFile: %s (onclose: %d)\n", filePath, DokanFileInfo->DeleteOnClose);

	DWORD dwAttrib = GetFileAttributes(filePath);

	if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		return STATUS_ACCESS_DENIED;

	if (handle && handle != INVALID_HANDLE_VALUE) {
		FILE_DISPOSITION_INFO fdi;
		fdi.DeleteFile = DokanFileInfo->DeleteOnClose;
		if (!SetFileInformationByHandle(handle, FileDispositionInfo, &fdi,
			sizeof(FILE_DISPOSITION_INFO)))
			return DokanNtStatusFromWin32(GetLastError());
	}

	return STATUS_SUCCESS;
}

/*
	Check if it is possible to delete a directory.
	DeleteDirectory will also be called with DOKAN_FILE_INFO.DeleteOnClose set to FALSE to notify the driver when the file is no longer requested to be deleted.
	The Directory in DeleteDirectory should not be deleted, but instead must be checked as to whether or not it can be deleted, and STATUS_SUCCESS should be returned (when it can be deleted) or appropriate error codes, such as STATUS_ACCESS_DENIED, STATUS_OBJECT_PATH_NOT_FOUND, or STATUS_DIRECTORY_NOT_EMPTY, should be returned.
	When STATUS_SUCCESS is returned, a Cleanup call is received afterwards with DOKAN_FILE_INFO.DeleteOnClose set to TRUE. Only then must the closing file be deleted.
*/
static NTSTATUS DOKAN_CALLBACK MirrorDeleteDirectory (
	LPCWSTR FileName, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	// HANDLE	handle = (HANDLE)DokanFileInfo->Context;
	HANDLE hFind;
	WIN32_FIND_DATAW findData;
	size_t fileLen;

	ZeroMemory(filePath, sizeof(filePath));
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	wprintf(L"MirrorDeleteDirectory: %s (del: %d)\n", filePath, DokanFileInfo->DeleteOnClose);

	if (!DokanFileInfo->DeleteOnClose)
		//Dokan notify that the file is requested not to be deleted.
		return STATUS_SUCCESS;

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') {
		filePath[fileLen++] = L'\\';
	}
	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		wprintf(L"\tDeleteDirectory error code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}

	do {
		if (wcscmp(findData.cFileName, L"..") != 0 &&
			wcscmp(findData.cFileName, L".") != 0) {
			FindClose(hFind);
			wprintf(L"\tDirectory is not empty: %s\n", findData.cFileName);
			return STATUS_DIRECTORY_NOT_EMPTY;
		}
	} while (FindNextFile(hFind, &findData) != 0);

	DWORD error = GetLastError();

	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		wprintf(L"\tDeleteDirectory error code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

/* Move a file or directory to a new destination */
static NTSTATUS DOKAN_CALLBACK MirrorMoveFile (
	LPCWSTR FileName, // existing file name
	LPCWSTR NewFileName, 
	BOOL ReplaceIfExisting,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	WCHAR newFilePath[DOKAN_MAX_PATH];
	GetFilePath(newFilePath, DOKAN_MAX_PATH, NewFileName);

	wprintf(L"MirrorMoveFile: %s -> %s\n", filePath, newFilePath);

	HANDLE handle;
	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_INVALID_HANDLE;
	}

	size_t newFilePathLen = wcslen(newFilePath);

	// the PFILE_RENAME_INFO struct has space for one WCHAR for the name at
	// the end, so that accounts for the null terminator

	DWORD bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) + newFilePathLen * sizeof(newFilePath[0]));

	PFILE_RENAME_INFO renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
	if (!renameInfo) {
		return STATUS_BUFFER_OVERFLOW;
	}
	ZeroMemory(renameInfo, bufferSize);

	renameInfo->ReplaceIfExists = ReplaceIfExisting ? TRUE : FALSE; // some warning about converting BOOL to BOOLEAN
	renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
	renameInfo->FileNameLength = (DWORD)newFilePathLen * sizeof(newFilePath[0]); // they want length in bytes

	wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

	BOOL result = SetFileInformationByHandle(handle, FileRenameInfo, renameInfo, bufferSize);

	free(renameInfo);

	if (result) {
		return STATUS_SUCCESS;
	}
	else {
		DWORD error = GetLastError();
		wprintf(L"\tMoveFile error = %u\n", error);
		return DokanNtStatusFromWin32(error);
	}
}

/*
	Lock file at a specific offset and data length. This is only used if DOKAN_OPTION_FILELOCK_USER_MODE is enabled.
*/
static NTSTATUS DOKAN_CALLBACK MirrorLockFile (
	LPCWSTR FileName,
	LONGLONG ByteOffset,
	LONGLONG Length,
	PDOKAN_FILE_INFO DokanFileInfo) {

	LARGE_INTEGER offset;
	LARGE_INTEGER length;

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorLockFile: %s\n", filePath);

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_INVALID_HANDLE;
	}

	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	if (!LockFile(handle, offset.LowPart, offset.HighPart, length.LowPart, length.HighPart)) {
		DWORD error = GetLastError();
		wprintf(L"\terror code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

/* SetEndOfFile is used to truncate or extend a file (physical file size). */
static NTSTATUS DOKAN_CALLBACK MirrorSetEndOfFile (
	LPCWSTR FileName, 
	LONGLONG ByteOffset, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorSetEndOfFile: %s, %I64d\n", filePath, ByteOffset);

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_INVALID_HANDLE;
	}

	LARGE_INTEGER offset;
	offset.QuadPart = ByteOffset;
	if (!SetFilePointerEx(handle, offset, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		wprintf(L"\tSetFilePointer error: %d, offset = %I64d\n", error, ByteOffset);
		return DokanNtStatusFromWin32(error);
	}

	if (!SetEndOfFile(handle)) {
		DWORD error = GetLastError();
		wprintf(L"\tSetEndOfFile error code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

/* SetAllocationSize is used to truncate or extend a file. */
static NTSTATUS DOKAN_CALLBACK MirrorSetAllocationSize (
	LPCWSTR FileName, 
	LONGLONG AllocSize, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorSetAllocationSize: %s, %I64d\n", filePath, AllocSize);

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_INVALID_HANDLE;
	}

	LARGE_INTEGER fileSize;
	if (GetFileSizeEx(handle, &fileSize)) {
		if (AllocSize < fileSize.QuadPart) {
			fileSize.QuadPart = AllocSize;
			if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) {
				DWORD error = GetLastError();
				wprintf(L"\tSetFilePointer error = %d, offset = %I64d\n", error, AllocSize);
				return DokanNtStatusFromWin32(error);
			}
			if (!SetEndOfFile(handle)) {
				DWORD error = GetLastError();
				wprintf(L"\tSetEndOfFile error = %d\n", error);
				return DokanNtStatusFromWin32(error);
			}
		}
	}
	else {
		DWORD error = GetLastError();
		wprintf(L"\terror code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}
	return STATUS_SUCCESS;
}

/* Set file attributes on a specific file */
static NTSTATUS DOKAN_CALLBACK MirrorSetFileAttributes (
	LPCWSTR FileName, 
	DWORD FileAttributes, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorSetFileAttributes: %s a: %x %s\n", filePath, FileAttributes, FileAttributesString(FileAttributes));

	if (FileAttributes != 0) {
		if (!SetFileAttributes(filePath, FileAttributes)) {
			DWORD error = GetLastError();
			wprintf(L"\terror code = %d\n", error);
			return DokanNtStatusFromWin32(error);
		}
	}
	else {
		// case FileAttributes == 0 :
		// MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
		// because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
		wprintf(L"Set 0 to FileAttributes means MUST NOT be changed. Didn't call SetFileAttributes function. \n");
	}

	return STATUS_SUCCESS;
}

/* Set file attributes on a specific file */
static NTSTATUS DOKAN_CALLBACK MirrorSetFileTime (
	LPCWSTR FileName, 
	CONST FILETIME *CreationTime,
	CONST FILETIME *LastAccessTime, 
	CONST FILETIME *LastWriteTime,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorSetFileTime: %s\n", filePath);

	HANDLE handle = (HANDLE)DokanFileInfo->Context;

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_INVALID_HANDLE;
	}

	if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
		DWORD error = GetLastError();
		wprintf(L"\terror code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

/* Unlock file at a specific offset and data length. This is only used if DOKAN_OPTION_FILELOCK_USER_MODE is enabled. */
static NTSTATUS DOKAN_CALLBACK MirrorUnlockFile (
	LPCWSTR FileName, 
	LONGLONG ByteOffset, 
	LONGLONG Length,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"UnlockFile %s\n", filePath);

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_INVALID_HANDLE;
	}

	LARGE_INTEGER length;
	length.QuadPart = Length;

	LARGE_INTEGER offset;
	offset.QuadPart = ByteOffset;

	if (!UnlockFile(handle, offset.LowPart, offset.HighPart, length.LowPart, length.HighPart)) {
		DWORD error = GetLastError();
		wprintf(L"\tUnlockFile error code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

/*
	Get specified information about the security of a file or directory.
	Return STATUS_NOT_IMPLEMENTED to let dokan library build a sddl of the current process user with authenticate user rights for context menu. 
	Return STATUS_BUFFER_OVERFLOW if buffer size is too small.
*/
static NTSTATUS DOKAN_CALLBACK MirrorGetFileSecurity (
	LPCWSTR FileName, 
	PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, 
	ULONG BufferLength,
	PULONG LengthNeeded, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorGetFileSecurity: %s si: %x %s\n", filePath, *SecurityInformation, SecurityInformationString(SecurityInformation));

	BOOLEAN requestingSaclInfo = ((*SecurityInformation & SACL_SECURITY_INFORMATION) || (*SecurityInformation & BACKUP_SECURITY_INFORMATION));

	if (!g_HasSeSecurityPrivilege) {
		*SecurityInformation &= ~SACL_SECURITY_INFORMATION;
		*SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
	}

	//wprintf(L"  Opening new handle with READ_CONTROL access\n");
	HANDLE handle = CreateFile(
		filePath,
		READ_CONTROL | ((requestingSaclInfo && g_HasSeSecurityPrivilege) ? ACCESS_SYSTEM_SECURITY : 0),
		FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL, // security attribute
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
		NULL);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		wprintf(L"\tCreateFile invalid handle: %d\n", error);
		return DokanNtStatusFromWin32(error);
	}

	if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor, BufferLength, LengthNeeded)) {
		DWORD error = GetLastError();
		if (error == ERROR_INSUFFICIENT_BUFFER) {
			wprintf(L"\tGetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n");
			CloseHandle(handle);
			return STATUS_BUFFER_OVERFLOW;
		}
		else {
			wprintf(L"\tGetUserObjectSecurity error: %d\n", error);
			CloseHandle(handle);
			return DokanNtStatusFromWin32(error);
		}
	}

	// Ensure the Security Descriptor Length is set
	DWORD securityDescriptorLength = GetSecurityDescriptorLength(SecurityDescriptor);
	//wprintf(L"  GetUserObjectSecurity return true,  *LengthNeeded = securityDescriptorLength \n");
	*LengthNeeded = securityDescriptorLength;

	CloseHandle(handle);

	return STATUS_SUCCESS;
}

/* Sets the security of a file or directory object. */
static NTSTATUS DOKAN_CALLBACK MirrorSetFileSecurity (
	LPCWSTR FileName, 
	PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, 
	ULONG SecurityDescriptorLength,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
	wprintf(L"MirrorSetFileSecurity: %s si: %s\n", filePath, SecurityInformationString(SecurityInformation));

	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		wprintf(L"\tinvalid handle\n");
		return STATUS_INVALID_HANDLE;
	}

	if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
		int error = GetLastError();
		wprintf(L"\terror: %d\n", error);
		return DokanNtStatusFromWin32(error);
	}
	return STATUS_SUCCESS;
}

/*	
	Retrieves information about the file system and volume associated with the specified root directory.
	Neither GetVolumeInformation nor GetDiskFreeSpace save the DOKAN_FILE_INFO::Context. 
	Before these methods are called, ZwCreateFile may not be called. (ditto CloseFile and Cleanup)
	FileSystemName could be anything up to 10 characters. But Windows check few feature availability based on file system name. For this, it is recommended to set NTFS or FAT here.
	FILE_READ_ONLY_VOLUME is automatically added to the FileSystemFlags if DOKAN_OPTION_WRITE_PROTECT was specified in DOKAN_OPTIONS when the volume was mounted.
*/
static NTSTATUS DOKAN_CALLBACK MirrorGetVolumeInformation (
	LPWSTR VolumeNameBuffer, 
	DWORD VolumeNameSize, 
	LPDWORD VolumeSerialNumber,
	LPDWORD MaximumComponentLength, 
	LPDWORD FileSystemFlags,
	LPWSTR FileSystemNameBuffer, 
	DWORD FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR volumeRoot[4];
	DWORD fsFlags = 0;

	wcscpy_s(VolumeNameBuffer, VolumeNameSize, L"DOKAN");

	if (VolumeSerialNumber)
		*VolumeSerialNumber = 0x19831116;
	if (MaximumComponentLength)
		*MaximumComponentLength = 255;
	if (FileSystemFlags)
		*FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
		FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
		FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;

	volumeRoot[0] = RootDirectory[0];
	volumeRoot[1] = ':';
	volumeRoot[2] = '\\';
	volumeRoot[3] = '\0';

	if (GetVolumeInformation(volumeRoot, NULL, 0, NULL, MaximumComponentLength, &fsFlags, FileSystemNameBuffer, FileSystemNameSize)) {

		if (FileSystemFlags)
			*FileSystemFlags &= fsFlags;

		if (MaximumComponentLength) {
			//wprintf(L"GetVolumeInformation: max component length %u\n", *MaximumComponentLength);
		}
		if (FileSystemNameBuffer) {
			//wprintf(L"GetVolumeInformation: file system name %s\n", FileSystemNameBuffer);
		}
		if (FileSystemFlags) {
			//wprintf(L"GetVolumeInformation: got file system flags %x, returning %x\n", fsFlags, *FileSystemFlags);
		}
	}
	else {
		wprintf(L"GetVolumeInformation: unable to query underlying fs, using defaults.  Last error = %u\n", GetLastError());

		// File system name could be anything up to 10 characters.
		// But Windows check few feature availability based on file system name.
		// For this, it is recommended to set NTFS or FAT here.
		wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"NTFS");
	}

	return STATUS_SUCCESS;
}

/*
	Retrieves information about the amount of space that is available on a disk volume.
	It consits of the total amount of space, the total amount of free space, and the total amount of free space available to the user that is associated with the calling thread.
	Neither GetDiskFreeSpace nor GetVolumeInformation save the DOKAN_FILE_INFO.Context.
	Before these methods are called, ZwCreateFile may not be called. (ditto CloseFile and Cleanup)
*/
static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace (
	PULONGLONG FreeBytesAvailable, 
	PULONGLONG TotalNumberOfBytes,
	PULONGLONG TotalNumberOfFreeBytes, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	*FreeBytesAvailable = (ULONGLONG)(512 * 1024 * 1024);
	*TotalNumberOfBytes = (ULONGLONG)(2 * 512 * 1024 * 1024);
	*TotalNumberOfFreeBytes = (ULONGLONG)(2 * 512 * 1024 * 1024);

	return STATUS_SUCCESS;
}

/**
 * Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
 * definition.
 * This only for MirrorFindStreams. Link with ntdll.lib still required.
 *
 * Not needed if you're not using NtQueryInformationFile!
 *
 * BEGIN
 */
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(
	_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
 * END
 */

/* Retrieve all NTFS Streams informations on the file. This is only called if DOKAN_OPTION_ALT_STREAM is enabled. */
NTSTATUS DOKAN_CALLBACK MirrorFindStreams (
	LPCWSTR FileName, 
	PFillFindStreamData FillFindStreamData,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	wprintf(L"MirrorFindStreams: %s\n", filePath);

	WIN32_FIND_STREAM_DATA findData;
	HANDLE hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

	DWORD error;
	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		wprintf(L"\tinvalid file handle. Error is %u\n", error);
		return DokanNtStatusFromWin32(error);
	}

	int count = 0;
	FillFindStreamData(&findData, DokanFileInfo);
	count++;

	while (FindNextStreamW(hFind, &findData) != 0) {
		FillFindStreamData(&findData, DokanFileInfo);
		count++;
	}

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_HANDLE_EOF) {
		wprintf(L"\tFindNextStreamW error %u\n", error);
		return DokanNtStatusFromWin32(error);
	}

	//wprintf(L"\tFindStreams return %d entries in %s\n", count, filePath);

	return STATUS_SUCCESS;
}

/* Called when Dokan successfully mounts the volume. */
static NTSTATUS DOKAN_CALLBACK MirrorMounted (PDOKAN_FILE_INFO DokanFileInfo) {
	UNREFERENCED_PARAMETER(DokanFileInfo);
	wprintf(L"MirrorMounted\n");
	return STATUS_SUCCESS;
}

/* Called when Dokan is unmounting the volume. */
static NTSTATUS DOKAN_CALLBACK MirrorUnmounted (PDOKAN_FILE_INFO DokanFileInfo) {
	UNREFERENCED_PARAMETER(DokanFileInfo);
	wprintf(L"MirrorUnmounted\n");
	return STATUS_SUCCESS;
}

BOOL WINAPI CtrlHandler (DWORD dwCtrlType) {
	switch (dwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		SetConsoleCtrlHandler(CtrlHandler, FALSE);
		DokanRemoveMountPoint(MountPoint);
		return TRUE;
	default:
		return FALSE;
	}
}

void ShowUsage() {
	// clang-format off
	fprintf(stderr, "mirror.exe\n"
		"  /r RootDirectory (ex. /r c:\\test)\t\t Directory source to mirror.\n"
		"  /l MountPoint (ex. /l m)\t\t\t Mount point. Can be M:\\ (drive letter) or empty NTFS folder C:\\mount\\dokan .\n"
		"  /t ThreadCount (ex. /t 5)\t\t\t Number of threads to be used internally by Dokan library.\n\t\t\t\t\t\t More threads will handle more event at the same time.\n"
		"  /d (enable debug output)\t\t\t Enable debug output to an attached debugger.\n"
		"  /s (use stderr for output)\t\t\t Enable debug output to stderr.\n"
		"  /n (use network drive)\t\t\t Show device as network device.\n"
		"  /m (use removable drive)\t\t\t Show device as removable media.\n"
		"  /w (write-protect drive)\t\t\t Read only filesystem.\n"
		"  /o (use mount manager)\t\t\t Register device to Windows mount manager.\n\t\t\t\t\t\t This enables advanced Windows features like recycle bin and more...\n"
		"  /c (mount for current session only)\t\t Device only visible for current user session.\n"
		"  /u (UNC provider name ex. \\localhost\\myfs)\t UNC name used for network volume.\n"
		"  /p (Impersonate Caller User)\t\t\t Impersonate Caller User when getting the handle in CreateFile for operations.\n\t\t\t\t\t\t This option requires administrator right to work properly.\n"
		"  /a Allocation unit size (ex. /a 512)\t\t Allocation Unit Size of the volume. This will behave on the disk file size.\n"
		"  /k Sector size (ex. /k 512)\t\t\t Sector Size of the volume. This will behave on the disk file size.\n"
		"  /f User mode Lock\t\t\t\t Enable Lockfile/Unlockfile operations. Otherwise Dokan will take care of it.\n"
		"  /i (Timeout in Milliseconds ex. /i 30000)\t Timeout until a running operation is aborted and the device is unmounted.\n"
		"Examples:\n"
		"\tmirror.exe /r C:\\Users /l M:\t\t\t# Mirror C:\\Users as RootDirectory into a drive of letter M:\\.\n"
		"\tmirror.exe /r C:\\Users /l C:\\mount\\dokan\t# Mirror C:\\Users as RootDirectory into NTFS folder C:\\mount\\dokan.\n"
		"\tmirror.exe /r C:\\Users /l M: /n /u \\myfs\\myfs1\t# Mirror C:\\Users as RootDirectory into a network drive M:\\. with UNC \\\\myfs\\myfs1\n"
		"Unmount the drive with CTRL + C in the console or alternatively via \"dokanctl /u MountPoint\".\n");
	// clang-format on
}

int __cdecl wmain (ULONG argc, PWCHAR argv[]) {
	int status;
	ULONG command;

	PDOKAN_OPERATIONS dokanOperations = (PDOKAN_OPERATIONS) malloc(sizeof(DOKAN_OPERATIONS));
	PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS) malloc(sizeof(DOKAN_OPTIONS));

	if (argc < 3) {
		ShowUsage();
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	/*g_DebugMode = FALSE;
	g_UseStdErr = FALSE;*/

	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
	dokanOptions->Version = DOKAN_VERSION;
	dokanOptions->ThreadCount = 0; // use default

	for (command = 1; command < argc; command++) {
		switch (towlower(argv[command][1])) {
		case L'r':
			command++;
			wcscpy_s(RootDirectory, sizeof(RootDirectory) / sizeof(WCHAR), argv[command]);
			wprintf(L"RootDirectory: %ls\n", RootDirectory);
			break;
		case L'l':
			command++;
			wcscpy_s(MountPoint, sizeof(MountPoint) / sizeof(WCHAR), argv[command]);
			dokanOptions->MountPoint = MountPoint;
			break;
		case L't':
			command++;
			dokanOptions->ThreadCount = (USHORT)_wtoi(argv[command]);
			break;
			/*case L'd':
				g_DebugMode = TRUE;
				break;
			case L's':
				g_UseStdErr = TRUE;
				break;*/
		case L'n':
			dokanOptions->Options |= DOKAN_OPTION_NETWORK;
			break;
		case L'm':
			dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
			break;
		case L'w':
			dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
			break;
		case L'o':
			dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
			break;
		case L'c':
			dokanOptions->Options |= DOKAN_OPTION_CURRENT_SESSION;
			break;
		case L'f':
			dokanOptions->Options |= DOKAN_OPTION_FILELOCK_USER_MODE;
			break;
		case L'u':
			command++;
			wcscpy_s(UNCName, sizeof(UNCName) / sizeof(WCHAR), argv[command]);
			dokanOptions->UNCName = UNCName;
			wprintf(L"UNC Name: %ls\n", UNCName);
			break;
			/*case L'p':
			  g_ImpersonateCallerUser = TRUE;
			  break;*/
		case L'i':
			command++;
			dokanOptions->Timeout = (ULONG)_wtol(argv[command]);
			break;
		case L'a':
			command++;
			dokanOptions->AllocationUnitSize = (ULONG)_wtol(argv[command]);
			break;
		case L'k':
			command++;
			dokanOptions->SectorSize = (ULONG)_wtol(argv[command]);
			break;
		default:
			fwprintf(stderr, L"unknown command: %s\n", argv[command]);
			free(dokanOperations);
			free(dokanOptions);
			return EXIT_FAILURE;
		}
	}

	if (wcscmp(UNCName, L"") != 0 &&
		!(dokanOptions->Options & DOKAN_OPTION_NETWORK)) {
		fwprintf(stderr, L"  Warning: UNC provider name should be set on network drive only.\n");
	}

	if (dokanOptions->Options & DOKAN_OPTION_NETWORK &&
		dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) {
		fwprintf(stderr, L"Mount manager cannot be used on network drive.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if (!(dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&
		wcscmp(MountPoint, L"") == 0) {
		fwprintf(stderr, L"Mount Point required.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if ((dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&
		(dokanOptions->Options & DOKAN_OPTION_CURRENT_SESSION)) {
		fwprintf(stderr, L"Mount Manager always mount the drive for all user sessions.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
		fwprintf(stderr, L"Control Handler is not set.\n");
	}

	// Add security name privilege. Required here to handle GetFileSecurity
	// properly.
	g_HasSeSecurityPrivilege = AddSeSecurityNamePrivilege();
	if (!g_HasSeSecurityPrivilege) {
		fwprintf(stderr, L"Failed to add security privilege to process\n");
		fwprintf(stderr, L"\t=> GetFileSecurity/SetFileSecurity may not work properly\n");
		fwprintf(stderr, L"\t=> Please restart mirror sample with administrator rights to fix it\n");
	}

	/*if (g_DebugMode) {
		dokanOptions->Options |= DOKAN_OPTION_DEBUG;
	}
	if (g_UseStdErr) {
		dokanOptions->Options |= DOKAN_OPTION_STDERR;
	}*/

	dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

	ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
	dokanOperations->ZwCreateFile = MirrorCreateFile;
	dokanOperations->Cleanup = MirrorCleanup;
	dokanOperations->CloseFile = MirrorCloseFile;
	dokanOperations->ReadFile = MirrorReadFile;
	dokanOperations->WriteFile = MirrorWriteFile;
	dokanOperations->FlushFileBuffers = MirrorFlushFileBuffers;
	dokanOperations->GetFileInformation = MirrorGetFileInformation;
	dokanOperations->FindFiles = MirrorFindFiles;
	dokanOperations->FindFilesWithPattern = NULL;
	dokanOperations->SetFileAttributes = MirrorSetFileAttributes;
	dokanOperations->SetFileTime = MirrorSetFileTime;
	dokanOperations->DeleteFile = MirrorDeleteFile;
	dokanOperations->DeleteDirectory = MirrorDeleteDirectory;
	dokanOperations->MoveFile = MirrorMoveFile;
	dokanOperations->SetEndOfFile = MirrorSetEndOfFile;
	dokanOperations->SetAllocationSize = MirrorSetAllocationSize;
	dokanOperations->LockFile = MirrorLockFile;
	dokanOperations->UnlockFile = MirrorUnlockFile;
	dokanOperations->GetFileSecurity = MirrorGetFileSecurity;
	dokanOperations->SetFileSecurity = MirrorSetFileSecurity;
	dokanOperations->GetDiskFreeSpace = MirrorDokanGetDiskFreeSpace;
	dokanOperations->GetVolumeInformation = MirrorGetVolumeInformation;
	dokanOperations->Unmounted = MirrorUnmounted;
	dokanOperations->FindStreams = MirrorFindStreams;
	dokanOperations->Mounted = MirrorMounted;

	status = DokanMain(dokanOptions, dokanOperations);
	switch (status) {
	case DOKAN_SUCCESS:
		fprintf(stderr, "Success\n");
		break;
	case DOKAN_ERROR:
		fprintf(stderr, "Error\n");
		break;
	case DOKAN_DRIVE_LETTER_ERROR:
		fprintf(stderr, "Bad Drive letter\n");
		break;
	case DOKAN_DRIVER_INSTALL_ERROR:
		fprintf(stderr, "Can't install driver\n");
		break;
	case DOKAN_START_ERROR:
		fprintf(stderr, "Driver something wrong\n");
		break;
	case DOKAN_MOUNT_ERROR:
		fprintf(stderr, "Can't assign a drive letter\n");
		break;
	case DOKAN_MOUNT_POINT_ERROR:
		fprintf(stderr, "Mount point error\n");
		break;
	case DOKAN_VERSION_ERROR:
		fprintf(stderr, "Version error\n");
		break;
	default:
		fprintf(stderr, "Unknown error: %d\n", status);
		break;
	}

	free(dokanOptions);
	free(dokanOperations);
	return EXIT_SUCCESS;
}
