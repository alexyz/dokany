
#include "../../dokan/dokan.h"
#include "../../dokan/fileinfo.h"

#include <stdio.h>
#include <winbase.h>
#include <strsafe.h>

#include "vfile.h"
#include "util.h"

static WCHAR fsname[16] = { 0 };
static WCHAR volumename[16] = { 0 };
static DWORD volumeserial = 0x31415926;
static CRITICAL_SECTION lock;
static vdir root(0, std::wstring(L""));
//static WCHAR RootDirectory[DOKAN_MAX_PATH] = L"C:";
static WCHAR MountPoint[MAX_PATH] = L"M:\\";
//static WCHAR UNCName[DOKAN_MAX_PATH] = L"";

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

	wprintf(L"\n%s\n", NowString().c_str());
	wprintf(L"MirrorCreateFile: %s da: %x [%s] fa: %x [%s] sa: %x [%s] cd: %x [%s] co: %x [%s]\n",
		FileName,
		DesiredAccess, DesiredAccessString(DesiredAccess).c_str(),
		FileAttributes, FileAttributesString(FileAttributes).c_str(),
		ShareAccess, ShareAccessString(ShareAccess).c_str(),
		CreateDisposition, NtCreateDispositionString(CreateDisposition),
		CreateOptions, CreateOptionsString(CreateOptions).c_str());

	vdir *parent;
	vfile *file;
	{
		std::pair<vdir*, vfile*> p = root.findpath(FileName);
		parent = p.first;
		file = p.second;
	}
	wprintf(L"\tparent=%s file=%s\n", parent ? parent->tos().c_str() : 0, file ? file->tos().c_str() : 0);

	if (file && file->dir()) {
		if (CreateOptions & FILE_NON_DIRECTORY_FILE) {
			wprintf(L"\tCannot open a dir as a file\n");
			DokanFileInfo->Context = (ULONG64)file;
			return STATUS_FILE_IS_A_DIRECTORY;
		}
		else {
			DokanFileInfo->IsDirectory = TRUE;
		}
	}

	int isdir = DokanFileInfo->IsDirectory;
	
	switch (CreateDisposition) {
	case FILE_SUPERSEDE: // replace or create
		if (file) {
			wprintf(L"\tsupersede - replace\n");
			if (file->blob()) {
				file->blob()->truncate(0);
			}
			DokanFileInfo->Context = (ULONG64)file;
			return STATUS_SUCCESS;
		} 
		else if (parent) {
			wprintf(L"\tsupersede - create\n");
			DokanFileInfo->Context = (ULONG64)parent->create(FileName, isdir);
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\tsupersede - not found\n");
			return STATUS_NOT_FOUND;
		}
	case FILE_CREATE: // return error or create
		if (file) {
			wprintf(L"\tcreate - exists\n");
			DokanFileInfo->Context = (ULONG64)file;
			return STATUS_ACCESS_DENIED;
		}
		else if (parent) {
			wprintf(L"\tcreate\n");
			DokanFileInfo->Context = (ULONG64) parent->create(FileName, isdir);
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\tcreate - not found\n");
			return STATUS_NOT_FOUND;
		}
	case FILE_OPEN: // open or error
		if (file) {
			wprintf(L"\topen\n");
			DokanFileInfo->Context = (ULONG64)file;
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\topen - not found\n");
			return STATUS_NOT_FOUND;
		}
	case FILE_OPEN_IF: // open or create
		if (file) {
			wprintf(L"open if\n");
			DokanFileInfo->Context = (ULONG64)file;
			return STATUS_SUCCESS;
		}
		else if (parent) {
			wprintf(L"\topen if - create\n");
			DokanFileInfo->Context = (ULONG64)parent->create(FileName, isdir);
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\topen if - not found\n");
			return STATUS_NOT_FOUND;
		}
	case FILE_OVERWRITE: // overwrite or error
		if (file) {
			wprintf(L"overwrite\n");
			if (file->blob()) {
				file->blob()->truncate(0);
			}
			DokanFileInfo->Context = (ULONG64)file;
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\toverwrite - not found\n");
			return STATUS_NOT_FOUND;
		}
	case FILE_OVERWRITE_IF: // overwrite or create
		if (file) {
			wprintf(L"overwrite if - overwrite\n");
			if (file->blob()) {
				file->blob()->truncate(0);
			}
			DokanFileInfo->Context = (ULONG64)file;
			return STATUS_SUCCESS;
		}
		else if (parent) {
			wprintf(L"\toverwrite if - create\n");
			DokanFileInfo->Context = (ULONG64) parent->create(FileName, isdir);
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\toverwrite if - not found\n");
			return STATUS_NOT_FOUND;
		}
	default:
		wprintf(L"\tunimplemented operation\n");
		return STATUS_NOT_IMPLEMENTED;
	}

}

/*
	Clean remaining Context
	CloseFile is called at the end of the life of the context. 
	Anything remaining in DOKAN_FILE_INFO::Context must be cleared before returning.
*/
static void DOKAN_CALLBACK MirrorCloseFile (
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorCloseFile: %s -> %s\n", FileName, f ? f->tos().c_str() : 0);

	DokanFileInfo->Context = 0;
}

/*
	Cleanup request before CloseFile is called.
	When DOKAN_FILE_INFO.DeleteOnClose is TRUE, the file in Cleanup must be deleted. 
	See DeleteFile documentation for explanation.
*/
static void DOKAN_CALLBACK MirrorCleanup (
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorCleanup: %s (delete: %d) -> %s\n", 
		FileName, DokanFileInfo->DeleteOnClose, f ? f->tos().c_str() : 0);

	if (f) {
		if (DokanFileInfo->DeleteOnClose) {
			if (f->parent->remove(f)) {
				DokanFileInfo->Context = 0;
				delete f;
			}
			else {
				wprintf(L"\tcould not remove file\n");
			}
		}
	}
	else {
		wprintf(L"\tinvalid file\n");
	}

	
}

/*
	ReadFile callback on the file previously opened in DOKAN_OPERATIONS.ZwCreateFile. 
	It can be called by different threads at the same time, so the read/context has to be thread safe.
*/
static NTSTATUS DOKAN_CALLBACK MirrorReadFile (
	LPCWSTR FileName,
	LPVOID Buffer,
	DWORD BufferLength, //u32
	LPDWORD ReadLength, //u32
	LONGLONG Offset, //s64
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorReadFile: %s, %p [%d], %p, %lld -> %s\n", 
		FileName, Buffer, BufferLength, ReadLength, Offset, f ? f->tos().c_str() : 0);

	if (!f) {
		wprintf(L"\tno file\n");
		return STATUS_INTERNAL_ERROR;
	}

	vblob *b = f->blob();
	if (!b) {
		wprintf(L"\tnot a blob\n");
		return STATUS_INTERNAL_ERROR;
	}

	*ReadLength = (DWORD) b->read((LPBYTE) Buffer, Offset, BufferLength);
	wprintf(L"\tread: %d\n", *ReadLength);

	return STATUS_SUCCESS;
}

/*
	WriteFile callback on the file previously opened in DOKAN_OPERATIONS.ZwCreateFile.
	It can be called by different threads at the same time, sp the write/context has to be thread safe.
*/
static NTSTATUS DOKAN_CALLBACK MirrorWriteFile (
	LPCWSTR FileName,
	LPCVOID Buffer,
	DWORD NumberOfBytesToWrite, //u32
	LPDWORD NumberOfBytesWritten,
	LONGLONG Offset, //s64
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorWriteFile: %s, %p [%u], %p, %lld -> %s\n", 
		FileName, Buffer, NumberOfBytesToWrite, 
		NumberOfBytesWritten, Offset, f ? f->tos().c_str() : 0);

	if (!f) {
		wprintf(L"\tno file\n");
		return STATUS_INTERNAL_ERROR;
	}

	vblob *b = f->blob();
	if (!b) {
		wprintf(L"\tnot a blob\n");
		return STATUS_INTERNAL_ERROR;
	}

	b->write((LPBYTE)Buffer, Offset, NumberOfBytesToWrite);
	*NumberOfBytesWritten = NumberOfBytesToWrite;

	return STATUS_SUCCESS;
}

/*
	Clears buffers for this context and causes any buffered data to be written to the file.
*/
static NTSTATUS DOKAN_CALLBACK MirrorFlushFileBuffers (
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {

	wprintf(L"FlushFileBuffers: %s\n", FileName);

	return STATUS_SUCCESS;
}

/*
	Get specific information on a file.
*/
static NTSTATUS DOKAN_CALLBACK MirrorGetFileInformation (
	LPCWSTR FileName,
	LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorGetFileInformation: %s -> %s\n", FileName, f ? f->tos().c_str() : 0);

	if (f) {
		vdir *d = f->dir();
		vblob *b = f->blob();
		HandleFileInformation->dwFileAttributes = d ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
		HandleFileInformation->dwVolumeSerialNumber = volumeserial;
		HandleFileInformation->ftCreationTime = IntToFiletime(f->ctime);
		HandleFileInformation->ftLastAccessTime = IntToFiletime(f->atime);
		HandleFileInformation->ftLastWriteTime = IntToFiletime(f->mtime);
		HandleFileInformation->nFileIndexHigh = f->id >> 32;
		HandleFileInformation->nFileIndexLow = (DWORD)f->id;
		HandleFileInformation->nFileSizeHigh = b ? b->length >> 32 : 0;
		HandleFileInformation->nFileSizeLow = b ? (DWORD) b->length : 0;
		HandleFileInformation->nNumberOfLinks = 1;
		return STATUS_SUCCESS;
	}
	else {
		wprintf(L"\tinvalid file\n");
		return STATUS_INTERNAL_ERROR;
	}
}

/*
	List all files in the requested path DOKAN_OPERATIONS::FindFilesWithPattern is checked first. 
	If it is not implemented or returns STATUS_NOT_IMPLEMENTED, then FindFiles is called, if implemented.
*/
static NTSTATUS DOKAN_CALLBACK MirrorFindFiles (
	LPCWSTR FileName,
	PFillFindData FillFindData, // function pointer
	PDOKAN_FILE_INFO DokanFileInfo)
{
	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorFindFiles: %s -> %s\n", FileName, f ? f->tos().c_str() : 0);
	
	if (f) {
		vdir *d = f->dir();
		if (d) {
			// TODO include ., .. if not root
			for (int n = 0; n < d->files.size(); n++) {
				vfile *f2 = d->files[n];
				vdir *d2 = f2->dir();
				vblob *b2 = f2->blob();
				WIN32_FIND_DATAW fd;
				f2->getname(fd.cFileName, sizeof(fd.cFileName));
				// ehh...
				//fd.cAlternateFileName[0] = 0;
				f2->getname(fd.cAlternateFileName, sizeof(fd.cAlternateFileName));
				fd.dwFileAttributes = d2 ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
				fd.dwReserved0 = 0;
				fd.dwReserved1 = 0;
				fd.ftCreationTime = IntToFiletime(f2->ctime);
				fd.ftLastAccessTime = IntToFiletime(f2->atime);
				fd.ftLastWriteTime = IntToFiletime(f2->mtime);
				fd.nFileSizeHigh = b2 ? b2->length >> 32 : 0;
				fd.nFileSizeLow = b2 ? (DWORD)b2->length : 0;
				FillFindData(&fd, DokanFileInfo);
			}
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\tcannot list non dir\n");
			return STATUS_ACCESS_DENIED;
		}
	}
	else {
		wprintf(L"\tcannot find file\n");
		return STATUS_INTERNAL_ERROR;
	}
}

/*
	Check if it is possible to delete a file.
	DeleteFile will also be called with DOKAN_FILE_INFO.DeleteOnClose set to FALSE to notify the driver when the file is no longer requested to be deleted.
	The file in DeleteFile should not be deleted, but instead the file must be checked as to whether or not it can be deleted, and STATUS_SUCCESS should be returned (when it can be deleted) or appropriate error codes, such as STATUS_ACCESS_DENIED or STATUS_OBJECT_NAME_NOT_FOUND, should be returned.
	When STATUS_SUCCESS is returned, a Cleanup call is received afterwards with DOKAN_FILE_INFO.DeleteOnClose set to TRUE. Only then must the closing file be deleted.
*/
static NTSTATUS DOKAN_CALLBACK MirrorCanDeleteFile (
	LPCWSTR FileName, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorCanDeleteFile: %s, delete: %d -> %s\n", FileName, DokanFileInfo->DeleteOnClose, f ? f->tos().c_str() : 0);

	if (f) {
		vblob *b = f->blob();
		if (b) {
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\tcannot delete dir\n");
			return STATUS_INTERNAL_ERROR;
		}
	}
	else {
		wprintf(L"\tcannot find file\n");
		return STATUS_INTERNAL_ERROR;
	}
}

/*
	Check if it is possible to delete a directory.
	DeleteDirectory will also be called with DOKAN_FILE_INFO.DeleteOnClose set to FALSE to notify the driver when the file is no longer requested to be deleted.
	The Directory in DeleteDirectory should not be deleted, but instead must be checked as to whether or not it can be deleted, and STATUS_SUCCESS should be returned (when it can be deleted) or appropriate error codes, such as STATUS_ACCESS_DENIED, STATUS_OBJECT_PATH_NOT_FOUND, or STATUS_DIRECTORY_NOT_EMPTY, should be returned.
	When STATUS_SUCCESS is returned, a Cleanup call is received afterwards with DOKAN_FILE_INFO.DeleteOnClose set to TRUE. 
	Only then must the closing file be deleted.
*/
static NTSTATUS DOKAN_CALLBACK MirrorCanDeleteDirectory (
	LPCWSTR FileName, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorCanDeleteDirectory: %s, delete: %d -> %s\n", FileName, DokanFileInfo->DeleteOnClose, f ? f->tos().c_str() : 0);

	if (f) {
		vdir *d = f->dir();
		if (d) {
			if (d->files.size() > 0) {
				wprintf(L"\tcannot delete non empty dir\n");
				return STATUS_DIRECTORY_NOT_EMPTY;
			}
			else {
				return STATUS_SUCCESS;
			}
		}
		else {
			wprintf(L"\tcannot delete file\n");
			return STATUS_INTERNAL_ERROR;
		}
	}
	else {
		wprintf(L"\tcannot find file\n");
		return STATUS_INTERNAL_ERROR;
	}

}

/* Move a file or directory to a new destination */
static NTSTATUS DOKAN_CALLBACK MirrorMoveFile(
	LPCWSTR FileName, // existing file name
	LPCWSTR NewFileName,
	BOOL ReplaceIfExisting,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	// MirrorMoveFile: \hello1.txt, \hello9.txt, 0 -> vblob[id=1 name=hello1.txt pages=1 length=8]
	// MirrorMoveFile: \hello1.txt, \dir1\hello1.txt, 0 -> vblob[id=1 name=hello1.txt pages=1 length=8]

	vfile* srcfile = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorMoveFile: %s, %s, %d -> %s\n",
		FileName, NewFileName, ReplaceIfExisting, srcfile ? srcfile->tos().c_str() : 0);

	if (!srcfile) {
		wprintf(L"\tno source file!\n");
		return STATUS_INTERNAL_ERROR;
	}

	std::wstring destname = NameString(NewFileName);
	if (destname.empty()) {
		wprintf(L"\tinvalid destination file name!\n");
		return STATUS_INTERNAL_ERROR;
	}

	vdir* destdir;
	vfile* destfile;
	{
		std::pair<vdir*, vfile*> dest = root.findpath(NewFileName);
		destdir = dest.first;
		destfile = dest.second;
	}

	if (!destdir) {
		wprintf(L"\tdestination directory does not exist\n");
		return STATUS_ACCESS_DENIED;
	}

	if (destfile) {
		wprintf(L"\tdestination file exists\n");
		return STATUS_ACCESS_DENIED;
	}

	std::wstring srcname = srcfile->name;
	vdir* srcdir = srcfile->parent;

	if (srcdir->remove(srcfile)) {
		if (destdir->add(srcfile, destname)) {
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\tcould not add to destination directory!\n");
			if (srcdir->add(srcfile, srcname)) {
				wprintf(L"\tcould not revert to source directory!\n");
			}
			return STATUS_INTERNAL_ERROR;
		}
	}
	else {
		wprintf(L"\tcould not remove from source directory!\n");
		return STATUS_INTERNAL_ERROR;
	}
}

/*
	Lock file at a specific offset and data length. This is only used if DOKAN_OPTION_FILELOCK_USER_MODE is enabled.
*/
static NTSTATUS DOKAN_CALLBACK MirrorLockFile (
	LPCWSTR FileName,
	LONGLONG ByteOffset, //s64
	LONGLONG Length, //s64
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorLockFile: %s, %lld, %lld -> %s\n", 
		FileName, ByteOffset, Length, f ? f->tos().c_str() : 0);

	wprintf(L"\tunimplemented\n");
	return STATUS_NOT_IMPLEMENTED;
}

/* SetEndOfFile is used to truncate or extend a file (physical file size). */
static NTSTATUS DOKAN_CALLBACK MirrorSetEndOfFile (
	LPCWSTR FileName, 
	LONGLONG ByteOffset, // s64
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorSetEndOfFile: %s, %lld -> %s\n", FileName, ByteOffset, f ? f->tos().c_str() : 0);

	if (f) {
		vblob *b = f->blob();
		if (b) {
			b->truncate(ByteOffset);
			return STATUS_SUCCESS;
		}
		else {
			wprintf(L"\tset eof on dir\n");
			return STATUS_ACCESS_DENIED;
		}
	}
	else {
		wprintf(L"\tfile not found\n");
		return STATUS_INTERNAL_ERROR;
	}
}

/* SetAllocationSize is used to truncate or extend a file. */
static NTSTATUS DOKAN_CALLBACK MirrorSetAllocationSize (
	LPCWSTR FileName, 
	LONGLONG AllocSize, //s64
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorSetAllocationSize: %s, %lld -> %s\n", FileName, AllocSize, f ? f->tos().c_str() : 0);

	return MirrorSetEndOfFile(FileName, AllocSize, DokanFileInfo);
}

/* Set file attributes on a specific file */
static NTSTATUS DOKAN_CALLBACK MirrorSetFileAttributes (
	LPCWSTR FileName, 
	DWORD FileAttributes, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorSetFileAttributes: %s, %x [%s] -> %s\n", 
		FileName, 
		FileAttributes, FileAttributesString(FileAttributes).c_str(), 
		f ? f->tos().c_str() : 0);

	if (FileAttributes == 0 || FileAttributes == FILE_ATTRIBUTE_NORMAL) {
		return STATUS_SUCCESS;
	} else {
		wprintf(L"\tunimplemented\n");
		return STATUS_NOT_IMPLEMENTED;
	}

}

/* Set file attributes on a specific file */
static NTSTATUS DOKAN_CALLBACK MirrorSetFileTime (
	LPCWSTR FileName, 
	CONST FILETIME *CreationTime,
	CONST FILETIME *LastAccessTime, 
	CONST FILETIME *LastWriteTime,
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorSetFileTime: %s -> %s\n", FileName, f ? f->tos().c_str() : 0);

	if (f) {
		if (CreationTime && CreationTime->dwLowDateTime) {
			wprintf(L"\tset creation = %s\n", FileTimeString(*CreationTime).c_str());
			f->ctime = FiletimeToInt(*CreationTime);
		}
		if (LastAccessTime && LastAccessTime->dwLowDateTime) {
			wprintf(L"\tset access = %s\n", FileTimeString(*LastAccessTime).c_str());
			f->atime = FiletimeToInt(*LastAccessTime);
		}
		if (LastWriteTime && LastWriteTime->dwLowDateTime) {
			wprintf(L"\tset modified = %s\n", FileTimeString(*LastWriteTime).c_str());
			f->mtime = FiletimeToInt(*LastWriteTime);
		}
		return STATUS_SUCCESS;
	}
	else {
		wprintf(L"\tfile not found\n");
		return STATUS_ACCESS_DENIED;
	}
}

/*
	Unlock file at a specific offset and data length.
	This is only used if DOKAN_OPTION_FILELOCK_USER_MODE is enabled.
*/
static NTSTATUS DOKAN_CALLBACK MirrorUnlockFile (
	LPCWSTR FileName, 
	LONGLONG ByteOffset, //s64
	LONGLONG Length, //s64
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorLockFile: %s, %lld, %lld -> %s\n", 
		FileName, ByteOffset, Length, f ? f->tos().c_str() : 0);

	wprintf(L"\tunimplemented\n");
	return STATUS_NOT_IMPLEMENTED;
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
	ULONG BufferLength, //u32
	PULONG LengthNeeded, 
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorGetFileSecurity: %s, %p, %p, %d, %p -> %s\n",
		FileName, SecurityInformation, SecurityDescriptor, BufferLength, LengthNeeded, f ? f->tos().c_str() : 0);

	return STATUS_NOT_IMPLEMENTED;
}

/* Sets the security of a file or directory object. */
static NTSTATUS DOKAN_CALLBACK MirrorSetFileSecurity (
	LPCWSTR FileName, 
	PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, 
	ULONG SecurityDescriptorLength, //u32
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorSetFileSecurity: %s, %p, %p [%d] -> %s\n",
		FileName, SecurityInformation, SecurityDescriptor, 
		SecurityDescriptorLength, f ? f->tos().c_str() : 0);

	wprintf(L"\tunimplemented (success)\n");
	return STATUS_SUCCESS;

}

/*	
	Retrieves information about the file system and volume associated with the specified root directory.
	Neither GetVolumeInformation nor GetDiskFreeSpace save the DOKAN_FILE_INFO::Context. 
	Before these methods are called, ZwCreateFile may not be called. (ditto CloseFile and Cleanup)
	FileSystemName could be anything up to 10 characters. 
	But Windows check few feature availability based on file system name. 
	For this, it is recommended to set NTFS or FAT here.
	FILE_READ_ONLY_VOLUME is automatically added to the FileSystemFlags if DOKAN_OPTION_WRITE_PROTECT was specified in DOKAN_OPTIONS when the volume was mounted.
*/
static NTSTATUS DOKAN_CALLBACK MirrorGetVolumeInformation (
	LPWSTR VolumeNameBuffer, 
	DWORD VolumeNameSize,  //u32
	LPDWORD VolumeSerialNumber,
	LPDWORD MaximumComponentLength, 
	LPDWORD FileSystemFlags,
	LPWSTR FileSystemNameBuffer, 
	DWORD FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorGetVolumeInformation: %p [%d], %p, %p, %p, %p [%d] -> %s\n",
		VolumeNameBuffer, VolumeNameSize,
		VolumeSerialNumber, MaximumComponentLength,
		FileSystemFlags, FileSystemNameBuffer, FileSystemNameSize,
		f ? f->tos().c_str() : 0);

	if (VolumeNameBuffer) {
		StringCbCopyW(VolumeNameBuffer, VolumeNameSize, volumename);
	}
	if (VolumeSerialNumber) {
		*VolumeSerialNumber = volumeserial;
	}
	if (MaximumComponentLength) {
		*MaximumComponentLength = 255;
	}
	if (FileSystemFlags) {
		*FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;
		// FILE_SUPPORTS_REMOTE_STORAGE | FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;
	}
	if (FileSystemNameBuffer) {
		StringCbCopyW(FileSystemNameBuffer, FileSystemNameSize, fsname);
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
	PULONGLONG FreeBytesAvailable, //u64
	PULONGLONG TotalNumberOfBytes, //u64
	PULONGLONG TotalNumberOfFreeBytes, //u64
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorDokanGetDiskFreeSpace: %p, %p, %p -> %s\n",
		FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes, 
		f ? f->tos().c_str() : 0);

	UINT64 m = 2U << 20;
	if (FreeBytesAvailable) {
		*FreeBytesAvailable = 512 * m;
	}
	if (TotalNumberOfBytes) {
		*TotalNumberOfBytes = 1024 * m;
	}
	if (TotalNumberOfFreeBytes) {
		*TotalNumberOfFreeBytes = 512 * m;
	}

	return STATUS_SUCCESS;
}

/*
	Retrieve all NTFS Streams informations on the file. 
	This is only called if DOKAN_OPTION_ALT_STREAM is enabled.
*/
NTSTATUS DOKAN_CALLBACK MirrorFindStreams (
	LPCWSTR FileName, 
	PFillFindStreamData FillFindStreamData,
	PDOKAN_FILE_INFO DokanFileInfo) {

	vfile* f = (vfile*)DokanFileInfo->Context;
	wprintf(L"MirrorFindStreams: %s, %p -> %s\n",
		FileName, FillFindStreamData, f ? f->tos().c_str() : 0);

	wprintf(L"\tnot implemented\n");

	return STATUS_NOT_IMPLEMENTED;
}

/* Called when Dokan successfully mounts the volume. */
static NTSTATUS DOKAN_CALLBACK MirrorMounted (PDOKAN_FILE_INFO DokanFileInfo) {
	wprintf(L"MirrorMounted\n");
	return STATUS_SUCCESS;
}

/* Called when Dokan is unmounting the volume. */
static NTSTATUS DOKAN_CALLBACK MirrorUnmounted (PDOKAN_FILE_INFO DokanFileInfo) {
	wprintf(L"MirrorUnmounted\n");
	return STATUS_SUCCESS;
}

BOOL WINAPI CtrlHandler (DWORD dwCtrlType) {
	wprintf(L"ctrl pressed\n");
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

int __cdecl wmain (ULONG argc, PWCHAR argv[]) {
	
	InitializeCriticalSection(&lock);

	StringCbCopyW(volumename, sizeof(volumename), L"ALEXYZ");
	StringCbCopyW(fsname, sizeof(fsname), L"NTFS");

	if (argc < 3) {
		wprintf(L"insufficient arguments\n");
		return EXIT_FAILURE;
	}

	DOKAN_OPTIONS options;
	ZeroMemory(&options, sizeof(options));

	options.Version = DOKAN_VERSION;
	options.ThreadCount = 0; // use default

	ULONG command;
	for (command = 1; command < argc; command++) {
		switch (towlower(argv[command][1])) {
		/*case L'r':
			command++;
			wcscpy_s(RootDirectory, sizeof(RootDirectory) / sizeof(WCHAR), argv[command]);
			wprintf(L"RootDirectory: %ls\n", RootDirectory);
			break;*/
		case L'l':
			command++;
			wcscpy_s(MountPoint, sizeof(MountPoint) / sizeof(WCHAR), argv[command]);
			options.MountPoint = MountPoint;
			break;
		case L't':
			command++;
			options.ThreadCount = (USHORT)_wtoi(argv[command]);
			break;
			/*case L'd':
				g_DebugMode = TRUE;
				break;
			case L's':
				g_UseStdErr = TRUE;
				break;*/
		case L'n':
			options.Options |= DOKAN_OPTION_NETWORK;
			break;
		case L'm':
			options.Options |= DOKAN_OPTION_REMOVABLE;
			break;
		case L'w':
			options.Options |= DOKAN_OPTION_WRITE_PROTECT;
			break;
		case L'o':
			options.Options |= DOKAN_OPTION_MOUNT_MANAGER;
			break;
		case L'c':
			options.Options |= DOKAN_OPTION_CURRENT_SESSION;
			break;
		case L'f':
			options.Options |= DOKAN_OPTION_FILELOCK_USER_MODE;
			break;
		/*case L'u':
			command++;
			wcscpy_s(UNCName, sizeof(UNCName) / sizeof(WCHAR), argv[command]);
			dokanOptions->UNCName = UNCName;
			wprintf(L"UNC Name: %ls\n", UNCName);
			break;*/
			/*case L'p':
			  g_ImpersonateCallerUser = TRUE;
			  break;*/
		case L'i':
			command++;
			options.Timeout = (ULONG)_wtol(argv[command]);
			break;
		case L'a':
			command++;
			options.AllocationUnitSize = (ULONG)_wtol(argv[command]);
			break;
		case L'k':
			command++;
			options.SectorSize = (ULONG)_wtol(argv[command]);
			break;
		default:
			wprintf(L"unknown command: %s\n", argv[command]);
			return EXIT_FAILURE;
		}
	}

	/*if (wcscmp(UNCName, L"") != 0 &&
		!(dokanOptions->Options & DOKAN_OPTION_NETWORK)) {
		wprintf(L"  Warning: UNC provider name should be set on network drive only.\n");
	}*/

	if (options.Options & DOKAN_OPTION_NETWORK && options.Options & DOKAN_OPTION_MOUNT_MANAGER) {
		wprintf(L"Mount manager cannot be used on network drive.\n");
		return EXIT_FAILURE;
	}

	if (!(options.Options & DOKAN_OPTION_MOUNT_MANAGER) && wcscmp(MountPoint, L"") == 0) {
		wprintf(L"Mount Point required.\n");
		return EXIT_FAILURE;
	}

	if ((options.Options & DOKAN_OPTION_MOUNT_MANAGER) && (options.Options & DOKAN_OPTION_CURRENT_SESSION)) {
		wprintf(L"Mount Manager always mount the drive for all user sessions.\n");
		return EXIT_FAILURE;
	}

	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
		wprintf(L"Control Handler is not set.\n");
	}

	//options.Options |= DOKAN_OPTION_ALT_STREAM;

	DOKAN_OPERATIONS operations;
	ZeroMemory(&operations, sizeof(operations));

	operations.ZwCreateFile = MirrorCreateFile;
	operations.Cleanup = MirrorCleanup;
	operations.CloseFile = MirrorCloseFile;
	operations.ReadFile = MirrorReadFile;
	operations.WriteFile = MirrorWriteFile;
	operations.FlushFileBuffers = MirrorFlushFileBuffers;
	operations.GetFileInformation = MirrorGetFileInformation;
	operations.FindFiles = MirrorFindFiles;
	operations.FindFilesWithPattern = NULL;
	operations.SetFileAttributes = MirrorSetFileAttributes;
	operations.SetFileTime = MirrorSetFileTime;
	operations.DeleteFile = MirrorCanDeleteFile;
	operations.DeleteDirectory = MirrorCanDeleteDirectory;
	operations.MoveFile = MirrorMoveFile;
	operations.SetEndOfFile = MirrorSetEndOfFile;
	operations.SetAllocationSize = MirrorSetAllocationSize;
	operations.LockFile = MirrorLockFile;
	operations.UnlockFile = MirrorUnlockFile;
	operations.GetFileSecurity = MirrorGetFileSecurity;
	operations.SetFileSecurity = MirrorSetFileSecurity;
	operations.GetDiskFreeSpace = MirrorDokanGetDiskFreeSpace;
	operations.GetVolumeInformation = MirrorGetVolumeInformation;
	operations.Unmounted = MirrorUnmounted;
	operations.FindStreams = MirrorFindStreams;
	operations.Mounted = MirrorMounted;

	int e = DokanMain(&options, &operations);

	if (e) {
		wprintf(L"dokan error: %d [%s]\n", e, DokanError(e));
		return EXIT_FAILURE;
	}
	else {
		return EXIT_SUCCESS;
	}
}
