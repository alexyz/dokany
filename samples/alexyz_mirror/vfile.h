
#pragma once
#ifndef VFILE
#define VFILE

// alawys have to nclude this before winbase.h
#include "../../dokan/dokan.h"
#include <winbase.h>
#include <string>
#include <vector>

class vfile;
class vdir;
class vblob;

class vfile {
public:
	const UINT64 id;
	vdir *parent;
	std::wstring name;
	INT64 ctime, atime, mtime;
	vfile(vdir* p, std::wstring n);
	virtual ~vfile();
	virtual vdir* dir();
	virtual vblob* blob();
	virtual const std::wstring tos() = 0;
	void getname(LPWSTR v, size_t sz);
};

class vblob : public vfile {
public:
	std::vector<LPBYTE> pages;
	size_t length;
	vblob(vdir* p, std::wstring n);
	~vblob();
	virtual vblob * blob();
	virtual const std::wstring tos();
	size_t read(const LPBYTE buf, const size_t off, const size_t reqlen);
	void write(const LPBYTE buf, const size_t off, const size_t len);
	void truncate(const INT64 len);
};

class vdir : public vfile {
public:
	std::vector<vfile*> files;
	//std::map<std::wstring,vfile*> files; ...
	vdir(vdir* p, std::wstring n);
	~vdir();
	virtual vdir* dir();
	virtual const std::wstring tos();
	vfile* find(std::wstring name);
	std::pair<vdir*, vfile*> findpath(const LPCWSTR path);
	vfile* create(const LPCWSTR FileName, const int dir);
	/* remove file from this directory (parent and name are cleared), returns 1 on success */
	int remove(vfile* f);
	/* add file to this directory (parent and name are updated), returns 1 on success */
	int add(vfile* f, std::wstring name);
};

#endif
