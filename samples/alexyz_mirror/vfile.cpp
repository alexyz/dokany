
#include <strsafe.h>
#include "vfile.h"
#include "util.h"

// prob dont need this
std::wstring operator+ (std::wstring s, vfile* t) {
	std::wstring u(s);
	return t ? u.append(t->tos()) : u.append(L"null");
}

// -------------------------------------

static UINT64 fileid = 1;

vfile::vfile(vdir* p, std::wstring n) : parent(p), name(n), id(fileid++)
{ 
	atime = ctime = mtime = NowInt();
	wprintf(L"vfile %lld\n", id);
}

vdir::vdir(vdir* p, std::wstring n) : vfile(p,n) { 
	//
}

vblob::vblob(vdir* p, std::wstring n) : vfile(p,n), length(0) { 
	//
}

vfile::~vfile() {
	wprintf(L"~vfile %lld\n", id);
}

vblob::~vblob() {
	wprintf(L"~vblob %lld\n", id);
	// free the file content...
	truncate(0);
}

vdir::~vdir() {
	if (files.size() > 0) {
		wprintf(L"~vdir %I64d: directory not empty!\n", id);
	}
}

vdir* vfile::dir() {
	return 0;
}

vdir* vdir::dir() {
	return this;
}

vblob* vfile::blob() {
	return 0;
}

vblob* vblob::blob() {
	return this;
}

void vfile::getname(LPWSTR v, size_t sz) {
	//wprintf(L"getname %p [%zd]\n", v, sz);
	StringCbCopyW(v, sz, name.c_str());
}

const std::wstring vblob::tos() {
	WCHAR v[256];
	StringCbPrintfW(v, sizeof(v), 
		L"vblob[id=%lld name=%s pages=%zd length=%lld]", 
		id, name.c_str(), pages.size(), length);
	return std::wstring(v);
}

const std::wstring vdir::tos() {
	WCHAR v[256];
	StringCbPrintfW(v, sizeof(v), L"vdir[id=%lld name=%s files=%zd]", id, name.c_str(), files.size());
	return std::wstring(v);
}

size_t vblob::read(const LPBYTE buf, const size_t off, const size_t reqlen)
{
	wprintf(L"read %p, %zd, %zd (pages: %zd length: %zd)\n", buf, off, reqlen, pages.size(), length);
	size_t len = length >= off ? min(length - off, reqlen) : 0;
	size_t n = 0;
	if (len > 0) {
		size_t p1 = off >> 12; // first page
		size_t p2 = (off + len - 1) >> 12; // last page (inclusive)
		for (size_t p = p1; p <= p2; p++) {
			LPBYTE page = pages[p];
			size_t i1 = p == p1 ? off & 0xfff : 0; // start index
			size_t i2 = p == p2 ? ((off + len - 1) & 0xfff) + 1 : 0x1000; // end index (exclusive)
			//wprintf(L"\tread p=%zd i1=%zd i2=%zd\n", p, i1, i2);
			if (page) {
				CopyMemory(buf + ((p - p1) << 12), page + i1, i2 - i1);
			}
			else {
				ZeroMemory(buf + ((p - p1) << 12), i2 - i1);
			}
			n = n + (i2 - i1);
		}
	}
	return n;
}

void vblob::truncate(const INT64 len) {
	wprintf(L"truncate %lld\n", len);
	// 0->0, 1->1, 4096->1, 4097->2
	size_t maxp = (len + 4095) >> 12; // pages required, first index of not required page
	for (size_t p = maxp; p < pages.size(); p++) {
		freepage(pages[p]);
	}
	wprintf(L"\tpages=%zd len=%lld -> pages=%zd len=%lld\n", pages.size(), length, maxp, len);
	pages.resize(maxp, 0);
	length = len;
}

void vblob::write(const LPBYTE buf, const size_t off, const size_t len)
{
	truncate(max(length, off + len));
	wprintf(L"write %p, %zd, %zd (pages: %zd length: %zd)\n", buf, off, len, pages.size(), length);
	if (len > 0) {
		size_t p1 = off >> 12;
		size_t p2 = (off + len - 1) >> 12;

		for (size_t p = p1; p <= p2; p++) {
			LPBYTE page = pages[p];
			if (!page) {
				pages[p] = page = newpage();
			}
			size_t i1 = p == p1 ? off & 0xfff : 0;
			size_t i2 = p == p2 ? ((off + len - 1) & 0xfff) + 1 : 0x1000;
			//wprintf(L"\twrite p=%zd i1=%zd i2=%zd\n", p, i1, i2);
			CopyMemory(page + i1, buf + ((p - p1) << 12), i2 - i1);
		}
	}
}

vfile* vdir::find (const std::wstring name) {
	//wprintf(L"find %s\n", name.c_str());
	for (int n = 0; n < files.size(); n++) {
		if (files[n]->name == name) {
			return files[n];
		}
	}
	return 0;
}

std::pair<vdir*,vfile*> vdir::findpath (const LPCWSTR path) 
{
	std::vector<std::wstring> pathv = PathVector(path);
	wprintf(L"findpath %s -> %s\n", path, VectorString(&pathv).c_str());

	// \ [0] = (null, this)
	// \abc [1] = (this, abc)
	// \abc\def [2] = (abc, def)
	vdir* d = 0;
	vfile* f = this;
	for (size_t n = 0; n < pathv.size(); n++) {
		//wprintf(L"\tn=%zd d=%s f=%s\n", n, d ? d->tos().c_str() : 0, f ? f->tos().c_str() : 0);
		//d = dynamic_cast<vdir*>(f);
		d = f->dir();
		f = d ? d->find(pathv[n]) : 0;
	}

	//wprintf(L"\t=> p=%s f=%s\n", d ? d->tos().c_str() : 0, f ? f->tos().c_str() : 0);
	return std::pair<vdir*, vfile*>(d, f);
}

vfile* vdir::create(const LPCWSTR path, const int dir) {
	std::vector<std::wstring> pathv = PathVector(path);
	wprintf(L"create %s, %d -> %s\n", path, dir, VectorString(&pathv).c_str());
	if (pathv.size() > 0) {
		std::wstring name = pathv.back();
		if (!find(name)) {
			vfile *f;
			if (dir) {
				f = new vdir(this, name);
			}
			else {
				f = new vblob(this, name);
			}
			wprintf(L"push %s\n", f->tos().c_str());
			files.push_back(f);
			return f;
		}
	}
	return 0;
}

int vdir::remove(vfile* f) {
	for (std::vector<vfile*>::iterator it = files.begin(); it != files.end(); ++it) {
		vfile* g = *it;
		if (g == f) {
			f->name.clear();
			f->parent = 0;
			files.erase(it);
			return 1;
		}
	}
	return 0;
}

int vdir::add(vfile* f, std::wstring name) {
	if (name.empty() || find(name)) {
		return 0;
	}
	else {
		f->name = name;
		f->parent = this;
		files.push_back(f);
		return 1;
	}
}
