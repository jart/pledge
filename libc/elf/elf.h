#ifndef PLEDGE_LIBC_ELF_ELF_H_
#define PLEDGE_LIBC_ELF_ELF_H_

#include <elf.h>
#include <stddef.h>

void CheckElfAddress(const Elf64_Ehdr *, size_t, intptr_t, size_t);
Elf64_Phdr *GetElfSegmentHeaderAddress(const Elf64_Ehdr *, size_t, unsigned);

#endif
