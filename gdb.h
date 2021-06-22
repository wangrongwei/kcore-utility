#ifndef __GDB_H__
#define __GDB_H__

#define GDB_5_3   (0)
#define GDB_6_0   (1)
#define GDB_6_1   (2)
#define GDB_7_0   (3)
#define GDB_7_3_1 (4)
#define GDB_7_6   (5)
#define SUPPORTED_GDB_VERSIONS (GDB_7_6 + 1)

/*
 *  GNU commands
 */
#define GNU_DATATYPE_INIT           (1)
#define GNU_DISASSEMBLE             (2)
#define GNU_GET_LINE_NUMBER         (3)
#define GNU_PASS_THROUGH            (4)
#define GNU_GET_DATATYPE            (5)
#define GNU_COMMAND_EXISTS          (6)
#define GNU_STACK_TRACE             (7)
#define GNU_ALPHA_FRAME_OFFSET      (8)
#define GNU_FUNCTION_NUMARGS        (9)
#define GNU_RESOLVE_TEXT_ADDR       (10)
#define GNU_ADD_SYMBOL_FILE         (11)
#define GNU_DELETE_SYMBOL_FILE      (12)
#define GNU_VERSION                 (13)
#define GNU_PATCH_SYMBOL_VALUES     (14)
#define GNU_GET_SYMBOL_TYPE         (15)
#define GNU_USER_PRINT_OPTION       (16)
#define GNU_SET_CRASH_BLOCK         (17)
#define GNU_GET_FUNCTION_RANGE      (18)
#define GNU_GET_NEXT_DATATYPE       (19)
#define GNU_LOOKUP_STRUCT_CONTENTS  (20)
#define GNU_DEBUG_COMMAND           (100)
/*
 *  GNU flags
 */
#define GNU_PRINT_LINE_NUMBERS   (0x1)
#define GNU_FUNCTION_ONLY        (0x2)
#define GNU_PRINT_ENUMERATORS    (0x4)
#define GNU_RETURN_ON_ERROR      (0x8)
#define GNU_COMMAND_FAILED      (0x10)
#define GNU_FROM_TTY_OFF        (0x20)
#define GNU_NO_READMEM          (0x40)
#define GNU_VAR_LENGTH_TYPECODE (0x80)

/*
 *  Common request structure for BFD or GDB data or commands.
 */
struct gnu_request {    
	int command;
	char *buf;
	FILE *fp;
	unsigned long addr;
	unsigned long addr2;
	unsigned long count;
	unsigned long flags;
	char *name;
	unsigned long length;
	int typecode;
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1) || defined(GDB_7_0) 
	char *typename;
#else
	char *type_name;
#endif
	char *target_typename;
	unsigned long target_length;
	int target_typecode;
	int is_typedef;
	char *member;
	long member_offset;
	long member_length;
	int member_typecode;
	long value;
	char *tagname;
	unsigned long pc;
	unsigned long sp;
	unsigned long ra;
	int curframe;
	unsigned long frame;
	unsigned long prevsp;
	unsigned long prevpc;
	unsigned long lastsp;
	unsigned long task;
	unsigned long debug;
	//struct stack_hook *hookp;
	struct global_iterator {
    		int finished; 
		int block_index;
    		//struct symtab *symtab;
    		//struct symbol *sym;
    		//struct objfile *obj;
  	} global_iterator;
	//struct load_module *lm;
	char *member_main_type_name;
	char *member_main_type_tag_name;
	char *member_target_type_name;
	char *member_target_type_tag_name;
	char *type_tag_name;
};


/*
 *  gdb/symtab.c
 */
extern void gdb_command_funnel(struct gnu_request *);


#endif
