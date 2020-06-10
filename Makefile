
EXEC=kread

# find .c file under the current dir
C_SOURCES = $(shell find . -path "./*" -prune -o -name "*.c" -print)
C_OBJECTS = $(patsubst %.c,%.o,$(C_SOURCES))

# find .asm file under the current dir
S_SOURCES = $(shell find ./init -name "*.asm")
S_OBJECTS = $(patsubst %.asm,%.o,$(S_SOURCES))


CC = gcc
ASM = nasm
LD = ld
OBJCOPY = objcopy

C_FLAGS   = -c -Wall -ggdb -gstabs+ -nostdinc -fno-builtin -std=c99\
-fno-stack-protector -I include

LD_FLAGS  = 


$(EXEC) : $(C_OBJECTS)
	$(LD) $(LD_FLAGS) $(S_OBJECTS) $(C_OBJECTS) -o $(EXEC)

.c.o:
	@echo $(C_SOURCES)
	$(CC) $(C_FLAGS) $< -o $@

.PHONY: all clean install

all:
	@echo "build $(EXEC)"

install:
	install $(EXEC)

clean :
	rm -f $(EXEC) $(C_OBJECTS)

