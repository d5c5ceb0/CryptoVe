.PHONY: all

all : libcrypto.so

CC    := gcc
C_INC := /usr/include/tcl8.5 
C_LIB := /usr/lib/
C_OBJ := math.c crypto.c aes.c des.c sm4.c md5.c sm3.c sha.c miracl.a

libcrypto.so : ${C_OBJ}
	${CC} -fPIC -shared -o libcrypto.so -DUSE_TCL_STUBS -I${C_INC}  ${C_OBJ} -L${C_LIB} -ltclstub8.5

