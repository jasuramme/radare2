OBJ_ARM=bp_ppc.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=bp_ppc.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC} -shared ${CFLAGS} -o ${TARGET_ARM} ${OBJ_ARM}
