OBJ_MALLOC=io_malloc.o

STATIC_OBJ+=${OBJ_MALLOC}
TARGET_MALLOC=io_malloc.${EXT_SO}
ALL_TARGETS+=${TARGET_MALLOC}

${TARGET_MALLOC}: ${OBJ_MALLOC}
	${CC} -shared ${CFLAGS} -o ${TARGET_MALLOC} ${OBJ_MALLOC}
