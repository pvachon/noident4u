OBJ=noident4u.o
TARGET=noident4u

# DEBUGFLAGS=-D_NI_DEBUG -D_NI_DEBUG_STATE
DEBUGFLAGS=
CFLAGS=-O2 -g $(DEBUGFLAGS) -std=c99 -D_GNU_SOURCE
LDFLAGS=-lrt

all: $(TARGET)

.c.o:
	$(CC) $(CFLAGS) -c $<

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(LDFLAGS) $(OBJ)

clean:
	$(RM) $(OBJ)
	$(RM) $(TARGET)

.PHONY: all clean
