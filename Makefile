CC = gcc
CFLAGS = -Wall -O2 -municode -mwindows
LIBS = -lws2_32 -lshlwapi -lcomctl32 -lgdi32 -ladvapi32 -lsodium
TARGET = SecureNotes.exe
SRC = main.c core.c aes.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
