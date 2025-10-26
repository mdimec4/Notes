all:
	gcc main.c aes.c core.c -g -o secure_notes.exe `pkg-config --cflags --libs gtk4` -lws2_32 -lshlwapi
