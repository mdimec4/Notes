all:
	gcc main.c aes.c -g -o secure_notes.exe `pkg-config --cflags --libs gtk4` -lws2_32
