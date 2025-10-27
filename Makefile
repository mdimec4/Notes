all:
	gcc main.c aes.c core.c -o secure_notes.exe \
  -lws2_32 -lshlwapi -lcomctl32 -lgdi32 -ladvapi32 -municode -mwindows
