all:
	gcc main.c aes.c core.c -g -o secure_notes.exe -lws2_32 -lshlwapi -lcomctl32 -lgdi32 -municode -mwindows
