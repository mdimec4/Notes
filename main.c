#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

//#define _WINSOCKAPI_   // Prevent conflicts with sys/select.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <gtk/gtk.h>

#include "aes.h"

unsigned char key[AES_KEYLEN] = "01234567890123456789012345678901"; // 32 bytes
unsigned char iv[AES_BLOCKLEN] = "0123456789012345";                    // 16 bytes

struct AES_ctx encryption_ctx;

// Callback for the “Save Encrypted” button
static void on_save_clicked(GtkButton *button, gpointer user_data) {
    GtkTextBuffer *buffer = GTK_TEXT_BUFFER(user_data);
    GtkTextIter start, end;
    gchar *text;

    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

    FILE *f = fopen("notes.txt", "wb");
    if (f) {
        size_t text_len = strlen(text);
        size_t text_with_prefix_len = sizeof(uint32_t) + text_len;

        // Round up to multiple of AES block length (16)
        size_t encrypted_txt_cap =
            ((text_with_prefix_len + AES_BLOCKLEN - 1) / AES_BLOCKLEN) * AES_BLOCKLEN;

        char* data = calloc(encrypted_txt_cap, 1);

        // Store big-endian length prefix
        uint32_t write_len = htonl((uint32_t)text_len);
        memcpy(data, &write_len, sizeof(write_len));
        memcpy(data + sizeof(uint32_t), text, text_len);

        // Encrypt the full padded buffer
        AES_init_ctx_iv(&encryption_ctx, key, iv); // important!
        AES_CBC_encrypt_buffer(&encryption_ctx, data, encrypted_txt_cap);

        fwrite(data, 1, encrypted_txt_cap, f);

        free(data);
        fflush(f);
        fclose(f);
        g_print("Saved text to notes.txt (encrypted)\n");
    } else {
        g_warning("Failed to save file!\n");
    }

    g_free(text);
}


void read_and_decrypt_file(GtkTextBuffer* buffer) {
    FILE *f = fopen("notes.txt", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        size_t encrypted_len = ftell(f);
        
        if(encrypted_len <= sizeof(uint32_t))
        {
            fclose(f);
            return;
        }
        char* data = calloc(encrypted_len + 1, 1);
        fseek(f, 0, SEEK_SET);
        size_t r1 = fread(data, 1, encrypted_len, f); 
        fclose(f);

        AES_init_ctx_iv(&encryption_ctx, key, iv);
        AES_CBC_decrypt_buffer(&encryption_ctx, data, encrypted_len);
        //string is prefixed with big endian 32 bit length
        
        uint32_t read_len;
        memcpy(&read_len, data, sizeof(read_len));  // Safe: no unaligned access
        read_len = ntohl(read_len); 
        if (read_len + sizeof(uint32_t) > encrypted_len)
        {
            free(data);
            return;
        }
        data[sizeof(uint32_t) + read_len] = '\0';  
        gtk_text_buffer_set_text (buffer, data + sizeof(uint32_t), read_len);

        free(data);
        g_print("Read text from notes.txt (unencrypted for now)\n");
    } else {
        g_warning("Failed to read file!\n");
    }
}

// Called when the application window is created
static void on_activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Secure Notes (Prototype)");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_window_set_child(GTK_WINDOW(window), vbox);

    GtkWidget *textview = gtk_text_view_new();
    gtk_widget_set_size_request(GTK_WIDGET(textview), 600, 300);
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
    gtk_box_append(GTK_BOX(vbox), textview);

    GtkWidget *save_button = gtk_button_new_with_label("Save Encrypted");
    g_signal_connect(save_button, "clicked", G_CALLBACK(on_save_clicked), buffer);
    gtk_box_append(GTK_BOX(vbox), save_button);

    // Show the window
    gtk_window_present(GTK_WINDOW(window));
    
    read_and_decrypt_file(buffer);
}



int main(int argc, char *argv[]) {
    GtkApplication *app;
    int status;
    
    app = gtk_application_new("com.example.securenotes", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}