#include <stdlib.h>
#include <stdio.h>

#include <gtk/gtk.h>

#include "core.h"

// Callback for the “Save Encrypted” button
static void on_save_clicked(GtkButton *button, gpointer user_data) {
    GtkTextBuffer *buffer = GTK_TEXT_BUFFER(user_data);
    GtkTextIter start, end;
    gchar *text;

    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

    EncryptAndSaveFile(".\\", "notes.enc", text);

    g_free(text);
}


void read_and_decrypt_file(GtkTextBuffer* buffer) {
    
    char* text = ReadFileAndDecrypt(".\\", "notes.enc");
    if (text == NULL)
        return;
    gtk_text_buffer_set_text (buffer, text, strlen(text));

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
    
    //read_and_decrypt_file(buffer);
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