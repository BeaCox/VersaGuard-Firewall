#ifndef CORE_FUNC_H
#define CORE_FUNC_H

#include <gtk/gtk.h>
#include "database.h"

void on_import_button_clicked(GtkButton *button, gpointer data);
void on_add_button_clicked(GtkButton *button, gpointer data);
void on_export_button_clicked(GtkButton *button, gpointer data);
void on_delete_button_clicked(GtkButton *button, gpointer data);
void on_select_all_button_clicked(GtkButton *button, gpointer data);

#endif // CORE_FUNC_H
