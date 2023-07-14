#ifndef HEADERBAR_H
#define HEADERBAR_H

#include "global.h"

void on_dark_toggle_button_toggled(GtkToggleButton *toggle_button, gpointer data);
void on_about_button_clicked(GtkButton *button, gpointer data);
void on_data_dir_button_clicked(GtkButton *button, gpointer data);

#endif /* HEADERBAR_H */
