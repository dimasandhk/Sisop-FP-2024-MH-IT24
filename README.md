# Sisop-FP-2024-MH-IT24

Anggota Kelompok:

- Dimas Andhika Diputra 5027231074
- Mochamad Fadhil Saifullah 5027231068
- Thio Billy Amansyah 5027231007

# Command Handling sebelum revisi
Handling request dari client dengan kode:

```c
void *handle_client(void *arg) {
    ClientInfo *cli = (ClientInfo *)arg;
    char buffer[10240];
    int n;

    while ((n = read(cli->socket, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[n] = '\0';
        printf("Pesan dari client: %s\n", buffer);
        printf("tes 123 setelah pesan dari client");
        char *command = strtok(buffer, " ");
        if (!command) {
            const char *response = "Perintah tidak dikenali";
            write(cli->socket, response, strlen(response));
            continue;
        }

        if (strcmp(command, "REGISTER") == 0) {
            handle_register(cli);
        } else if (strcmp(command, "LOGIN") == 0) {
            handle_login(cli);
        } else if (strcmp(command, "CREATE") == 0) {
            handle_create(cli);
        } else if (strcmp(command, "LIST") == 0) {
            handle_list(cli);
        } else if (strcmp(command, "JOIN") == 0) {
            command = strtok(NULL, " ");
            if (command == NULL) {
                char response[] = "Format perintah JOIN tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Gagal mengirim respons ke client");
                }
                continue;
            }
            if (strlen(cli->logged_in_channel) == 0) {
                char *channel = command;
                join_channel(cli->logged_in_user, channel, cli);
            } else {
                char *room = command;
                join_room(cli->logged_in_channel, room, cli);
            }
        } else if (strcmp(command, "DEL") == 0) {
            handle_delete(cli);
        } else if (strcmp(command, "EDIT") == 0) {
            handle_update(cli);
        } else if (strcmp(command, "REMOVE") == 0) {
            handle_remove(cli);
        }  else if (strcmp(command, "EXIT") == 0) {
            handle_exit(cli);
        } else {
            const char *response = "Perintah tidak dikenali";
            write(cli->socket, response, strlen(response));
        }
    }

    close(cli->socket);
    free(cli);
    pthread_exit(NULL);
}
```

Fitur yang dibuat sebelum revisi yakni:
- LOGIN REGISTER USER
![](./img/image.png)

Kode yang digunakan untuk handle login & register

```c
void register_user(const char *username, const char *password, ClientInfo *client) {
    if (username == NULL || password == NULL) {
        send_response(client, "Username or password cannot be empty");
        return;
    }

    create_directory("/home/dim/uni/sisop/FP/DiscorIT", client);

    if (user_exists(username)) {
        char response[100];
        snprintf(response, sizeof(response), "%s sudah terdaftar", username);
        send_response(client, response);
        return;
    }

    int user_count = get_user_count();

    if (!write_user_to_file(username, password, user_count)) {
        send_response(client, "Tidak dapat membuka atau membuat file users.csv");
        return;
    }

    char response[100];
    snprintf(response, sizeof(response), "%s berhasil register", username);
    send_response(client, response);
}

bool verify_user_credentials(const char *username, const char *password, ClientInfo *client) {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) return false;

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            char *stored_hash = strtok(NULL, ",");
            if (bcrypt_checkpw(password, stored_hash) == 0) {
                snprintf(client->logged_in_user, sizeof(client->logged_in_user), "%s", username);
                char *role = strtok(NULL, ",");
                snprintf(client->logged_in_role, sizeof(client->logged_in_role), "%s", role);
                fclose(file);
                return true;
            }
            break;
        }
    }
    fclose(file);
    return false;
}

void login_user(const char *username, const char *password, ClientInfo *client) {
    if (verify_user_credentials(username, password, client)) {
        char response[10240];
        snprintf(response, sizeof(response), "%s berhasil login", username);
        send_response(client, response);
    } else {
        send_response(client, "Username atau password salah");
    }
}
```

<hr>

- CREATE CHANNEL & CREATE ROOM
![](./img/create-ch-room.png)

Kode yang digunakan untuk buat channel dan room

```c

void create_channel(const char *username, const char *channel, const char *key, ClientInfo *client) {
    if (channel_exists(channel)) {
        send_response(client, "Channel sudah ada silakan cari nama lain");
        return;
    }

    int channel_id = get_next_channel_id();
    write_channel_to_file(channel, key, channel_id);
    create_channel_directories(channel, client);
    add_user_to_auth(channel, username, client);

    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/user.log", channel);
    FILE *log_file = fopen(log_path, "w+");
    if (log_file) {
        fclose(log_file);
    }

    send_response(client, "Channel dibuat");
    char log_message[100];
    snprintf(log_message, sizeof(log_message), "ADMIN membuat channel %s", channel);
    log_activity(channel, log_message);
}

bool user_has_permission(const char *channel, const char *username) {
    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(path, "r");
    if (!auth_file) return false;

    char line[256];
    bool has_permission = false;
    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            token = strtok(NULL, ",");
            if (strstr(token, "ADMIN") || strstr(token, "ROOT")) {
                has_permission = true;
                break;
            }
        }
    }
    fclose(auth_file);
    return has_permission;
}

void create_room(const char *username, const char *channel, const char *room, ClientInfo *client) {
    if (!user_has_permission(channel, username)) {
        send_response(client, "Anda tidak memiliki izin untuk membuat room di channel ini");
        return;
    }

    char check_path[256];
    snprintf(check_path, sizeof(check_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(check_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        send_response(client, "Nama room sudah digunakan");
        return;
    }

    create_directory(check_path, client);

    char chat_path[1024];
    snprintf(chat_path, sizeof(chat_path), "%s/chat.csv", check_path);
    FILE *chat_file = fopen(chat_path, "w+");
    if (chat_file) {
        fclose(chat_file);
    } else {
        send_response(client, "Unable to create chat.csv");
        return;
    }

    send_response(client, "Room dibuat");

    char log_message[100];
    snprintf(log_message, sizeof(log_message), "%s membuat room %s", (user_has_permission(channel, username) ? "ROOT" : "ADMIN"), room);
    log_activity(channel, log_message);
}

```

<hr>

- LIST CHANNEL & ROOM & USER
![](./img/list-ch-room.png)

Kode yang digunakan untuk list channel dan room

```c
void list_channels(ClientInfo *client) {
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) {
        send_response(client, "Unable to open channels.csv file or there are no channels");
        return;
    }

    char response[10240] = "";
    char line[256];
    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        if (token) token = strtok(NULL, ","); // Get the channel name
        if (token) {
            strncat(response, token, sizeof(response) - strlen(response) - 1);
            strncat(response, " ", sizeof(response) - strlen(response) - 1);
        }
    }

    if (strlen(response) == 0) {
        snprintf(response, sizeof(response), "No channels found");
    }

    send_response(client, response);
    fclose(channels_file);
}

void list_rooms(const char *channel, ClientInfo *client) {
    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);

    const char *exclusions[] = {".", "..", "admin"};
    char response[10240] = "";
    list_directory(path, exclusions, 3, response, sizeof(response));

    if (strlen(response) == 0) {
        snprintf(response, sizeof(response), "Tidak ada room yang ditemukan");
    }

    send_response(client, response);
}

void list_users(const char *channel, ClientInfo *client) {
    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(path, "r");
    if (!auth_file) {
        send_response(client, "Unable to open auth.csv file or you're not in a channel");
        return;
    }

    char response[10240] = "";
    char line[256];
    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        if (token) token = strtok(NULL, ","); // Get the username
        if (token) {
            strncat(response, token, sizeof(response) - strlen(response) - 1);
            strncat(response, " ", sizeof(response) - strlen(response) - 1);
        }
    }

    if (strlen(response) == 0) {
        snprintf(response, sizeof(response), "No users found");
    }

    send_response(client, response);
    fclose(auth_file);
}

void list_users_root(ClientInfo *client) {
    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) {
        send_response(client, "Unable to open users.csv file");
        return;
    }

    char response[10240] = "";
    char line[256];
    while (fgets(line, sizeof(line), users_file)) {
        char *token = strtok(line, ",");
        if (token) token = strtok(NULL, ","); // Get the username
        if (token) {
            strncat(response, token, sizeof(response) - strlen(response) - 1);
            strncat(response, " ", sizeof(response) - strlen(response) - 1);
        }
    }

    if (strlen(response) == 0) {
        snprintf(response, sizeof(response), "No users found");
    }

    send_response(client, response);
    fclose(users_file);
}
```

<hr>

- DELETE CHANNEL & ROOM
![](./img/del-ch-room.png)

Kode untuk delete channel & room:

```c

void delete_channel(const char *channel, ClientInfo *client) {
    if (!is_user_admin_or_root(channel, client)) {
        const char *response = "Anda tidak memiliki izin untuk menghapus channel ini";
        write(client->socket, response, strlen(response));
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    struct stat st;
    if (stat(path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        const char *response = "Channel tidak ditemukan";
        write(client->socket, response, strlen(response));
        return;
    }

    // Delete directory recursively
    delete_directory(path);

    // Update channels.csv
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) {
        const char *response = "Unable to open channels.csv file";
        write(client->socket, response, strlen(response));
        return;
    }

    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "/home/dim/uni/sisop/FP/DiscorIT/channels_temp.csv");
    FILE *temp_file = fopen(temp_path, "w");
    if (!temp_file) {
        const char *response = "Unable to create temp file";
        write(client->socket, response, strlen(response));
        fclose(channels_file);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        char *line_number = token;
        token = strtok(NULL, ",");
        if (token && strcmp(token, channel) != 0) {
            fprintf(temp_file, "%s,%s", line_number, token);
            while ((token = strtok(NULL, ",")) != NULL) {
                fprintf(temp_file, ",%s", token);
            }
        }
    }

    fclose(channels_file);
    fclose(temp_file);

    remove(CHANNELS_FILE);
    rename(temp_path, CHANNELS_FILE);

    char response[100];
    snprintf(response, sizeof(response), "%s berhasil dihapus", channel);
    write(client->socket, response, strlen(response));
}

void delete_room(const char *channel, const char *room, ClientInfo *client) {
    if (!is_user_admin_or_root(channel, client)) {
        const char *response = "Anda tidak memiliki izin untuk menghapus room";
        write(client->socket, response, strlen(response));
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        const char *response = "Room tidak ditemukan";
        write(client->socket, response, strlen(response));
        return;
    }

    // Recursively delete the room directory
    delete_directory(path);

    char response[100];
    snprintf(response, sizeof(response), "%s berhasil dihapus", room);
    write(client->socket, response, strlen(response));

    char log_message[100];
    snprintf(log_message, sizeof(log_message), "User %s menghapus room %s", client->logged_in_user, room);
    log_activity(channel, log_message);
}

void delete_all_rooms(const char *channel, ClientInfo *client) {
    if (!is_user_admin_or_root(channel, client)) {
        const char *response = "Anda tidak memiliki izin untuk menghapus semua room";
        write(client->socket, response, strlen(response));
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    DIR *dir = opendir(path);
    if (!dir) {
        const char *response = "Unable to open channel dir";
        write(client->socket, response, strlen(response));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, "admin") != 0 && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char room_path[1024];
            snprintf(room_path, sizeof(room_path), "%s/%s", path, entry->d_name);

            struct stat st;
            if (stat(room_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                delete_directory(room_path);
            }
        }
    }
    closedir(dir);

    const char *response = "Semua room dihapus";
    write(client->socket, response, strlen(response));

    char log_message[100];
    snprintf(log_message, sizeof(log_message), "User %s menghapus semua room", client->logged_in_user);
    log_activity(channel, log_message);
}
```

<hr>

- EDIT CHANNEL & ROOM
![](./img/edit-ch-room.png)

Kode untuk update nama channel & room

```c
void update_channel(const char *channel, ClientInfo *client) {
    char *new_channel = strtok(NULL, " "); // Get the "TO"
    if (!new_channel || strcmp(new_channel, "TO") != 0) {
        const char *response = "Penggunaan perintah: EDIT CHANNEL <channel> TO <new_channel>";
        write(client->socket, response, strlen(response));
        return;
    }

    new_channel = strtok(NULL, " "); // Get the new channel name
    if (!new_channel) {
        const char *response = "Penggunaan perintah: EDIT CHANNEL <channel> TO <new_channel>";
        write(client->socket, response, strlen(response));
        return;
    }

    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) {
        const char *response = "Unable to open users.csv file";
        write(client->socket, response, strlen(response));
        return;
    }

    char line[256];
    bool is_admin = false;

    while (fgets(line, sizeof(line), users_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, client->logged_in_user) == 0) {
            token = strtok(NULL, ",");
            token = strtok(NULL, ",");
            if (strstr(token, "ROOT") != NULL) {
                is_admin = true;
            }
            break;
        }
    }

    fclose(users_file);

    if (!is_admin) {
        char auth_path[256];
        snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
        FILE *auth_file = fopen(auth_path, "r");
        if (!auth_file) {
            const char *response = "Unable to open auth.csv file";
            write(client->socket, response, strlen(response));
            return;
        }

        while (fgets(line, sizeof(line), auth_file)) {
            char *token = strtok(line, ",");
            if (token == NULL) continue;
            token = strtok(NULL, ",");
            if (token == NULL) continue;
            if (strcmp(token, client->logged_in_user) == 0) {
                token = strtok(NULL, ",");
                if (strstr(token, "ADMIN") != NULL) {
                    is_admin = true;
                }
                break;
            }
        }

        fclose(auth_file);
    }

    if (!is_admin) {
        const char *response = "Anda tidak memiliki izin untuk mengubah channel ini";
        write(client->socket, response, strlen(response));
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    struct stat st;
    if (stat(path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        const char *response = "Channel tidak ditemukan";
        write(client->socket, response, strlen(response));
        return;
    }

    // Renaming the directory
    char new_path[256];
    snprintf(new_path, sizeof(new_path), "/home/dim/uni/sisop/FP/DiscorIT/%s", new_channel);
    if (rename(path, new_path) == -1) {
        perror("Unable to rename directory");
        const char *response = "Gagal mengganti nama channel";
        write(client->socket, response, strlen(response));
        return;
    }

    // Updating the channels.csv file
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) {
        const char *response = "Unable to open channels.csv file";
        write(client->socket, response, strlen(response));
        return;
    }

    char temp_file[] = "/home/dim/uni/sisop/FP/DiscorIT/channels_temp.csv";
    FILE *temp_channels_file = fopen(temp_file, "w");
    if (!temp_channels_file) {
        const char *response = "Unable to open temporary channels.csv file";
        write(client->socket, response, strlen(response));
        fclose(channels_file);
        return;
    }

    bool channel_found = false;

    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        char *channel_name = strtok(NULL, ",");
        char *stored_hash = strtok(NULL, ",");
        if (channel_name && strcmp(channel_name, channel) == 0) {
            fprintf(temp_channels_file, "%s,%s,%s\n", token, new_channel, stored_hash);
            channel_found = true;
        } else {
            fputs(line, temp_channels_file);
        }
    }

    fclose(channels_file);
    fclose(temp_channels_file);

    if (!channel_found) {
        const char *response = "Channel tidak ditemukan di channels.csv";
        write(client->socket, response, strlen(response));
        remove(temp_file); // Remove the temporary file as it is not needed
        return;
    }

    // Replace the original channels.csv with the updated one
    if (rename(temp_file, CHANNELS_FILE) == -1) {
        perror("Unable to replace channels.csv");
        const char *response = "Gagal memperbarui channels.csv";
        write(client->socket, response, strlen(response));
        return;
    }

    // Success response
    const char *response = "Channel berhasil diubah";
    write(client->socket, response, strlen(response));

    // Log the activity
    char log_message[100];
    snprintf(log_message, sizeof(log_message), "ROOT mengubah channel %s menjadi %s", channel, new_channel);
    log_activity(channel, log_message);
}

void update_room(const char *channel, const char *room, const char *new_room, ClientInfo *client) {
    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) {
        char response[] = "Unable to open users.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return;
    }

    char line[256];
    bool is_admin = false;

    while (fgets(line, sizeof(line), users_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, client->logged_in_user) == 0) {
            token = strtok(NULL, ",");
            token = strtok(NULL, ",");
            if (strstr(token, "ROOT") != NULL) {
                is_admin = true;
            }
            break;
        }
    }

    fclose(users_file);

    if (!is_admin) {
        char auth_path[256];
        snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
        FILE *auth_file = fopen(auth_path, "r");
        if (!auth_file) {
            char response[] = "Unable to open auth.csv file";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send response to client");
            }
            return;
        }

        while (fgets(line, sizeof(line), auth_file)) {
            char *token = strtok(line, ",");
            if (token == NULL) continue;
            token = strtok(NULL, ",");
            if (token == NULL) continue;
            if (strcmp(token, client->logged_in_user) == 0) {
                token = strtok(NULL, ",");
                if (strstr(token, "ADMIN") != NULL) {
                    is_admin = true;
                }
                break;
            }
        }

        fclose(auth_file);
    }

    if (!is_admin) {
        char response[] = "Anda tidak memiliki izin untuk mengedit room ini";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return;
    }

    char room_path[256];
    snprintf(room_path, sizeof(room_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(room_path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        char response[] = "Room tidak ditemukan";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return;
    }

    char new_room_path[256];
    snprintf(new_room_path, sizeof(new_room_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, new_room);

    if (rename(room_path, new_room_path) != 0) {
        char response[] = "Gagal mengubah nama room";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return;
    }

    char response[10240];
    snprintf(response, sizeof(response), "Room %s berhasil diubah menjadi %s", room, new_room);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send response to client");
    }

    char log_message[100];
    snprintf(log_message, sizeof(log_message), "ROOT mengubah room %s menjadi %s", room, new_room);
    log_activity(channel, log_message);
}
```

<hr>

- EXIT COMMAND
![](./img/EXIT.png)

Kode untuk handle command exit

```c
void clear_logged_in_info(ClientInfo *client) {
    memset(client->logged_in_room, 0, sizeof(client->logged_in_room));
    memset(client->logged_in_channel, 0, sizeof(client->logged_in_channel));
}

void handle_exit(ClientInfo *client) {
    char response[10240];
    if (strlen(client->logged_in_room) > 0) {
        clear_logged_in_info(client);
        snprintf(response, sizeof(response), "[%s/%s]", client->logged_in_user, client->logged_in_channel);
    } else if (strlen(client->logged_in_channel) > 0) {
        clear_logged_in_info(client);
        snprintf(response, sizeof(response), "[%s]", client->logged_in_user);
    } else {
        snprintf(response, sizeof(response), "Anda telah keluar dari aplikasi");
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        close(client->socket);
        pthread_exit(NULL);
    }

    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send response to client");
    }
}
```

# Command Handling tambahan setelah revisi
- EDIT PROFILE SELF
![](./img/edit-profile-self.png)

- EDIT PROFILE FROM ROOT
![](./img/edit-where-root.png)

- REMOVE USER FROM ROOT
![](./img/remove-root.png)

- KICK USER
![](./img/kick-user.png)
