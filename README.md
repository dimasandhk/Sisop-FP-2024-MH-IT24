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

<hr>

- DELETE CHANNEL & ROOM
![](./img/del-ch-room.png)

<hr>

- EDIT CHANNEL & ROOM
![](./img/edit-ch-room.png)

<hr>

- EXIT COMMAND
![](./img/EXIT.png)

# Command Handling tambahan setelah revisi
- EDIT PROFILE SELF
![](./img/edit-profile-self.png)

- EDIT PROFILE FROM ROOT
![](./img/edit-where-root.png)

- REMOVE USER FROM ROOT
![](./img/remove-root.png)

- KICK USER
![](./img/kick-user.png)
