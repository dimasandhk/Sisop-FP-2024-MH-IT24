#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bcrypt.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 10240
#define USERS_FILE "/home/dim/uni/sisop/FP/DiscorIT/users.csv"
#define CHANNELS_FILE "/home/dim/uni/sisop/FP/DiscorIT/channels.csv"

typedef struct {
    int socket;
    struct sockaddr_in address;
    char logged_in_user[50];
    char logged_in_role[10];
    char logged_in_channel[50];
    char logged_in_room[50];
} client_info;

client_info *clients[5];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void *handle_client(void *arg);
void daemonize();

void register_user(const char *username, const char *password, client_info *client);
void login_user(const char *username, const char *password, client_info *client);

void create_directory(const char *path, client_info *client);
void create_channel(const char *username, const char *channel, const char *key, client_info *client);
void create_room(const char *username, const char *channel, const char *room, client_info *client);
void list_channels(client_info *client);
void list_rooms(const char *channel, client_info *client);
void list_users(const char *channel, client_info *client);
void join_channel(const char *username, const char *channel, client_info *client);
void verify_key(const char *username, const char *channel, const char *key, client_info *client);
void join_room(const char *channel, const char *room, client_info *client);

void delete_directory(const char *path);
void delete_channel(const char *channel, client_info *client);
void delete_room(const char *channel, const char *room, client_info *client);
void delete_all_rooms(const char *channel, client_info *client);
void log_activity(const char *channel, const char *message);

void list_users_root(client_info *client);

void handle_exit(client_info *client);

int main() {
    daemonize();

    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    pthread_t tid;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failure");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addr_len)) < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        pthread_t tid;
        client_info *client = (client_info *)malloc(sizeof(client_info));
        client->socket = new_socket;
        client->address = address;
        memset(client->logged_in_user, 0, sizeof(client->logged_in_user));
        memset(client->logged_in_role, 0, sizeof(client->logged_in_role));
        memset(client->logged_in_channel, 0, sizeof(client->logged_in_channel));
        memset(client->logged_in_room, 0, sizeof(client->logged_in_room));

        pthread_create(&tid, NULL, handle_client, (void *)client);
    }

    return 0;
}

void daemonize() {
    pid_t pid, sid;

    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int log_fd = open("/tmp/server.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (log_fd < 0) {
        exit(EXIT_FAILURE);
    }
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
}

void *handle_client(void *arg) {
    client_info *cli = (client_info *)arg;
    char buffer[BUFFER_SIZE];
    int n;

    while ((n = read(cli->socket, buffer, sizeof(buffer))) > 0) {
        buffer[n] = '\0';
        printf("Pesan dari client: %s\n", buffer);

        char *token = strtok(buffer, " ");
        if (token == NULL) {
            char response[] = "Perintah tidak dikenali";
            if (write(cli->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
            continue;
        }

        if (strcmp(token, "REGISTER") == 0) {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            register_user(username, password, cli);
        } else if (strcmp(token, "LOGIN") == 0) {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            if (username == NULL || password == NULL) {
                char response[] = "Format perintah LOGIN tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
                continue;
            }
            login_user(username, password, cli);
        } else if (strcmp(token, "CREATE") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                char response[] = "Format perintah CREATE tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
                continue;
            }
            if (strcmp(token, "CHANNEL") == 0) {
                char *channel = strtok(NULL, " ");
                token = strtok(NULL, " ");
                char *key = strtok(NULL, " ");
                if (channel == NULL || key == NULL) {
                    char response[] = "Penggunaan perintah: CREATE CHANNEL <channel> -k <key>";
                    if (write(cli->socket, response, strlen(response)) < 0) {
                        perror("Unable to send responds to client");
                    }
                    continue;
                }
                create_channel(cli->logged_in_user, channel, key, cli);
            } else if (strcmp(token, "ROOM") == 0) {
                char *room = strtok(NULL, " ");
                if (room == NULL) {
                    char response[] = "Penggunaan perintah: CREATE ROOM <room>";
                    if (write(cli->socket, response, strlen(response)) < 0) {
                        perror("Unable to send responds to client");
                    }
                    continue;
                }
                create_room(cli->logged_in_user, cli->logged_in_channel, room, cli);
            } else {
                char response[] = "Format perintah CREATE tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
            }
        } else if(strcmp(token, "LIST") == 0){
            token = strtok(NULL, " ");
            if (token == NULL) {
                char response[] = "Format perintah LIST tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
                continue;
            }
            if (strcmp(token, "CHANNEL") == 0) {
                list_channels(cli);
            } else if (strcmp(token, "ROOM") == 0) {
                list_rooms(cli->logged_in_channel, cli);
            } else if (strcmp(token, "USER") == 0) {
                strstr(cli->logged_in_role, "ROOT") != NULL ? list_users_root(cli) : list_users(cli->logged_in_channel, cli);
            } else {
                char response[] = "Format perintah LIST tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
            }
        } else if (strcmp(token, "JOIN") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                char response[] = "Format perintah JOIN tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
                continue;
            }
            if (strlen(cli->logged_in_channel) == 0) {
                char *channel = token;
                join_channel(cli->logged_in_user, channel, cli);
            } else {
                char *room = token;
                join_room(cli->logged_in_channel, room, cli);
            }
        } else if (strcmp(token, "DEL") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                char response[] = "Format perintah DEL tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
                continue;
            }
            if (strcmp(token, "CHANNEL") == 0) {
                char *channel = strtok(NULL, " ");
                if(strlen(cli->logged_in_channel) > 0 || strlen(cli->logged_in_room) > 0){
                    char response[] = "Anda harus keluar dari channel";
                    if (write(cli->socket, response, strlen(response)) < 0) {
                        perror("Unable to send responds to client");
                    }
                    continue;
                } else if(channel == NULL) {
                    char response[] = "Penggunaan perintah: DEL CHANNEL <channel>";
                    if (write(cli->socket, response, strlen(response)) < 0) {
                        perror("Unable to send responds to client");
                    }
                    continue;
                } else {
                    delete_channel(channel, cli);
                }
            } else if (strcmp(token, "ROOM") == 0) {
                token = strtok(NULL, " ");
                if (strcmp(token, "ALL") == 0){
                    if(strlen(cli->logged_in_room) > 0 || strlen(cli->logged_in_channel) == 0){
                        char response[] = "You must leave the room or join a channel first";
                        if (write(cli->socket, response, strlen(response)) < 0) {
                            perror("Unable to send responds to client");
                        }
                        continue;
                    }else{
                        delete_all_rooms(cli->logged_in_channel, cli);
                    }
                } else {
                    char *room = token;
                    if(strlen(cli->logged_in_room) > 0 || strlen(cli->logged_in_channel) == 0){
                        char response[] = "You must leave the room or join a channel first";
                        if (write(cli->socket, response, strlen(response)) < 0) {
                            perror("Unable to send responds to client");
                        }
                        continue;
                    } else if(room == NULL) {
                        char response[] = "Penggunaan perintah: DEL ROOM <room>";
                        if (write(cli->socket, response, strlen(response)) < 0) {
                            perror("Unable to send responds to client");
                        }
                        continue;
                    } else {
                        delete_room(cli->logged_in_channel, room, cli);
                    }
                }
            } else {
                char response[] = "Format perintah DEL tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
            }
        } else if (strcmp(token, "EXIT") == 0) {
            handle_exit(cli);
        } else {
            char response[] = "Perintah tidak dikenali";
            if (write(cli->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
        }
    }

    close(cli->socket);
    free(cli);
    pthread_exit(NULL);
}

void create_directory(const char *path, client_info *client) {
    struct stat st = {0};

    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) < 0) {
            char response[] = "Unable to create directory";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
        }
    }
}

void register_user(const char *username, const char *password, client_info *client) {
    if (username == NULL || password == NULL) {
        char response[] = "Username or password cannot be empty";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }
    create_directory("/home/dim/uni/sisop/FP/DiscorIT", client);

    FILE *file = fopen(USERS_FILE, "r+");
    if (!file) {
        file = fopen(USERS_FILE, "w+");
        if (!file) {
            perror("Tidak dapat membuka atau membuat file");
            char response[] = "Tidak dapat membuka atau membuat file users.csv";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
            return;
        }
    }

    char line[256];
    bool user_exists = false;
    int user_count = 0;

    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            user_exists = true;
            break;
        }
        user_count++;
    }

    if (user_exists) {
        char response[100];
        snprintf(response, sizeof(response), "%s sudah terdaftar", username);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        fclose(file);
        return;
    }

    fseek(file, 0, SEEK_END);

    char salt[64];
    snprintf(salt, sizeof(salt), "$2y$12$%.22s", "rahasia1234567890qwertyu");
    char hash[BCRYPT_HASHSIZE];
    bcrypt_hashpw(password, salt, hash);

    if (hash == NULL) {
        char response[] = "Unable to create hash password";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        fclose(file);
        return;
    }

    fprintf(file, "%d,%s,%s,%s\n", user_count + 1, username, hash, user_count == 0 ? "ROOT" : "USER");
    fclose(file);

    char response[100];
    snprintf(response, sizeof(response), "%s berhasil register", username);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }
}

void login_user(const char *username, const char *password, client_info *client) {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) {
        char response[] = "Tidak dapat membuka file users.csv atau user belum terdaftar";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    bool user_found = false;

    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            user_found = true;
            token = strtok(NULL, ","); // Hash password
            char *stored_hash = token;

            if (bcrypt_checkpw(password, stored_hash) == 0){
                snprintf(client->logged_in_user, sizeof(client->logged_in_user), "%s", username);
                token = strtok(NULL, ","); // Role
                snprintf(client->logged_in_role, sizeof(client->logged_in_role), "%s", token);

                char response[BUFFER_SIZE];
                snprintf(response, sizeof(response), "%s berhasil login", username);
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
            } else {
                char response[] = "Password salah";
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
            }
            break;
        }
    }

    if (!user_found) {
        char response[] = "Username tidak ditemukan";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
    }

    fclose(file);
}

void create_channel(const char *username, const char *channel, const char *key, client_info *client) {
    FILE *channels_file = fopen(CHANNELS_FILE, "r+");
    if (!channels_file) {
        channels_file = fopen(CHANNELS_FILE, "w+");
        if (!channels_file) {
            perror("Tidak dapat membuka atau membuat file channels");
            return;
        }
    }

    char line[256];
    bool channel_exists = false;
    int channel_count = 0;

    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, channel) == 0) {
            channel_exists = true;
            break;
        }
        channel_count++;
    }

    if (channel_exists) {
        char response[100];
        snprintf(response, sizeof(response), "Channel %s sudah ada silakan cari nama lain", channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        fclose(channels_file);
        return;
    }

    fseek(channels_file, 0, SEEK_END);

    char salt[64];
    snprintf(salt, sizeof(salt), "$2y$12$%.22s", "rahasia1234567890qwertyu");
    char hash[BCRYPT_HASHSIZE];
    bcrypt_hashpw(key, salt, hash);

    fprintf(channels_file, "%d,%s,%s\n", channel_count + 1, channel, hash);
    fclose(channels_file);

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    create_directory(path, client);

    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin", channel);
    create_directory(path, client);

    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(path, "w+");
    if (auth_file) {
        // Get user id from users.csv
        char user_id[10];
        FILE *users_file = fopen(USERS_FILE, "r");
        if (!users_file) {
            char response[] = "Unable to open users.csv file";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
            fclose(auth_file);
            return;
        }

        char user_line[256];
        bool user_found = false;

        while (fgets(user_line, sizeof(user_line), users_file)) {
            char *token = strtok(user_line, ",");
            strcpy(user_id, token);
            token = strtok(NULL, ",");
            if (token && strcmp(token, username) == 0) {
                user_found = true;
                break;
            }
        }

        fclose(users_file);

        if (user_found) {
            fprintf(auth_file, "%s,%s,ADMIN\n", user_id, username);
        } else {
            char response[] = "User tidak ditemukan";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
        }
        fclose(auth_file);
    } else {
        char response[] = "Unable to create auth.csv";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
    }

    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/user.log", channel);
    FILE *log_file = fopen(log_path, "w+");
    if (log_file) {
        fclose(log_file);
    } else {
        char response[] = "Unable to create user.log";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
    }

    char response[100];
    snprintf(response, sizeof(response), "Channel %s dibuat", channel);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    char log_message[100];
    snprintf(log_message, sizeof(log_message), "ADMIN membuat channel %s", channel);
    log_activity(channel, log_message);
}

void create_room(const char *username, const char *channel, const char *room, client_info *client) {
    char auth_path[256];
    snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);

    FILE *auth_file = fopen(auth_path, "r");
    if (!auth_file) {
        char response[] = "Unable to open auth.csv file or you're not in a channel";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    bool is_admin = false;
    bool is_root = false;

    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        if (strcmp(token, username) == 0) {
            token = strtok(NULL, ",");
            if (strstr(token, "ADMIN") != NULL) {
                is_admin = true;
            } else if (strstr(token, "ROOT") != NULL) {
                is_root = true;
            }
        }
    }

    fclose(auth_file);

    if (!is_admin && !is_root) {
        char response[] = "Anda tidak memiliki izin untuk membuat room di channel ini";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char check_path[256];
    snprintf(check_path, sizeof(check_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(check_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        char response[] = "Nama room sudah digunakan";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    create_directory(path, client);

    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s/chat.csv", channel, room);
    FILE *chat_file = fopen(path, "w+");
    if(chat_file){
        fclose(chat_file);
    }else{
        char response[] = "Unable to create chat.csv";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }
    
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Room %s dibuat", room);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    char log_message[100];
    if(is_root){
        snprintf(log_message, sizeof(log_message), "ROOT membuat room %s", room);
    }else{
        snprintf(log_message, sizeof(log_message), "ADMIN membuat room %s", room);
    }
    log_activity(channel, log_message);
}

void list_channels(client_info *client) {
    char path[256];
    strcpy(path, CHANNELS_FILE);
    FILE *channels_file = fopen(path, "r+");
    if (channels_file == NULL) {
        char response[] = "Unable to open channels.csv file or there are no channels";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    char response[BUFFER_SIZE] = "";

    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        snprintf(response + strlen(response), sizeof(response) - strlen(response), "%s ", token);
    }

    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    fclose(channels_file);
}

void list_rooms(const char *channel, client_info *client) {
    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    DIR *dir = opendir(path);
    if (dir == NULL) {
        char response[] = "Unable to open channel dir or there are no rooms";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    struct dirent *entry;
    char response[BUFFER_SIZE] = "";

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 && strcmp(entry->d_name, "admin") != 0) {
            char entry_path[512];
            snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);
            struct stat entry_stat;
            if (stat(entry_path, &entry_stat) == 0 && S_ISDIR(entry_stat.st_mode)) {
                snprintf(response + strlen(response), sizeof(response) - strlen(response), "%s ", entry->d_name);
            }
        }
    }

    if (strlen(response) == 0) {
        snprintf(response, sizeof(response), "Tidak ada room yang ditemukan");
    }

    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    closedir(dir);
}

void list_users(const char *channel, client_info *client) {
    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(path, "r+");
    if (auth_file == NULL) {
        char response[] = "Unable to open auth.csv file or you're not in a channel";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    char response[BUFFER_SIZE] = "";

    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        snprintf(response + strlen(response), sizeof(response) - strlen(response), "%s ", token);
    }

    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    fclose(auth_file);
}

void list_users_root(client_info *client) {
    FILE *users_file = fopen(USERS_FILE, "r+");
    if (users_file == NULL) {
        char response[] = "Unable to open users.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    char response[BUFFER_SIZE] = "";

    while (fgets(line, sizeof(line), users_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        snprintf(response + strlen(response), sizeof(response) - strlen(response), "%s ", token);
    }

    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    fclose(users_file);
}

void join_channel(const char *username, const char *channel, client_info *client) {
    char channel_path[256];
    snprintf(channel_path, sizeof(channel_path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    struct stat st;
    
    if (stat(channel_path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "Channel %s tidak ada", channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    // Check if user is ROOT in users.csv
    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) {
        char response[] = "Unable to open users.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    bool is_root = false;
    char user_id[10];

    while (fgets(line, sizeof(line), users_file)) {
        char *token = strtok(line, ",");
        strcpy(user_id, token);
        token = strtok(NULL, ",");
        char *name = token;
        if (token && strstr(name, username) != NULL){
            token = strtok(NULL, ",");
            token = strtok(NULL, ",");
            char *role = token;
            if (strstr(role, "ROOT") != NULL){
                is_root = true;
            }
            break;
        }
    }

    fclose(users_file);

    if (is_root) {
        // If ROOT, join without further checks
        snprintf(client->logged_in_channel, sizeof(client->logged_in_channel), "%s", channel);

        // Ensure ROOT role is recorded in auth.csv
        char auth_path[256];
        snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
        FILE *auth_file = fopen(auth_path, "r+");
        if (auth_file) {
            bool root_exists = false;
            while (fgets(line, sizeof(line), auth_file)) {
                char *token = strtok(line, ",");
                if (token == NULL) continue;
                token = strtok(NULL, ",");
                if (token == NULL) continue;
                if (strcmp(token, username) == 0) {
                    root_exists = true;
                    break;
                }
            }

            if (!root_exists) {
                auth_file = fopen(auth_path, "a");
                if (auth_file) {
                    fprintf(auth_file, "%s,%s,ROOT\n", user_id, username);
                    fclose(auth_file);
                }
            } else {
                fclose(auth_file);
            }
        } else {
            char response[] = "Unable to open auth.csv file";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
            return;
        }

        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "[%s/%s]", username, channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    // Check if user is ADMIN/USER/BANNED in auth.csv
    char auth_path[256];
    snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(auth_path, "r");
    if (!auth_file) {
        char response[] = "Unable to open auth.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    bool is_admin = false;
    bool is_user = false;
    bool is_banned = false;

    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        if (strcmp(token, username) == 0) {
            token = strtok(NULL, ",");
            if (strstr(token, "ADMIN") != NULL) {
                is_admin = true;
                break;
            } else if (strstr(token, "USER") != NULL){
                is_user = true;
                break;
            } else if (strstr(token, "BANNED") != NULL){
                is_banned = true;
                break;
            }
        }
    }

    fclose(auth_file);

    if (is_banned) {
        char response[] = "Anda telah diban, silahkan menghubungi admin";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    if (is_admin || is_user) {
        snprintf(client->logged_in_channel, sizeof(client->logged_in_channel), "%s", channel);
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "[%s/%s]", username, channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return; // ADMIN or already registered USER joined without further checks
    } else {
        // If not ROOT, ADMIN, or already registered USER, prompt for key
        char response[] = "Key: ";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }

        char key[BUFFER_SIZE];
        memset(key, 0, sizeof(key));

        if (recv(client->socket, key, sizeof(key), 0) < 0) {
            perror("Unable to receive key from client");
            return;
        }
        verify_key(username, channel, key, client);
    }
}

void verify_key(const char *username, const char *channel, const char *key, client_info *client) {
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) {
        char response[] = "Unable to open channels.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    bool key_valid = false;

    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, channel) == 0) {
            token = strtok(NULL, ","); // Get the stored hash
            char *stored_hash = token;
            stored_hash[strcspn(stored_hash, "\n")] = 0;
            if(token && bcrypt_checkpw(key, stored_hash) == 0){
                key_valid = true;
            }
            break;
        }
    }

    fclose(channels_file);

    if (key_valid) {
        FILE *users_file = fopen(USERS_FILE, "r");
        if (!users_file) {
            char response[] = "Unable to open users.csv file";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
            return;
        }

        char user_line[256];
        char user_id[10];
        bool user_found = false;

        while (fgets(user_line, sizeof(user_line), users_file)) {
            char *token = strtok(user_line, ",");
            strcpy(user_id, token);
            token = strtok(NULL, ",");
            if (token && strcmp(token, username) == 0) {
                user_found = true;
                break;
            }
        }

        fclose(users_file);

        if (user_found) {
            char auth_path[256];
            snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
            FILE *auth_file = fopen(auth_path, "a");
            if (auth_file) {
                fprintf(auth_file, "%s,%s,USER\n", user_id, username);
                fclose(auth_file);

                snprintf(client->logged_in_channel, sizeof(client->logged_in_channel), "%s", channel);
                char response[BUFFER_SIZE];
                snprintf(response, sizeof(response), "[%s/%s]", username, channel);
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
            } else {
                char response[] = "Unable to open auth.csv file";
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Unable to send responds to client");
                }
            }
        } else {
            char response[] = "User tidak ditemukan";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
            }
        }
    } else {
        char response[] = "Key salah";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
    }

    
}

void join_room(const char *channel, const char *room, client_info *client) {
    // Check if the room directory exists
    char room_path[256];
    snprintf(room_path, sizeof(room_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(room_path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "Room %s tidak ada di channel %s", room, channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    snprintf(client->logged_in_room, sizeof(client->logged_in_room), "%s", room);
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "[%s/%s/%s]", client->logged_in_user, channel, room);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }
}

void delete_directory(const char *path) {
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == -1) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            delete_directory(full_path);
        } else {
            unlink(full_path);
        }
    }

    closedir(dir);
    rmdir(path);
}

void delete_channel(const char *channel, client_info *client) {
    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) {
        char response[] = "Unable to open users.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
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
                perror("Unable to send responds to client");
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
        char response[] = "Anda tidak memiliki izin untuk menghapus channel ini";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    struct stat st;
    if (stat(path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        char response[] = "Channel tidak ditemukan";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    // Delete directory recursively
    delete_directory(path);

    // Update channels.csv
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) {
        char response[] = "Unable to open channels.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "/home/dim/uni/sisop/FP/DiscorIT/channels_temp.csv");
    FILE *temp_file = fopen(temp_path, "w");
    if (!temp_file) {
        char response[] = "Unable to create temp file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        fclose(channels_file);
        return;
    }

    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, channel) != 0) {
            fprintf(temp_file, "%s", line);
        }
    }

    fclose(channels_file);
    fclose(temp_file);

    remove(CHANNELS_FILE);
    rename(temp_path, CHANNELS_FILE);

    char response[100];
    snprintf(response, sizeof(response), "%s berhasil dihapus", channel);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }
}

void delete_room(const char *channel, const char *room, client_info *client) {
        bool is_admin = false;
        bool is_root = false;
        char auth_path[256];
        char line[256];
        snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
        FILE *auth_file = fopen(auth_path, "r");
        if (!auth_file) {
            char response[] = "Unable to open auth.csv file";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send responds to client");
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
                }else if (strstr(token, "ROOT") != NULL){
                    is_root = true;
                }
                break;
            }
        }

        fclose(auth_file);

    if (!is_admin && !is_root) {
        char response[] = "Anda tidak memiliki izin untuk menghapus room";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        char response[] = "Room tidak ditemukan";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    // Delete directory
    delete_directory(path);

    char response[100];
    snprintf(response, sizeof(response), "%s berhasil dihapus", room);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    char log_message[100];
    if(is_root){
        snprintf(log_message, sizeof(log_message), "ROOT menghapus room %s", room);
    } else {
        snprintf(log_message, sizeof(log_message), "ADMIN menghapus room %s", room);
    }
    log_activity(channel, log_message);
}

void delete_all_rooms(const char *channel, client_info *client) {
    char auth_path[256];
    snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(auth_path, "r");
    if (!auth_file) {
        char response[] = "Unable to open auth.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char line[256];
    bool is_admin = false;
    bool is_root = false;

    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        if (strcmp(token, client->logged_in_user) == 0) {
            token = strtok(NULL, ",");
            if (strstr(token, "ADMIN") != NULL) {
                is_admin = true;
            } else if (strstr(token, "ROOT") != NULL){
                is_root = true;
            }
            break;
        }
    }

    fclose(auth_file);

    if (!is_admin && !is_root) {
        char response[] = "Anda tidak memiliki izin untuk menghapus semua room";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    DIR *dir = opendir(path);
    if (dir == NULL) {
        char response[] = "Unable to open channel dir";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
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

    char response[] = "Semua room dihapus";
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }

    char log_message[100];
    if(is_root){
        snprintf(log_message, sizeof(log_message), "ROOT menghapus semua room");
    } else {
        snprintf(log_message, sizeof(log_message), "ADMIN menghapus semua room");
    }
    log_activity(channel, log_message);
}

void log_activity(const char *channel, const char *message) {
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/user.log", channel);

    FILE *log_file = fopen(log_path, "a+");
    if (!log_file) {
        perror("Unable to open user.log file");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char date[30];
    strftime(date, sizeof(date), "%d/%m/%Y %H:%M:%S", t);

    fprintf(log_file, "[%s] %s\n", date, message);
    fclose(log_file);
}

void handle_exit(client_info *client) {
    if (strlen(client->logged_in_room) > 0) {
        memset(client->logged_in_room, 0, sizeof(client->logged_in_room));
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "[%s/%s]", client->logged_in_user, client->logged_in_channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
    } else if (strlen(client->logged_in_channel) > 0) {
        memset(client->logged_in_channel, 0, sizeof(client->logged_in_channel));
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "[%s]", client->logged_in_user);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
    } else {
        char response[] = "Anda telah keluar dari aplikasi";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        close(client->socket);
        pthread_exit(NULL);
    }
}