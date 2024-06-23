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

#define CHANNELS_FILE "/home/dim/uni/sisop/FP/DiscorIT/channels.csv"
#define USERS_FILE "/home/dim/uni/sisop/FP/DiscorIT/users.csv"

typedef struct {
    int socket;
    struct sockaddr_in address;
    char logged_in_user[50];
    char logged_in_role[10];
    char logged_in_channel[50];
    char logged_in_room[50];
} ClientInfo;

ClientInfo *clients[5];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void *handle_client(void *arg);

void register_user(const char *username, const char *password, ClientInfo *client);
void login_user(const char *username, const char *password, ClientInfo *client);

void create_directory(const char *path, ClientInfo *client);
void create_channel(const char *username, const char *channel, const char *key, ClientInfo *client);
void create_room(const char *username, const char *channel, const char *room, ClientInfo *client);
void list_channels(ClientInfo *client);
void list_rooms(const char *channel, ClientInfo *client);
void list_users(const char *channel, ClientInfo *client);
void join_channel(const char *username, const char *channel, ClientInfo *client);
void verify_key(const char *username, const char *channel, const char *key, ClientInfo *client);
void join_room(const char *channel, const char *room, ClientInfo *client);

void update_channel(const char *channel, ClientInfo *client);
void update_room(const char *channel, const char *room, const char *new_room, ClientInfo *client);

void delete_directory(const char *path);
void delete_channel(const char *channel, ClientInfo *client);
void delete_room(const char *channel, const char *room, ClientInfo *client);
void delete_all_rooms(const char *channel, ClientInfo *client);
void log_activity(const char *channel, const char *message);

void list_users_root(ClientInfo *client);

void handle_exit(ClientInfo *client);

void start_daemon() {
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

    if (chdir("/") < 0) {
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

void start_server() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failure");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, &addr_len);
        if (new_socket < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        pthread_t tid;
        ClientInfo *client = (ClientInfo *)malloc(sizeof(ClientInfo));
        client->socket = new_socket;
        client->address = address;
        memset(client->logged_in_user, 0, sizeof(client->logged_in_user));
        memset(client->logged_in_role, 0, sizeof(client->logged_in_role));
        memset(client->logged_in_channel, 0, sizeof(client->logged_in_channel));
        memset(client->logged_in_room, 0, sizeof(client->logged_in_room));

        pthread_create(&tid, NULL, handle_client, (void *)client);
    }
}

int main() {
    start_daemon();
    start_server();
    return 0;
}

// Command Handlers
void handle_register(ClientInfo *cli) {
    char *username = strtok(NULL, " ");
    char *password = strtok(NULL, " ");
    if (username && password) {
        register_user(username, password, cli);
    } else {
        const char *response = "Format perintah REGISTER tidak valid";
        write(cli->socket, response, strlen(response));
    }
}

void handle_login(ClientInfo *cli) {
    char *username = strtok(NULL, " ");
    char *password = strtok(NULL, " ");
    if (username && password) {
        login_user(username, password, cli);
    } else {
        const char *response = "Format perintah LOGIN tidak valid";
        write(cli->socket, response, strlen(response));
    }
}

void handle_create(ClientInfo *cli) {
    char *type = strtok(NULL, " ");
    if (strcmp(type, "CHANNEL") == 0) {
        char *channel = strtok(NULL, " ");
        char *key = strtok(NULL, " ");
        if (channel && key) {
            create_channel(cli->logged_in_user, channel, key, cli);
        } else {
            const char *response = "Penggunaan perintah: CREATE CHANNEL <channel> -k <key>";
            write(cli->socket, response, strlen(response));
        }
    } else if (strcmp(type, "ROOM") == 0) {
        char *room = strtok(NULL, " ");
        if (room) {
            create_room(cli->logged_in_user, cli->logged_in_channel, room, cli);
        } else {
            const char *response = "Penggunaan perintah: CREATE ROOM <room>";
            write(cli->socket, response, strlen(response));
        }
    } else {
        const char *response = "Format perintah CREATE tidak valid";
        write(cli->socket, response, strlen(response));
    }
}

void handle_list(ClientInfo *cli) {
    char *type = strtok(NULL, " ");
    if (strcmp(type, "CHANNEL") == 0) {
        list_channels(cli);
    } else if (strcmp(type, "ROOM") == 0) {
        list_rooms(cli->logged_in_channel, cli);
    } else if (strcmp(type, "USER") == 0) {
        if (strstr(cli->logged_in_role, "ROOT")) {
            list_users_root(cli);
        } else {
            list_users(cli->logged_in_channel, cli);
        }
    } else {
        const char *response = "Format perintah LIST tidak valid";
        write(cli->socket, response, strlen(response));
    }
}

void handle_delete(ClientInfo *cli) {
    printf("masuk handle_delete");
    char *type = strtok(NULL, " ");
    if (strcmp(type, "CHANNEL") == 0) {
        char *channel = strtok(NULL, " ");
        if (strlen(cli->logged_in_channel) > 0 || strlen(cli->logged_in_room) > 0) {
            const char *response = "Anda harus keluar dari channel";
            write(cli->socket, response, strlen(response));
        } else if (channel) {
            delete_channel(channel, cli);
        } else {
            const char *response = "Penggunaan perintah: DEL CHANNEL <channel>";
            write(cli->socket, response, strlen(response));
        }
    } else if (strcmp(type, "ROOM") == 0) {
        char *room = strtok(NULL, " ");
        if (strcmp(room, "ALL") == 0) {
            if (strlen(cli->logged_in_room) > 0 || strlen(cli->logged_in_channel) == 0) {
                const char *response = "You must leave the room or join a channel first";
                write(cli->socket, response, strlen(response));
            } else {
                delete_all_rooms(cli->logged_in_channel, cli);
            }
        } else {
            if (strlen(cli->logged_in_room) > 0 || strlen(cli->logged_in_channel) == 0) {
                const char *response = "You must leave the room or join a channel first";
                write(cli->socket, response, strlen(response));
            } else if (room) {
                delete_room(cli->logged_in_channel, room, cli);
            } else {
                const char *response = "Penggunaan perintah: DEL ROOM <room>";
                write(cli->socket, response, strlen(response));
            }
        }
    } else {
        const char *response = "Format perintah DEL tidak valid";
        write(cli->socket, response, strlen(response));
    }
}

// handle update for channel (EDIT CHANNEL <channel> TO <new_channel>)
void handle_update(ClientInfo *cli) {
    char *type = strtok(NULL, " ");
    if (strcmp(type, "CHANNEL") == 0) {
        char *channel = strtok(NULL, " ");
        if (channel) {
            update_channel(channel, cli);
        } else {
            const char *response = "Penggunaan perintah: EDIT CHANNEL <channel> TO <new_channel>";
            write(cli->socket, response, strlen(response));
        }
    } else if (strcmp(type, "ROOM") == 0) {
        char *room = strtok(NULL, " ");
        char *to = strtok(NULL, " ");
        char *new_room = strtok(NULL, " ");
        
        if (strlen(cli->logged_in_room) > 0 || strlen(cli->logged_in_channel) == 0) {
            const char *response = "You must leave the room or join a channel first";
            write(cli->socket, response, strlen(response));
        } else if (room && to && new_room && strcmp(to, "TO") == 0) {
            update_room(cli->logged_in_channel, room, new_room, cli);
        } else {
            const char *response = "Penggunaan perintah: EDIT ROOM <room> TO <new_room>";
            write(cli->socket, response, strlen(response));
        }
    } else {
        const char *response = "Format perintah EDIT tidak valid";
        write(cli->socket, response, strlen(response));
    }
}

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

// C (Create) directory
void create_directory(const char *path, ClientInfo *client) {
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

// User handlers
bool user_exists(const char *username) {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) return false;

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            fclose(file);
            return true;
        }
    }
    fclose(file);
    return false;
}

int get_user_count() {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) return 0;

    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        count++;
    }
    fclose(file);
    return count;
}

bool write_user_to_file(const char *username, const char *password, int user_count) {
    FILE *file = fopen(USERS_FILE, "a");
    if (!file) return false;

    char salt[BCRYPT_HASHSIZE];
    bcrypt_gensalt(12, salt);

    char hash[BCRYPT_HASHSIZE];
    bcrypt_hashpw(password, salt, hash);

    fprintf(file, "%d,%s,%s,%s\n", user_count + 1, username, hash, user_count == 0 ? "ROOT" : "USER");
    fclose(file);
    return true;
}

void send_response(ClientInfo *client, const char *message) {
    if (write(client->socket, message, strlen(message)) < 0) {
        perror("Unable to send response to client");
    }
}

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

// C (Create) Room & Channel handlers
bool channel_exists(const char *channel) {
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) return false;

    char line[256];
    while (fgets(line, sizeof(line), channels_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, channel) == 0) {
            fclose(channels_file);
            return true;
        }
    }
    fclose(channels_file);
    return false;
}

int get_next_channel_id() {
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) return 1;

    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), channels_file)) {
        count++;
    }
    fclose(channels_file);
    return count + 1;
}

void create_channel_directories(const char *channel, ClientInfo *client) {
    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    create_directory(path, client);

    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin", channel);
    create_directory(path, client);
}

void write_channel_to_file(const char *channel, const char *key, int channel_id) {
    FILE *channels_file = fopen(CHANNELS_FILE, "a");
    if (!channels_file) return;

    char salt[BCRYPT_HASHSIZE];
    bcrypt_gensalt(12, salt);

    char hash[BCRYPT_HASHSIZE];
    bcrypt_hashpw(key, salt, hash);

    fprintf(channels_file, "%d,%s,%s\n", channel_id, channel, hash);
    fclose(channels_file);
}

void add_user_to_auth(const char *channel, const char *username, ClientInfo *client) {
    char path[256];
    snprintf(path, sizeof(path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(path, "w+");
    if (!auth_file) return;

    char user_id[10];
    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) return;

    char user_line[256];
    while (fgets(user_line, sizeof(user_line), users_file)) {
        char *token = strtok(user_line, ",");
        strcpy(user_id, token);
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            fprintf(auth_file, "%s,%s,ADMIN\n", user_id, username);
            break;
        }
    }

    fclose(users_file);
    fclose(auth_file);
}

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

// L (List) handlers
char *read_file_lines(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) return NULL;

    char *content = malloc(10240);
    if (!content) {
        fclose(file);
        return NULL;
    }
    content[0] = '\0';

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        strncat(content, line, 10240 - strlen(content) - 1);
    }

    fclose(file);
    return content;
}

void list_directory(const char *path, const char *exclusions[], size_t num_exclusions, char *response, size_t response_size) {
    DIR *dir = opendir(path);
    if (!dir) {
        snprintf(response, response_size, "Unable to open directory: %s", path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        int exclude = 0;
        for (size_t i = 0; i < num_exclusions; i++) {
            if (strcmp(entry->d_name, exclusions[i]) == 0) {
                exclude = 1;
                break;
            }
        }
        if (!exclude) {
            strncat(response, entry->d_name, response_size - strlen(response) - 1);
            strncat(response, " ", response_size - strlen(response) - 1);
        }
    }

    closedir(dir);
}

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

// U (Update) handlers
// void update_channel(const char *channel, const char )
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
}

// J (Join) handlers
void verify_key(const char *username, const char *channel, const char *key, ClientInfo *client) {
    FILE *channels_file = fopen(CHANNELS_FILE, "r");
    if (!channels_file) {
        char response[] = "Unable to open channels.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
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
            
            if (token && strcmp(token, stored_hash) == 0){
                key_valid = true;
            }
            
            FILE *debug_file = fopen("/home/dim/uni/sisop/FP/awikwokzzzz.csv", "a");
    if (!debug_file) {
        perror("Unable to open debug_log.csv file");
    } else {
        fprintf(debug_file, "Key Valid: %d, eq: %d,Token: %s, stHash: %s, key:%s, res:%d\n", key_valid, strcmp(token, stored_hash), token, stored_hash, key, bcrypt_checkpw(key, stored_hash));
        fclose(debug_file);
    }
            break;
        }
    }

    fclose(channels_file);

    FILE *debug_file = fopen("/home/dim/uni/sisop/FP/awikwok2.csv", "a");
    if (!debug_file) {
        perror("Unable to open debug_log.csv file");
    } else {
        fprintf(debug_file, "Key Valid: %d", key_valid);
        fclose(debug_file);
    }

    if (key_valid) {
        FILE *users_file = fopen(USERS_FILE, "r");
        if (!users_file) {
            char response[] = "Unable to open users.csv file";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send response to client");
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
                char response[10240];
                snprintf(response, sizeof(response), "[%s/%s]", username, channel);
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Unable to send response to client");
                }
            } else {
                char response[] = "Unable to open auth.csv file";
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Unable to send response to client");
                }
            }
        } else {
            char response[] = "User tidak ditemukan";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Unable to send response to client");
            }
        }
    } else {
        FILE *debug_file2 = fopen("/home/dim/uni/sisop/FP/awikwok3.csv", "a");
    if (!debug_file2) {
        perror("Unable to open debug_log.csv file");
    } else {
        fprintf(debug_file2, "Key Valid: %d", key_valid);
        fclose(debug_file2);
    }
        char response[] = "Key salah";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
    }
}

void join_channel(const char *username, const char *channel, ClientInfo *client) {
    char channel_path[256];
    snprintf(channel_path, sizeof(channel_path), "/home/dim/uni/sisop/FP/DiscorIT/%s", channel);
    struct stat st;

    if (stat(channel_path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        char response[10240];
        snprintf(response, sizeof(response), "Channel %s tidak ada", channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return;
    }

    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) {
        char response[] = "Unable to open users.csv file";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return;
    }

    char line[256];
    bool is_root = false;
    char user_id[10];

    // Cek kalo usernya root
    while (fgets(line, sizeof(line), users_file)) {
        char *token = strtok(line, ",");
        strcpy(user_id, token);
        token = strtok(NULL, ",");
        char *name = token;
        if (token && strstr(name, username) != NULL) {
            token = strtok(NULL, ",");
            token = strtok(NULL, ",");
            char *role = token;
            if (strstr(role, "ROOT") != NULL) {
                is_root = true;
            }
            break;
        }
    }

    fclose(users_file);

    if (is_root) {
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
                perror("Unable to send response to client");
            }
            return;
        }

        char response[10240];
        snprintf(response, sizeof(response), "[%s/%s]", username, channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return;
    }

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

    bool is_admin = false;
    bool is_user = false;

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
            } else if (strstr(token, "USER") != NULL) {
                is_user = true;
                break;
            }
        }
    }

    fclose(auth_file);

    if (is_admin || is_user) {
        snprintf(client->logged_in_channel, sizeof(client->logged_in_channel), "%s", channel);
        char response[10240];
        snprintf(response, sizeof(response), "[%s/%s]", username, channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }
        return; // ADMIN or already registered USER joined without further checks
    } else {
        // If not ROOT, ADMIN, or already registered USER, prompt for key
        char response[] = "Key: ";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send response to client");
        }

        char key[10240];
        memset(key, 0, sizeof(key));

        if (recv(client->socket, key, sizeof(key), 0) < 0) {
            perror("Unable to receive key from client");
            return;
        }

        // Remove any trailing newline character from the key
        key[strcspn(key, "\n")] = 0;

        FILE *debug_file = fopen("/home/dim/uni/sisop/FP/awikwok.csv", "a");
    if (!debug_file) {
        perror("Unable to open debug_log.csv file");
    } else {
        fprintf(debug_file, "Username: %s, Channel: %s, Key: %s\n", username, channel, key);
        fclose(debug_file);
    }
        verify_key(username, channel, key, client);
    }
}

void join_room(const char *channel, const char *room, ClientInfo *client) {
    // Check if the room directory exists
    char room_path[256];
    snprintf(room_path, sizeof(room_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(room_path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        char response[10240];
        snprintf(response, sizeof(response), "Room %s tidak ada di channel %s", room, channel);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Unable to send responds to client");
        }
        return;
    }

    snprintf(client->logged_in_room, sizeof(client->logged_in_room), "%s", room);
    char response[10240];
    snprintf(response, sizeof(response), "[%s/%s/%s]", client->logged_in_user, channel, room);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Unable to send responds to client");
    }
}

// D (Delete) handlers
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

bool is_user_admin_or_root(const char *channel, ClientInfo *client) {
    FILE *users_file = fopen(USERS_FILE, "r");
    if (!users_file) {
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), users_file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, client->logged_in_user) == 0) {
            token = strtok(NULL, ",");
            token = strtok(NULL, ",");
            if (strstr(token, "ROOT") != NULL) {
                fclose(users_file);
                return true;
            }
            break;
        }
    }
    fclose(users_file);

    char auth_path[256];
    snprintf(auth_path, sizeof(auth_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/auth.csv", channel);
    FILE *auth_file = fopen(auth_path, "r");
    if (!auth_file) {
        return false;
    }

    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        if (strcmp(token, client->logged_in_user) == 0) {
            token = strtok(NULL, ",");
            if (strstr(token, "ADMIN") != NULL) {
                fclose(auth_file);
                return true;
            }
            break;
        }
    }
    fclose(auth_file);
    return false;
}

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

// Other handlers
// Helper function to get the current timestamp
void get_current_timestamp(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, buffer_size, "%d/%m/%Y %H:%M:%S", t);
}

void log_activity(const char *channel, const char *message) {
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/home/dim/uni/sisop/FP/DiscorIT/%s/admin/user.log", channel);

    FILE *log_file = fopen(log_path, "a+");
    if (!log_file) {
        perror("Unable to open user.log file");
        return;
    }

    char date[30];
    get_current_timestamp(date, sizeof(date));

    fprintf(log_file, "[%s] %s\n", date, message);
    fclose(log_file);
}

// Helper function to clear logged in information
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