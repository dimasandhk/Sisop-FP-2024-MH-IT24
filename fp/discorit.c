#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int server_fd;

void handle_error(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

void connect_to_server() {
    struct sockaddr_in serv_addr;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        handle_error("Socket creation error");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        handle_error("Invalid address/ Address not supported");
    }

    if (connect(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        handle_error("Connection Failed");
    }
}

void send_command(const char *command) {
    if (send(server_fd, command, strlen(command), 0) < 0) {
        handle_error("Failed to send command to server");
    }
}

void receive_response(char *response) {
    memset(response, 0, BUFFER_SIZE);
    if (recv(server_fd, response, BUFFER_SIZE - 1, 0) < 0) {
        handle_error("Failed to receive response from server");
    }
}

void handle_response(char *response, char *username, char *channel, char *room) {
    if (strstr(response, "Key:") != NULL) {
        char key[50];
        printf("Key: ");
        fgets(key, sizeof(key), stdin);
        key[strcspn(key, "\n")] = '\0';
        send_command(key);

        receive_response(response);
        if (strstr(response, "Key salah") != NULL) {
            if (strlen(room) > 0) room[0] = '\0';
            else if (strlen(channel) > 0) channel[0] = '\0';
        }
    } else if (strstr(response, "tidak ada") != NULL || strstr(response, "Key salah") != NULL || strstr(response, "Anda telah diban") != NULL) {
        if (strlen(room) > 0) room[0] = '\0';
        else if (strlen(channel) > 0) channel[0] = '\0';
        printf("%s\n", response);
    } else if (strstr(response, "Anda telah keluar dari aplikasi") != NULL) {
        close(server_fd);
        exit(0);
    } else {
        printf("%s\n", response);
    }
}

void process_commands(char *username, char *channel, char *room) {
    char command[BUFFER_SIZE];
    while (1) {
        if (strlen(room) > 0) {
            printf("[%s/%s/%s] ", username, channel, room);
        } else if (strlen(channel) > 0) {
            printf("[%s/%s] ", username, channel);
        } else {
            printf("[%s] ", username);
        }

        if (fgets(command, BUFFER_SIZE, stdin) == NULL) {
            printf("Failed to read command\n");
            continue;
        }
        command[strcspn(command, "\n")] = '\0';

        if (strncmp(command, "JOIN ", 5) == 0) {
            if (strlen(channel) == 0) {
                snprintf(channel, sizeof(channel), "%s", command + 5);
            } else {
                snprintf(room, sizeof(room), "%s", command + 5);
            }
        } else if (strcmp(command, "EXIT") == 0) {
            if (strlen(room) > 0) room[0] = '\0';
            else if (strlen(channel) > 0) channel[0] = '\0';
        } else if (strncmp(command, "EDIT PROFILE SELF -u ", 21) == 0) {
            snprintf(username, sizeof(username), "%s", command + 21);
        }

        send_command(command);

        char response[BUFFER_SIZE];
        receive_response(response);
        handle_response(response, username, channel, room);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s REGISTER/LOGIN username -p password\n", argv[0]);
        return 1;
    }

    connect_to_server();

    char command[BUFFER_SIZE];
    char username[50];
    char channel[50] = "";
    char room[50] = "";

    if (strcmp(argv[1], "REGISTER") == 0 && argc >= 5 && strcmp(argv[3], "-p") == 0) {
        snprintf(username, sizeof(username), "%s", argv[2]);
        snprintf(command, sizeof(command), "REGISTER %s %s", username, argv[4]);
    } else if (strcmp(argv[1], "LOGIN") == 0 && argc >= 5 && strcmp(argv[3], "-p") == 0) {
        snprintf(username, sizeof(username), "%s", argv[2]);
        snprintf(command, sizeof(command), "LOGIN %s %s", username, argv[4]);

        send_command(command);

        char response[BUFFER_SIZE];
        receive_response(response);
        printf("%s\n", response);

        if (strstr(response, "berhasil login") != NULL) {
            process_commands(username, channel, room);
        }
        close(server_fd);
        return 0;
    } else {
        printf("Invalid command\n");
        return 1;
    }

    send_command(command);

    char response[BUFFER_SIZE];
    receive_response(response);
    handle_response(response, username, channel, room);

    close(server_fd);
    return 0;
}