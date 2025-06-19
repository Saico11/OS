/*
 Mini Shell - Proyecto Final de Sistemas Operativos
 Autor: chorri
 Descripcion: Shell personalizada que ejecuta comandos simples y encadenados,
              gestiona procesos, hilos, semaforos, sincronizacion, memoria compartida,
              sistema de archivos virtual en memoria, chatbox de soporte, quiz, tic-tac-toe y history.
*/

#include <stdio.h>        // Entrada/salida estandar
#include <stdlib.h>       // malloc, free, exit
#include <string.h>       // strtok, strcmp, strcpy
#include <unistd.h>       // fork, execvp, pipe, dup2, access, system
#include <sys/wait.h>     // waitpid
#include <pthread.h>      // pthread_create, pthread_join, pthread_mutex
#include <semaphore.h>    // sem_init, sem_wait, sem_post
#include <fcntl.h>        // O_CREAT, O_RDWR
#include <sys/mman.h>     // shm_open, mmap, munmap, shm_unlink
#include <sys/stat.h>     // ftruncate, mode_t
#include <ctype.h>        // isspace
#include <termios.h>      // getpass

#define MAX_CMD_LEN 1024  // Maximo de caracteres de un comando
#define MAX_ARGS 64       // Maximo de argumentos por comando
#define MAX_FILES 100     // Maximo de archivos en VFS
#define MAX_NAME_LEN 64   // Maximo de longitud de nombre en VFS
#define MAX_HISTORY 1000  // Maximo de comandos en history
#define SHM_NAME "/shm_shell" // Nombre de memoria compartida

// Estructura para archivos virtuales
typedef struct {
    char name[MAX_NAME_LEN]; // Nombre del archivo
    char *data;              // Puntero a datos del archivo
    size_t size;             // Tamano de datos
    mode_t perm;             // Permisos de archivo
} VFS_File;

// VFS global con mutex
typedef struct {
    VFS_File files[MAX_FILES];
    int count;
    pthread_mutex_t mutex;
} VirtualFS;

VirtualFS vfs;               // Sistema de archivos virtual
sem_t cmd_sem;               // Semaforo para contador de comandos
pthread_mutex_t print_mutex; // Mutex para impresion ordenada
int shm_fd;                  // Descriptor de memoria compartida
char *shm_ptr;               // Puntero a memoria compartida
pthread_t monitor_tid;       // Hilo de monitoreo

// Historial de comandos
char history[MAX_HISTORY][MAX_CMD_LEN];
int history_count = 0;

// FUNCION: recorta espacios en inicio y fin de cadena
char* trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) e--;
    *(e + 1) = '\0';
    return s;
}

// FUNCION: valida caracteres peligrosos en comando
int validate_command(const char *c) {
    if (strstr(c, ";") || strstr(c, "&&") || strstr(c, "||") || strstr(c, "`")) {
        printf("[Error] Caracter ilegal en comando\n");
        return 0;
    }
    return 1;
}

// FUNCION: login simulado (admin/password)
void login() {
    char *u = malloc(32);
    printf("Usuario: ");
    if (!fgets(u, 32, stdin)) exit(EXIT_FAILURE);
    u[strcspn(u, "\n")] = '\0';
    char *p = getpass("Password: ");
    if (strcmp(u, "admin") != 0 || strcmp(p, "password") != 0) {
        printf("Acceso denegado\n");
        free(u);
        exit(EXIT_FAILURE);
    }
    free(u);
}

// FUNCION: inicializa VFS
void vfs_init() {
    vfs.count = 0;
    pthread_mutex_init(&vfs.mutex, NULL);
}

// FUNCION: crea archivo en VFS
void vfs_create(const char *n) {
    pthread_mutex_lock(&vfs.mutex);
    if (vfs.count >= MAX_FILES) {
        printf("[VFS] Limite alcanzado\n");
    } else {
        strncpy(vfs.files[vfs.count].name, n, MAX_NAME_LEN - 1);
        vfs.files[vfs.count].name[MAX_NAME_LEN - 1] = '\0';
        vfs.files[vfs.count].data = NULL;
        vfs.files[vfs.count].size = 0;
        vfs.files[vfs.count].perm = S_IRUSR | S_IWUSR;
        vfs.count++;
        printf("[VFS] Archivo '%s' creado\n", n);
    }
    pthread_mutex_unlock(&vfs.mutex);
}

// FUNCION: lista archivos en VFS
void vfs_list() {
    pthread_mutex_lock(&vfs.mutex);
    printf("[VFS] Archivos en memoria:\n");
    for (int i = 0; i < vfs.count; i++) {
        printf(" - %s (size=%zu)\n", vfs.files[i].name, vfs.files[i].size);
    }
    pthread_mutex_unlock(&vfs.mutex);
}

// FUNCION: escribe texto en archivo VFS
void vfs_write(const char *n, const char *t) {
    pthread_mutex_lock(&vfs.mutex);
    for (int i = 0; i < vfs.count; i++) {
        if (strcmp(vfs.files[i].name, n) == 0) {
            if (!(vfs.files[i].perm & S_IWUSR)) {
                printf("[VFS] Sin permiso escritura\n");
            } else {
                free(vfs.files[i].data);
                vfs.files[i].size = strlen(t);
                vfs.files[i].data = malloc(vfs.files[i].size + 1);
                strcpy(vfs.files[i].data, t);
                printf("[VFS] Escrito en '%s'\n", n);
            }
            pthread_mutex_unlock(&vfs.mutex);
            return;
        }
    }
    printf("[VFS] '%s' no existe\n", n);
    pthread_mutex_unlock(&vfs.mutex);
}

// FUNCION: lee archivo de VFS
void vfs_read(const char *n) {
    pthread_mutex_lock(&vfs.mutex);
    for (int i = 0; i < vfs.count; i++) {
        if (strcmp(vfs.files[i].name, n) == 0) {
            if (!(vfs.files[i].perm & S_IRUSR)) {
                printf("[VFS] Sin permiso lectura\n");
            } else if (vfs.files[i].data) {
                printf("[VFS] %s\n", vfs.files[i].data);
            } else {
                printf("[VFS] Archivo vacio\n");
            }
            pthread_mutex_unlock(&vfs.mutex);
            return;
        }
    }
    printf("[VFS] '%s' no existe\n", n);
    pthread_mutex_unlock(&vfs.mutex);
}

// FUNCION: elimina archivo de VFS
void vfs_delete(const char *n) {
    pthread_mutex_lock(&vfs.mutex);
    for (int i = 0; i < vfs.count; i++) {
        if (strcmp(vfs.files[i].name, n) == 0) {
            free(vfs.files[i].data);
            for (int j = i; j < vfs.count - 1; j++)
                vfs.files[j] = vfs.files[j + 1];
            vfs.count--;
            printf("[VFS] '%s' eliminado\n", n);
            pthread_mutex_unlock(&vfs.mutex);
            return;
        }
    }
    printf("[VFS] '%s' no existe\n", n);
    pthread_mutex_unlock(&vfs.mutex);
}

// FUNCION: abre navegador web en URL
void open_browser(const char *url) {
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, MAX_CMD_LEN, "xdg-open %s &", url);
    system(cmd);
}

// FUNCION: Tic-Tac-Toe simple
void tic_tac_toe() {
    char b[9] = {'1','2','3','4','5','6','7','8','9'};
    int p = 0, mv;
    for (int i = 0; i < 9; i++) {
        printf("Jugador %d, casilla: ", p + 1);
        if (scanf("%d", &mv) != 1) break;
        getchar();
        if (mv < 1 || mv > 9 || b[mv-1] == 'X' || b[mv-1] == 'O') {
            printf("Invalid\n");
            i--; continue;
        }
        b[mv-1] = (p % 2 == 0) ? 'X' : 'O';
        p++;
        printf("%c|%c|%c\n-+-+-\n%c|%c|%c\n-+-+-\n%c|%c|%c\n",
            b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8]);
    }
    printf("Fin Tic-Tac-Toe\n");
}

// FUNCION: quiz basico
void quiz() {
    char r[8];
    printf("[Quiz] Cuanto es 2 + 2? ");
    fgets(r, sizeof(r), stdin);
    if (atoi(r) == 4) printf("Correcto!\n");
    else printf("Incorrecto\n");
}

// FUNCION: muestra historico de comandos
void show_history() {
    for (int i = 0; i < history_count; i++)
        printf("%4d  %s\n", i + 1, history[i]);
}

// FUNCION: ejecuta comando
void execute_command(char *in, int bg) {
    if (!validate_command(in)) return;
    char *args[MAX_ARGS]; int ac=0;
    args[ac] = strtok(in, " ");
    while (args[ac] && ac < MAX_ARGS-1)
        args[++ac] = strtok(NULL, " ");
    args[ac] = NULL;
    sem_wait(&cmd_sem);
    int c = atoi(shm_ptr) + 1; sprintf(shm_ptr, "%d", c);
    sem_post(&cmd_sem);
    pid_t pid = fork();
    if (pid == 0) {
        execvp(args[0], args);
        perror("execvp");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        if (!bg) waitpid(pid, NULL, 0);
    } else perror("fork");
}

// FUNCION: ejecuta pipe
void execute_pipe(char *c1, char *c2) {
    int fd[2]; pipe(fd);
    if (fork() == 0) {
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]); close(fd[1]);
        execute_command(c1, 0);
        exit(EXIT_FAILURE);
    }
    if (fork() == 0) {
        dup2(fd[0], STDIN_FILENO);
        close(fd[1]); close(fd[0]);
        execute_command(c2, 0);
        exit(EXIT_FAILURE);
    }
    close(fd[0]); close(fd[1]);
    wait(NULL); wait(NULL);
}

// FUNCION: hilo monitor cada 20 segundos
void* monitor_thread(void* arg) {
    (void)arg;
    while (1) {
        sleep(20);
        pthread_mutex_lock(&print_mutex);
        sem_wait(&cmd_sem);
        printf("[Monitor] Comandos ejecutados: %s\n", shm_ptr);
        sem_post(&cmd_sem);
        pthread_mutex_unlock(&print_mutex);
    }
    return NULL;
}

// FUNCION: chatbox de soporte
void chatbox() {
    char m[MAX_CMD_LEN];
    printf("[Chat] Soporte: escribe 'exit'\n");
    while (1) {
        printf("Soporte> ");
        if (!fgets(m, sizeof(m), stdin)) break;
        m[strcspn(m, "\n")] = '\0';
        if (strcmp(m, "exit") == 0) break;
        printf("[Soporte] %s\n", m);
    }
}

// FUNCION: libera recursos
void cleanup() {
    pthread_cancel(monitor_tid);
    pthread_join(monitor_tid, NULL);
    for (int i = 0; i < vfs.count; i++) free(vfs.files[i].data);
    munmap(shm_ptr, MAX_CMD_LEN);
    shm_unlink(SHM_NAME);
    sem_destroy(&cmd_sem);
    pthread_mutex_destroy(&print_mutex);
    pthread_mutex_destroy(&vfs.mutex);
}

// FUNCION PRINCIPAL
int main() {
    login();
    vfs_init();
    pthread_mutex_init(&print_mutex, NULL);
    sem_init(&cmd_sem, 0, 1);

    // Inicializa memoria compartida
    shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    ftruncate(shm_fd, MAX_CMD_LEN);
    shm_ptr = mmap(NULL, MAX_CMD_LEN, PROT_READ | PROT_WRITE,
                   MAP_SHARED, shm_fd, 0);
    strcpy(shm_ptr, "0");

    // Arranca hilo de monitoreo
    pthread_create(&monitor_tid, NULL, monitor_thread, NULL);

    char in[MAX_CMD_LEN];
    while (1) {
        printf("MiniShell> ");
        if (!fgets(in, sizeof(in), stdin)) break;
        in[strcspn(in, "\n")] = '\0';
        char *cmd = trim(in);
        if (*cmd == '\0') continue;
        if (history_count < MAX_HISTORY)
            strcpy(history[history_count++], cmd);
        if (strcmp(cmd, "exit") == 0) break;

        // VFS commands
        if (!strncmp(cmd, "fs_create ", 10)) { vfs_create(cmd+10); continue; }
        if (!strcmp(cmd, "fs_list")) { vfs_list(); continue; }
        if (!strncmp(cmd, "fs_write ", 9)) {
            char *n = strtok(cmd+9, " ");
            char *t = strtok(NULL, "");
            vfs_write(n, t);
            continue;
        }
        if (!strncmp(cmd, "fs_read ", 8)) { vfs_read(cmd+8); continue; }
        if (!strncmp(cmd, "fs_delete ", 10)) { vfs_delete(cmd+10); continue; }

        // Funcionalidades adicionales
        if (!strcmp(cmd, "chat")) { chatbox(); continue; }
        if (!strcmp(cmd, "quiz")) { quiz(); continue; }
        if (!strcmp(cmd, "juego") || !strcmp(cmd, "tictactoe")) { tic_tac_toe(); continue; }
        if (!strcmp(cmd, "history")) { show_history(); continue; }
        if (!strcmp(cmd, "google")) { open_browser("https://www.google.com"); continue; }
        if (!strcmp(cmd, "firefox")) { system("firefox &"); continue; }

        // Pipes vs comando simple
        char *p = strchr(cmd, '|');
        if (p) {
            *p = '\0';
            execute_pipe(trim(cmd), trim(p+1));
        } else {
            int bg = (cmd[strlen(cmd)-1] == '&');
            if (bg) cmd[strlen(cmd)-1] = '\0';
            execute_command(trim(cmd), bg);
        }
    }

    cleanup();
    return 0;
}

