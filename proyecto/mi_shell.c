#define _GNU_SOURCE

#include <stdio.h>                  // io básica: printf, fgets
#include <stdlib.h>                 // malloc, free, exit
#include <string.h>                 // strtok, strcmp, strcpy
#include <unistd.h>                 // fork, execvp, chdir, pipe, dup2, getcwd
#include <sys/types.h>              // tipos de datos de system V
#include <sys/wait.h>               // waitpid
#include <pthread.h>                // pthread_create, pthread_join, mutex
#include <semaphore.h>              // sem_t, sem_init, sem_wait, sem_post
#include <sys/ipc.h>                // ftok
#include <sys/shm.h>                // shmget, shmat, shmdt, shmctl
#include <fcntl.h>                  // O_CREAT, O_RDWR
#include <termios.h>                // getpass para ocultar entrada
#include <sys/stat.h>               // permisos de archivos

#define MAX_CMD_LEN 1024            // longitud máxima de entrada
#define MAX_ARGS 100                // máximo de argumentos por comando
#define VFS_MAX_FILES 100           // número máximo de archivos en VFS
#define VFS_MAX_NAME_LEN 64         // longitud máxima de nombre de archivo
#define VFS_MAX_DATA 4096           // tamaño máximo de datos por archivo

// Estructura de archivo para el sistema de archivos virtual en memoria
typedef struct {
    char name[VFS_MAX_NAME_LEN];   // nombre del archivo
    char *data;                    // puntero a datos dinámicos
    int size;                      // tamaño de datos
    mode_t perm;                   // permisos de archivo (lectura/escritura)
} VFS_File;

VFS_File vfs[VFS_MAX_FILES];       // array estático de archivos
int vfs_file_count = 0;            // contador de archivos en VFS
pthread_mutex_t vfs_mutex;         // mutex para proteger VFS

sem_t shm_sem;                     // semáforo para proteger memoria compartida
int *cmd_count_shm;                // contador de comandos en memoria compartida

// Inicializa el sistema de archivos virtual
void init_vfs() {
    pthread_mutex_init(&vfs_mutex, NULL); // crea mutex sin atributos especiales
}

// Crea un archivo vacío en VFS
void vfs_create(const char *name) {
    pthread_mutex_lock(&vfs_mutex);       // sección crítica
    if (vfs_file_count >= VFS_MAX_FILES) {
        printf("VFS lleno\n");            // límite alcanzado
    } else {
        VFS_File *f = &vfs[vfs_file_count++]; // obtiene nueva entrada
        strncpy(f->name, name, VFS_MAX_NAME_LEN-1); // copia nombre
        f->name[VFS_MAX_NAME_LEN-1] = '\0'; // asegura null terminator
        f->data = NULL;                   // sin datos aún
        f->size = 0;                      // tamaño cero
        f->perm = S_IRUSR | S_IWUSR;      // permiso lectura/escritura
        printf("Archivo '%s' creado en VFS\n", name); // confirmación
    }
    pthread_mutex_unlock(&vfs_mutex);     // sale de sección crítica
}

// Lista los archivos en VFS
void vfs_ls() {
    pthread_mutex_lock(&vfs_mutex);       // sección crítica
    printf("Archivos en VFS:\n");         // encabezado
    for (int i = 0; i < vfs_file_count; i++) {
        printf("  %s (size=%d)\n", vfs[i].name, vfs[i].size); // lista cada uno
    }
    pthread_mutex_unlock(&vfs_mutex);     // fin sección crítica
}

// Escribe datos en un archivo VFS
void vfs_write(const char *name, const char *text) {
    pthread_mutex_lock(&vfs_mutex);       // sección crítica
    for (int i = 0; i < vfs_file_count; i++) {
        if (strcmp(vfs[i].name, name) == 0) { // busca archivo
            free(vfs[i].data);            // libera datos previos
            vfs[i].size = strlen(text);  // actualiza tamaño
            vfs[i].data = malloc(vfs[i].size + 1); // reserva memoria
            strcpy(vfs[i].data, text);   // copia texto
            printf("Escrito en '%s': %s\n", name, text); // confirmación
            pthread_mutex_unlock(&vfs_mutex); // libera mutex
            return;
        }
    }
    printf("Archivo '%s' no encontrado\n", name); // no existe
    pthread_mutex_unlock(&vfs_mutex);     // libera mutex
}

// Lee datos de un archivo VFS
void vfs_read(const char *name) {
    pthread_mutex_lock(&vfs_mutex);       // sección crítica
    for (int i = 0; i < vfs_file_count; i++) {
        if (strcmp(vfs[i].name, name) == 0) { // busca archivo
            if (vfs[i].data) {
                printf("Contenido de '%s': %s\n", name, vfs[i].data); // muestra datos
            } else {
                printf("'%s' está vacío\n", name); // sin datos aún
            }
            pthread_mutex_unlock(&vfs_mutex); // libera mutex
            return;
        }
    }
    printf("Archivo '%s' no encontrado\n", name); // no existe
    pthread_mutex_unlock(&vfs_mutex);     // libera mutex
}

// Elimina un archivo de VFS
void vfs_rm(const char *name) {
    pthread_mutex_lock(&vfs_mutex);       // sección crítica
    for (int i = 0; i < vfs_file_count; i++) {
        if (strcmp(vfs[i].name, name) == 0) { // busca archivo
            free(vfs[i].data);            // libera datos
            // desplaza archivos posteriores
            for (int j = i; j < vfs_file_count - 1; j++) {
                vfs[j] = vfs[j+1];
            }
            vfs_file_count--;             // decrementa contador
            printf("Archivo '%s' eliminado\n", name); // confirmación
            pthread_mutex_unlock(&vfs_mutex); // libera mutex
            return;
        }
    }
    printf("Archivo '%s' no encontrado\n", name); // no existe
    pthread_mutex_unlock(&vfs_mutex);     // libera mutex
}

// Juego de Tic-Tac-Toe para funcionalidad adicional
void play_tic_tac_toe() {
    char board[9] = {'1','2','3','4','5','6','7','8','9'}; // tablero inicial
    int player = 0, move, i;
    char mark;
    for (i = 0; i < 9; i++) {
        mark = (player % 2 == 0) ? 'X' : 'O'; // determina marca
        printf("Jugador %d, ingresa casilla: ", player+1); // pide movimiento
        scanf("%d", &move);             // lee movimiento
        if (move < 1 || move > 9 || board[move-1] == 'X' || board[move-1] == 'O') {
            printf("Movimiento inválido\n"); // validación simple
            i--; continue;                // repite turno
        }
        board[move-1] = mark;           // actualiza tablero
        // imprime tablero
        printf("%c|%c|%c\n", board[0],board[1],board[2]);
        printf("-+-+-\n");
        printf("%c|%c|%c\n", board[3],board[4],board[5]);
        printf("-+-+-\n");
        printf("%c|%c|%c\n", board[6],board[7],board[8]);
        // chequea victoria simplificada
        int wins[8][3] = {{0,1,2},{3,4,5},{6,7,8},{0,3,6},{1,4,7},{2,5,8},{0,4,8},{2,4,6}};
        for (int w = 0; w < 8; w++) {
            if (board[wins[w][0]]==mark && board[wins[w][1]]==mark && board[wins[w][2]]==mark) {
                printf("Jugador %d gana!\n", player+1); return; // fin juego
            }
        }
        player++;                        // siguiente turno
    }
    printf("Empate!\n");                 // si completó 9 sin ganador
}

// Simula acceso a navegador web para funcionalidad adicional
void open_browser(const char *url) {
    char cmd[MAX_CMD_LEN];              // buffer para comando
    snprintf(cmd, sizeof(cmd), "xdg-open %s &", url); // construye comando
    system(cmd);                        // lo ejecuta
}

// Valida que el comando no contenga caracteres maliciosos
int validate_command(const char *cmd) {
    if (strstr(cmd, ";") || strstr(cmd, "`") || strstr(cmd, "&&") || strstr(cmd, "||")) {
        printf("Carácter ilegal en comando\n"); // evita código encadenado
        return 0;
    }
    return 1;                            // comando válido
}

// Lógica de login simulado con usuario y contraseña fijo
void login() {
    char *user;                          // puntero a usuario
    char *pwd;                           // puntero a contraseña
    struct termios oldt, newt;          // para ocultar input
    printf("Usuario: ");                 // pide usuario
    user = malloc(64);                   // reserva espacio
    fgets(user, 64, stdin);              // lee usuario
    user[strcspn(user, "\n")] = '\0';    // quita newline
    printf("Contraseña: ");              // pide contraseña
    tcgetattr(STDIN_FILENO, &oldt);      // guarda estado terminal
    newt = oldt; newt.c_lflag &= ~ECHO;  // deshabilita echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    pwd = getpass("");                   // lee contraseña oculta
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restaura terminal
    if (strcmp(user, "admin") != 0 || strcmp(pwd, "password") != 0) {
        printf("Login fallido\n");       // credenciales inválidas
        exit(1);                         // termina shell
    }
    printf("\nBienvenido, %s\n", user);  // login exitoso
    free(user);                          // libera memoria
}

// Hilo que monitorea contador de comandos en shm
void *monitor_thread(void *arg) {
    (void)arg;  // silencia warning: “argument ‘arg’ no se usa”
    while (1) {
        sleep(60);                       // cada 60 segundos
        sem_wait(&shm_sem);             // espera semáforo
        printf("[Monitor] Comandos ejecutados: %d\n", *cmd_count_shm); // informa
        sem_post(&shm_sem);             // libera semáforo
    }
    return NULL;
}

// Ejecuta comando sin pipes ni redirecciones
void run_simple(char **args, int background) {
    pid_t pid = fork();                 // crea proceso hijo
    if (pid < 0) {
        perror("fork error"); exit(1);  // error en fork
    } else if (pid == 0) {
        if (execvp(args[0], args) < 0) { // reemplaza imagen
            perror("exec error"); exit(1);
        }
    } else {
        if (!background) {              // si no es background
            waitpid(pid, NULL, 0);      // espera a hijo
        }
    }
}

// Maneja pipes entre dos comandos
void run_pipe(char **left_args, char **right_args) {
    int fd[2];                          // descriptores de pipe
    pipe(fd);                           // crea pipe
    if (fork() == 0) {                  // primer hijo
        dup2(fd[1], STDOUT_FILENO);     // redirige salida a pipe
        close(fd[0]); close(fd[1]);
        execvp(left_args[0], left_args);// ejecuta comando izquierdo
        perror("exec izquierda"); exit(1);
    }
    if (fork() == 0) {                  // segundo hijo
        dup2(fd[0], STDIN_FILENO);      // redirige entrada desde pipe
        close(fd[0]); close(fd[1]);
        execvp(right_args[0], right_args);// ejecuta comando derecho
        perror("exec derecha"); exit(1);
    }
    close(fd[0]); close(fd[1]);
    wait(NULL); wait(NULL);             // espera a ambos hijos
}

// Función principal
int main() {
    char line[MAX_CMD_LEN];             // buffer de línea
    char *args[MAX_ARGS];               // vector de argumentos
    key_t key;                          // clave para shm
    int shmid;                          // id del segmento
    pthread_t mon_thread;               // identificador de hilo

    login();                            // solicita login antes de shell

    // configura memoria compartida para contador de comandos
    key = ftok("/tmp", 'R');            // genera clave
    shmid = shmget(key, sizeof(int), IPC_CREAT | 0666); // crea shm
    cmd_count_shm = (int*)shmat(shmid, NULL, 0); // mapea shm
    *cmd_count_shm = 0;                 // inicializa contador

    sem_init(&shm_sem, 0, 1);           // crea semáforo con valor 1

    pthread_create(&mon_thread, NULL, monitor_thread, NULL); // lanza monitor

    init_vfs();                         // inicia VFS

    while (1) {
        printf("mi-shell> ");           // prompt personalizado
        if (!fgets(line, sizeof(line), stdin)) break; // fin de input
        if (line[0] == '\n') continue; // ignora líneas vacías
        line[strcspn(line, "\n")] = 0;  // quita newline

        if (!validate_command(line)) continue; // valida seguridad

        // parsea argumentos y detecta background
        int background = 0, argc = 0;
        char *token = strtok(line, " ");
        while (token && argc < MAX_ARGS-1) {
            args[argc++] = token;
            token = strtok(NULL, " ");
        }
        args[argc] = NULL;              // cierra lista de args
        if (argc>0 && strcmp(args[argc-1], "&")==0) {
            background = 1; args[--argc] = NULL; // marca & y quita
        }

        // comandos built-in de VFS y extras
        if (argc > 0) {
            if (strcmp(args[0], "vfs_ls")==0) { vfs_ls(); continue; }
            if (strcmp(args[0], "vfs_create")==0 && argc==2) { vfs_create(args[1]); continue; }
            if (strcmp(args[0], "vfs_write")==0 && argc==3) { vfs_write(args[1], args[2]); continue; }
            if (strcmp(args[0], "vfs_read")==0 && argc==2) { vfs_read(args[1]); continue; }
            if (strcmp(args[0], "vfs_rm")==0 && argc==2) { vfs_rm(args[1]); continue; }
            if (strcmp(args[0], "tictactoe")==0) { play_tic_tac_toe(); continue; }
            if (strcmp(args[0], "web")==0 && argc==2) { open_browser(args[1]); continue; }
        }

        // agrega contador de comandos protegido por semáforo
        sem_wait(&shm_sem);
        (*cmd_count_shm)++;
        sem_post(&shm_sem);

        // maneja pipes simple de un solo '|'
        char *pipe_pos = NULL;
        for (int i = 0; i < argc; i++) if (strcmp(args[i], "|")==0) pipe_pos = args[i];
        if (pipe_pos) {
            // separa en dos vectores
            char *left_args[MAX_ARGS], *right_args[MAX_ARGS];
            int li=0, ri=0, side=0;
            for (int i=0; i<argc; i++) {
                if (!side && strcmp(args[i],"|")==0) { side=1; continue; }
                if (!side) left_args[li++]=args[i]; else right_args[ri++]=args[i];
            }
            left_args[li]=right_args[ri]=NULL;
            run_pipe(left_args, right_args); continue;
        }

        // ejecución normal
        run_simple(args, background);
    }

    // limpieza al salir
    pthread_cancel(mon_thread);         // detiene hilo monitor
    pthread_join(mon_thread, NULL);     // espera su fin
    sem_destroy(&shm_sem);              // destruye semáforo
    pthread_mutex_destroy(&vfs_mutex);  // destruye mutex VFS
    shmdt(cmd_count_shm);               // desmapea memoria compartida
    shmctl(shmid, IPC_RMID, NULL);      // elimina segmento shm
    return 0;                           // termina programa
}

