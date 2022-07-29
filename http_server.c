#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_D                     \
    ""                                                    \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/html" CRLF "Connection: Keep-Alive" CRLF CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMM                  \
    ""                                                    \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Connection: Keep-Alive" CRLF CRLF
#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 1024

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    char request_data[4096];
    struct dir_context dir_context;
    int complete;
};
struct http_service daemon = {.is_stopped = false};
extern struct workqueue_struct *khttpd_wq;

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static int tracedir(struct dir_context *dir_context,
                    const char *name,
                    int namelen,
                    loff_t offset,
                    u64 ino,
                    unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        char msg[256];
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        snprintf(msg, 256, "<li><a href=\"%s\">%s</a></li>\r\n", name, name);
        http_server_send(request->socket, msg, strlen(msg));
    }
    return 0;
}

static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    request->dir_context.actor = tracedir;

    fp = filp_open("/home/qwe661234/jservHW/NetWork/khttpd/resources/",
                   O_RDONLY | O_DIRECTORY, 0);

    if (IS_ERR(fp)) {
        pr_info("Open file failed");
        return false;
    }

    iterate_dir(fp, &request->dir_context);
    filp_close(fp, NULL);
    return true;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    char *response;
    char msg[1024],
        root[1024] = "/home/qwe661234/jservHW/NetWork/khttpd/resources";
    struct file *fp;
    int len;
    pr_info("requested_url = %s\n", request->request_url);
    if (request->method == HTTP_POST) {
        strcat(root, request->request_url);
        if ((fp = filp_open(root, O_RDWR | O_CREAT, 0777)) < 0)
            printk("open fail");
        kernel_write(fp, request->request_data, strlen(request->request_data),
                     &fp->f_pos);
        http_server_send(request->socket, "OK!", 4);
        filp_close(fp, NULL);
    } else if (request->method == HTTP_GET) {
        if (strcmp(request->request_url, "/") == 0 ||
            strcmp(request->request_url, "/index.html") == 0) {
            response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_D
                                  : HTTP_RESPONSE_200_DUMMY;
            http_server_send(request->socket, response, strlen(response));
            snprintf(
                msg, 1024, "%s%s",
                "<html><head><title>Web File Dorectory List</title></head>\r\n",
                "<body><h1>File List</h1><ul>\r\n");
            http_server_send(request->socket, msg, strlen(msg));
            handle_directory(request);
            snprintf(msg, 1024, "%s", "</ul></body></html>\r\n");
            http_server_send(request->socket, msg, strlen(msg));
        } else {
            response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_DUMM
                                  : HTTP_RESPONSE_200_DUMMY;
            http_server_send(request->socket, response, strlen(response));
            strcat(root, request->request_url);
            if ((fp = filp_open(root, O_RDONLY, 0)) < 0)
                printk("open fail");
            if (fp) {
                while ((len = kernel_read(fp, msg, 1023, &fp->f_pos)) > 0) {
                    http_server_send(request->socket, msg, len);
                }
            }

            filp_close(fp, NULL);
        }
    } else {
        response = keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501;
        http_server_send(request->socket, response, strlen(response));
    }
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    struct http_request *request = parser->data;
    strncpy(request->request_data, p, len);
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void http_server_worker(struct work_struct *work)
{
    struct khttpd *worker = container_of(work, struct khttpd, khttpd_work);
    char *buf;
    // parse request and response
    struct http_parser parser;
    /* parse packet */
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) worker->sock;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (!kthread_should_stop()) {
        memset(buf, 0, RECV_BUFFER_SIZE);
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        } else {
            printk("recv\n");
            printk("%s\n", buf);
        }
        // prase request
        http_parser_execute(&parser, &setting, buf, ret);
        // if (request.complete && !http_should_keep_alive(&parser))
        //     break;
        if (request.complete)
            break;
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
}

static struct work_struct *create_work(struct socket *sk)
{
    struct khttpd *work;

    if (!(work = kmalloc(sizeof(struct khttpd), GFP_KERNEL)))
        return NULL;

    work->sock = sk;

    INIT_WORK(&work->khttpd_work, http_server_worker);

    list_add(&work->list, &daemon.worker);

    return &work->khttpd_work;
}

static void free_work(void)
{
    struct khttpd *l, *tar;
    /* cppcheck-suppress uninitvar */

    list_for_each_entry_safe (tar, l, &daemon.worker, list) {
        kernel_sock_shutdown(tar->sock, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->sock);
        kfree(tar);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct work_struct *work;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon.worker);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        if (unlikely(!(work = create_work(socket)))) {
            printk(KERN_ERR KBUILD_MODNAME
                   ": create work error, connection closed\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        /* start server worker */
        queue_work(khttpd_wq, work);
    }

    printk(KBUILD_MODNAME ": daemon shutdown in progress...\n");

    daemon.is_stopped = true;
    free_work();
    return 0;
}
