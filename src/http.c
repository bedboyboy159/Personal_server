/*  
Project 4 - ANSHGWASH and LONGH220

    Describe: This project focused on implementing a personal web server that support login, sign out, 
    user authentication, mp4 streaming, html5 fallback and Ipv6 support. It allow multiple users sign in at the
    same time. Verifying the user to see private files and support fallback when entered the wrong URL.

    Implementation:
    We implemeted(edit) the function handle_api to handle post and get request, later we also added in
    a part to handle video streaming.
    We also added a part to check for whether user is allowed to access the private authentication based
    on their cookie once they signed in.
    We also implemented html5 fallback in handle_Static_asset when the user entered wrong URL
    We also implemented IPV6 support in the socket.c by creating another for loop for it.
    We also implemented multi threading to support multiple user at once in main.c

    Lastly, for the authentication and edge cases to work, we had to work with the test cases to fix 
    edge cases so that our program would fully functional and pass every single test case.

*/
/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <jwt.h>
#include <dirent.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

#include <jansson.h>

static const char *NEVER_EMBED_A_SECRET_IN_CODE = "supa secret";

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2) // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len - 2] = '\0'; // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL) // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;
    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;)
    {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;
        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF)) // empty CRLF
            return true;

        header[len - 2] = '\0';
        /* Each header field consists of a name followed by a
         * colon (":") and the field value. Field names are
         * case-insensitive. The field value MAY be preceded by
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        // printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length"))
        {
            ta->req_content_len = atoi(field_value);
        }

        if (!strcasecmp(field_name, "Range"))
        {
            snprintf(ta->range_str, 100, "%s", field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */

        // sets cookie
        if (!strcasecmp(field_name, "Cookie"))
        {
            char *rhs;
            char *lhs = strtok_r(field_value, ";", &rhs);
            while (lhs)
            {
                if (strstr(lhs, "auth_token") != NULL)
                {
                    char *in_rhs;
                    // char *in_lhs = strtok_r(lhs, "=", &in_rhs);
                    strtok_r(lhs, "=", &in_rhs);
                    // printf("%s", in_lhs);
                    snprintf(ta->cookie, 300, "%s", in_rhs);
                    break;
                }
                lhs = strtok_r(rhs, ";", &rhs);
            }
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void http_add_header(buffer_t *resp, char *key, char *fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction *ta, buffer_t *res)
{
    if (ta->req_version == HTTP_1_0)
    {
        buffer_appends(res, "HTTP/1.0 ");
    }
    else
    {
        buffer_appends(res, "HTTP/1.1 ");
    }

    switch (ta->resp_status)
    {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction *ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

static bool
die(const char *msg, int error, struct http_transaction *ta)
{
    return send_error(ta, HTTP_PERMISSION_DENIED, "Death: %s", msg);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    // edit here and give back index.html
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found",
                      bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";

    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    if (!strcasecmp(suffix, ".svg"))
        return "image/svg+xml";

    return "text/plain";
    // apng
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    // check if header has range
    // use range to send file

    // when it comes to mp4
    // same as index.html

    // check range is in header

    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    if (access(fname, R_OK))
    {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else if (html5_fallback)
            snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");
        else
            return send_not_found(ta);
    }

    if (!strcmp(req_path, "/"))
        snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1)
    {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    http_add_header(&ta->resp_headers, "Accept-Ranges", "%s", "bytes");

    // off_t from = 0, to = st.st_size - 1;

    // off_t content_length = to + 1 - from;

    // check if range is given in header
    if (strlen(ta->range_str) != 0)
    {
        // printf("y");
        // parse range
        char *range_clean = strchr(ta->range_str, '=') + 1; // either XXX- OR XXX-YYY

        int range_clean_length = (int)strlen(range_clean) - 1;

        // printf("%s %d", range_clean, range_clean_length);
        char *first;
        char *second = NULL;

        first = strtok(range_clean, "-");
        // printf("%s%s", range_clean, first);
        if (strlen(first) < range_clean_length)
        {
            second = strtok(NULL, "-");
            // printf("%s", second);
        }

        // first and second are strings
        ta->range_from = (off_t)atoi(first);
        ta->range_to = st.st_size - 1;

        if (second != NULL)
        {
            ta->range_to = (off_t)atoi(second);
        }
        http_add_header(&ta->resp_headers, "Content-Range", "bytes %ld-%ld/%ld", ta->range_from, ta->range_to, st.st_size);
        // http_add_header(&ta->resp_headers, "Content-Range", "bytes %s-%s/%d", first, second, (int)content_length);
        ta->resp_status = HTTP_PARTIAL_CONTENT;
    }
    else
    {
        ta->resp_status = HTTP_OK;
        ta->range_from = 0;
        ta->range_to = st.st_size - 1;
    }

    // if yes then parse and add to header w Content-Range
    off_t content_length = (ta->range_to + 1) - ta->range_from;

    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && ta->range_from <= ta->range_to)
        success = bufio_sendfile(ta->client->bufio, filefd, &ta->range_from, &ta->range_to + 1 - &ta->range_from) > 0;

out:
    close(filefd);
    return success;
}

static bool handle_api_video(struct http_transaction *ta)
{
    // list out videos in json format
    if (ta->req_method == HTTP_GET)
    {
        char fileName[PATH_MAX];
        DIR *dir;
        dir = opendir(server_root);
        struct dirent *file;
        json_t *array = json_array();
        while ((file = readdir(dir)) != NULL)
        {
            char *mp4 = strchr(file->d_name, '.');
            if (mp4 != NULL)
            {
                if (strstr(mp4, ".mp4") != NULL)
                {
                    snprintf(fileName, sizeof(fileName), "%s/%s", server_root, file->d_name);
                    struct stat val;
                    stat(fileName, &val);
                    json_t *vid_object = json_object();
                    json_object_set_new(vid_object, "size", json_integer(val.st_size));
                    json_object_set_new(vid_object, "name", json_string(file->d_name));
                    json_array_append(array, vid_object);


                    // printf("useless: %d, %d, %d", size, name, appended);

                    // printf("useful: %s", ret_string);
                }
            }
        }
        closedir(dir);
        char *ret_string = json_dumps(array, 0);
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        buffer_append(&ta->resp_body, ret_string, strlen(ret_string));
        free(ret_string);
        ta->resp_status = HTTP_OK;
        return send_response(ta);
    }
    ta->resp_status = HTTP_OK;
    return send_response(ta);
}

static bool handle_private(struct http_transaction *ta)
{
    if (strlen(ta->cookie) != 0)
    {
        // authenticate
        jwt_t *ymtoken;
        int rc = jwt_decode(&ymtoken, ta->cookie,
                            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                            strlen(NEVER_EMBED_A_SECRET_IN_CODE));
        if (rc)
            return die("jwt_decode", rc, ta);

        char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
        if (grants == NULL)
            return die("jwt_get_grants_json", ENOMEM, ta);

        json_t *root = json_loadb(grants, strlen(grants), 0, NULL);

        json_t *expiry_time = json_object_get(root, "exp");
        json_t *user_name = json_object_get(root, "sub");

        const char *user_name_str = json_string_value(user_name);
        int exp_int = json_integer_value(expiry_time);
        time_t now = time(NULL);
        int now_int = (int)now;

        if (strcmp(user_name_str, "user0") == 0 && (exp_int > now_int))
        {
            return handle_static_asset(ta, server_root);
        }
        else
        {
            return send_error(ta, HTTP_PERMISSION_DENIED, "EXPIRED OR INCORRECT CRED");
        }
    }
    else
    {
        return send_error(ta, HTTP_PERMISSION_DENIED, "INCORRECT CREDENTIALS");
    }
}

static bool
handle_api_login(struct http_transaction *ta)
{
    // check for POST or GET
    if (ta->req_method == HTTP_GET)
    {
        ta->resp_status = HTTP_OK;
        if (strlen(ta->cookie) != 0)
        {
            jwt_t *ymtoken;
            int rc = jwt_decode(&ymtoken, ta->cookie,
                                (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                                strlen(NEVER_EMBED_A_SECRET_IN_CODE));
            if (rc)
            {
                buffer_append(&ta->resp_body, "{}", 2);
                ta->resp_status = HTTP_OK;
                return send_response(ta);
                // return die("jwt_decode", rc, ta);
            }

            char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
            if (grants == NULL)
            {
                buffer_append(&ta->resp_body, "{}", 2);
                ta->resp_status = HTTP_OK;
                return send_response(ta);
            }
            // return die("jwt_get_grants_json", ENOMEM, ta);

            // json_t *root = json_loadb(grants, strlen(grants), JSON_ENCODE_ANY, NULL);

            buffer_append(&ta->resp_body, grants, strlen(grants));
            // buffer_append(&ta->resp_headers, "Content-Type", "application/json");

            ta->resp_status = HTTP_OK;
            return send_response(ta);
        }
        buffer_append(&ta->resp_body, "{}", 2);
        ta->resp_status = HTTP_OK;
        return send_response(ta);
    }
    else if (ta->req_method == HTTP_POST)
    {
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        // check if /api/login (assume that this is there for now) & CHECK FOR JSON
        if (ta->req_content_len != 0)
        {
            char *body = bufio_offset2ptr(ta->client->bufio, ta->req_body);
            // check if json username and password match
            json_error_t err;
            json_t *res = json_loadb(body, (size_t)ta->req_content_len, JSON_ENCODE_ANY, &err);

            json_t *username_input = json_object_get(res, "username");
            json_t *password_input = json_object_get(res, "password");

            if (username_input == NULL || password_input == NULL)
            {
                return send_error(ta, HTTP_PERMISSION_DENIED, "INCORRECT CREDENTIALS");
            }

            const char *u_in_str = json_string_value(username_input);
            const char *p_in_str = json_string_value(password_input);

            if (strcmp(u_in_str, "user0") == 0 && strcmp(p_in_str, "thepassword") == 0)
            {
                // WHEN AUTH IS CORRECT
                // MAKE JWT AND SEND IT BACK
                jwt_t *mytoken;
                int rc = jwt_new(&mytoken);
                if (rc)
                    return die("jwt_new", rc, ta);

                rc = jwt_add_grant(mytoken, "sub", "user0");
                if (rc)
                    return die("jwt_add_grant sub", rc, ta);

                time_t now = time(NULL);
                rc = jwt_add_grant_int(mytoken, "iat", now);
                if (rc)
                    return die("jwt_add_grant iat", rc, ta);

                rc = jwt_add_grant_int(mytoken, "exp", now + token_expiration_time);
                // rc = jwt_add_grant_int(mytoken, "exp", now - 5);
                // always return expired token

                if (rc)
                    return die("jwt_add_grant exp", rc, ta);

                rc = jwt_set_alg(mytoken, JWT_ALG_HS256,
                                 (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                                 strlen(NEVER_EMBED_A_SECRET_IN_CODE));
                if (rc)
                    return die("jwt_set_alg", rc, ta);

                char *encoded = jwt_encode_str(mytoken);
                char *grants = jwt_get_grants_json(mytoken, NULL); // NULL means all
                if (grants == NULL)
                    return die("jwt_get_grants_json", ENOMEM, ta);
                // set cookie here
                http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/", encoded);
                buffer_append(&ta->resp_body, grants, strlen(grants));
                ta->resp_status = HTTP_OK;
                return send_response(ta);
            }
            else
            {
                return send_error(ta, HTTP_PERMISSION_DENIED, "INCORRECT CREDENTIALS");
            }
        }
        return send_error(ta, HTTP_PERMISSION_DENIED, "NO CREDENTIALS TYPED");
    }
    return send_error(ta, HTTP_METHOD_NOT_ALLOWED, "EDGE CASE NOT ACCOUNTED FOR");
}

/* Set up an http client, associating it with a bufio buffer. */
void http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
struct rc_and_ver http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);

    memset(&ta.cookie, 0, 300);
    memset(&ta.range_str, 0, 256);

    ta.client = self;

    // times out here
    if (!http_parse_request(&ta))
    {
        struct rc_and_ver return_stuff;
        return_stuff.http_ver = ta.req_version == HTTP_1_1 ? 1 : 0;
        return_stuff.rc = false;
        return return_stuff;
    }

    if (!http_process_headers(&ta))
    {
        struct rc_and_ver return_stuff;
        return_stuff.http_ver = ta.req_version == HTTP_1_1 ? 1 : 0;
        return_stuff.rc = false;
        return return_stuff;
    }

    if (ta.req_content_len > 0)
    {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
        {
            struct rc_and_ver return_stuff;
            return_stuff.http_ver = ta.req_version == HTTP_1_1 ? 1 : 0;
            return_stuff.rc = false;
            return return_stuff;
        }
        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    // this should be /api
    if (strstr(req_path, ".."))
    {
        rc = send_error(&ta, HTTP_NOT_FOUND, "Not found");
    }
    if (strcmp(req_path, "/api/login") == 0)
    {
        if (ta.req_method == HTTP_GET)
        {
            http_add_header(&ta.resp_headers, "Content-Type", "application/json");
            rc = handle_api_login(&ta);
        }
        else
        {
            rc = handle_api_login(&ta);
        }
    }
    else if (STARTS_WITH(req_path, "/api/video"))
    {
        // not implemented
        rc = handle_api_video(&ta);
    }
    else if (STARTS_WITH(req_path, "/private"))
    {
        // not implemented
        if (strlen(ta.cookie) == 0)
        {
            rc = send_error(&ta, HTTP_PERMISSION_DENIED, "NULL COOKIE");
        }
        rc = handle_private(&ta);
    }
    else
    {
        rc = handle_static_asset(&ta, server_root);
    }

    struct rc_and_ver return_stuff;
    return_stuff.http_ver = ta.req_version == HTTP_1_1 ? 1 : 0;
    return_stuff.rc = rc;
    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);
    return return_stuff;
}
