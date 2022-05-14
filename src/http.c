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
#include <jansson.h>
#include <dirent.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"


// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

static const char * NEVER_EMBED_A_SECRET_IN_CODE = "supa secret";
static bool user_authenticate(struct http_transaction* ta);

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
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
    if (http_version == NULL)  // would be HTTP 0.9
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
//parse info, look for cookie header, if it's there go through field to look for correct cookie.
//find the name, get value and validate
//save the value into trasction, use it and check later
//check name of header,
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
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
        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }
        if (!strcasecmp(field_name, "Range")){
            ta->partial = true;
            
            char temp[5];
            int starting = -1;
            int ending = -1;

            sscanf(field_value, "%5s=%d-%d", temp, &starting, &ending);
            
            ta->begin = starting;
            ta->end = ending;
            ta->type = temp;
        }
        if (!strcasecmp(field_name, "Cookie")){
            char* rest;
            char* token = strtok_r(field_value, ";", &rest);
            while(token != NULL){
                if(strstr(token, "auth_token")){
                    break;
                }       
                token = strtok_r(NULL, ";", &rest);
            }
            strtok_r(token, "=", &rest);
            ta->token = rest;
            ta->authenticate = true;
        }
        if (!strcasecmp(field_name, "Connection"))
        {
            if (strcmp(field_value, "close") == 0)
                ta->verify = true;
            else
                ta->verify = false;
        }
        
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
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
start_response(struct http_transaction * ta, buffer_t *res)
{
    buffer_appends(res, "HTTP/1.1 ");

    switch (ta->resp_status) {
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
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
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

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
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
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    // send 404 when there's no file
    // if there's .. in request path, cancel
    // if req_path got .. then return error code.
    char fname[PATH_MAX];
    // if(basedir == NULL){
    //     return send_not_found(ta);
    // }

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);

    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);
    if (access(fname, R_OK)) {
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
    //S_ISREG(path_stat.st_mode); // if req file, can do it, if not do the fall back. send not found if fall back is enabled
    //instead of req path. just do /index.html... read and send that file instead.
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
         return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    // off_t from = 0, to = st.st_size - 1;

    // off_t content_length = to + 1 - from;
    // add_content_length(&ta->resp_headers, content_length);
    off_t from, to, content_length;

    if(ta->partial == true){
        ta->resp_status = HTTP_PARTIAL_CONTENT;
        from = ta->begin;
        if(ta->end == -1){
            to = st.st_size - 1;
            if(from < 0){
                from = to + from + 1;
            }
        }else{
            to = ta->end;
        }

        content_length = to + 1 - from;
        http_add_header(&ta->resp_headers, "Content-Range", "bytes %ld-%ld/%ld", from, to, st.st_size);
    }else{
        from = 0;
        to = st.st_size - 1;
        content_length = to + 1 - from;
    }

    add_content_length(&ta->resp_headers, content_length);
    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
    ta->partial = false;
    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;
        
    out:
    close(filefd);
    return success;
}


static bool
handle_api(struct http_transaction *ta, int expired)
{
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    ta->resp_status = HTTP_OK;
    // printf(" req_path: %s \n", req_path);
    if(ta->req_method == HTTP_POST && strcmp(req_path, "/api/login") == 0){
        json_t *root;
        json_error_t error;

        char* body = bufio_offset2ptr(ta->client->bufio, ta->req_body);

        root = json_loadb(body, ta->req_body, JSON_DISABLE_EOF_CHECK, &error);
        json_t* json_username = json_object_get(root, "username");
        if(json_username == NULL){
            return send_error(ta,HTTP_PERMISSION_DENIED, "TEST");
        }
        json_t* json_password = json_object_get(root, "password");
        if(json_password == NULL){
            return send_error(ta,HTTP_PERMISSION_DENIED, "TEST");
        }
        const char* username = json_string_value(json_username);
        const char* password = json_string_value(json_password);

        if(strcmp(password, "thepassword") == 0 && strcmp(username, "user0") == 0){
            
            //create a new jwt token
            jwt_t *mytoken;

            jwt_new(&mytoken);
            //add sub to token
            jwt_add_grant(mytoken, "sub", username);
            //add iat to token
            time_t now = time(NULL);
            jwt_add_grant_int(mytoken, "iat", now);
            //add exp to token
            jwt_add_grant_int(mytoken, "exp", now + expired);

            jwt_set_alg(mytoken, JWT_ALG_HS256, 
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
            strlen(NEVER_EMBED_A_SECRET_IN_CODE));

            //encode the token
            char *encoded = jwt_encode_str(mytoken);
            //grab the json
            char *grants = jwt_get_grants_json(mytoken, NULL);
            
            buffer_appends(&ta->resp_body, grants);
            http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/", encoded);
            http_add_header(&ta->resp_headers, "Content-Type", "%s", "application/json");
            return send_response(ta);

        }
        else{
            return send_error(ta,HTTP_PERMISSION_DENIED, "TEST");
        }
    }else if(ta->req_method == HTTP_GET && strcmp(req_path, "/api/login") == 0){
        ta->resp_status = HTTP_OK;
        
        if(ta->authenticate == false){
            buffer_appends(&ta->resp_body, "{}");
            http_add_header(&ta->resp_headers, "Content-Type", "%s", "application/json");
        }
        else{
                jwt_t *ymtoken;
                jwt_decode(&ymtoken, ta->token,
                    (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
                    strlen(NEVER_EMBED_A_SECRET_IN_CODE));
                char *grants = jwt_get_grants_json(ymtoken, NULL);
                long exp = jwt_get_grant_int(ymtoken, "exp");
                time_t now = time(NULL);
                if(now - exp > 0){
                    buffer_appends(&ta->resp_body, "{}");
                }
                else{
                    buffer_appends(&ta->resp_body, grants);
                } 
                http_add_header(&ta->resp_headers, "Content-Type", "%s", "application/json");
                return send_response(ta);
        }

    }
    else if(ta->req_method == HTTP_GET && strcmp(req_path, "/api/video") == 0){
        DIR* dir;
        struct dirent* file;
        char fileName[PATH_MAX];
        dir = opendir(server_root);
        json_t* vids = json_array();
        ta->resp_status = HTTP_OK;

        while ((file = readdir(dir)) != NULL){
            char* pointer = file->d_name + strlen(file->d_name) - 4;
            if(pointer < file->d_name) continue;
            if(strcmp(pointer, ".mp4") == 0){
                snprintf(fileName, sizeof fileName, "%s/%s", server_root, file->d_name);
                struct stat val;
                stat(fileName, &val);
                json_t* vid_object = json_object();
                int size = json_object_set_new(vid_object, "size", json_integer(val.st_size));
                int name = json_object_set_new(vid_object, "name", json_string(file->d_name));
                if(size != 0) continue;
                if(name != 0) continue;

                json_array_append(vids, vid_object);

            }
        }
        closedir(dir);

        buffer_appends(&ta->resp_body, json_dumps(vids, JSON_INDENT(4)));
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
    }
    else if(ta->req_method != HTTP_GET && ta->req_method != HTTP_POST && strcmp(req_path, "/api/login") == 0){
        return send_error(ta,HTTP_METHOD_NOT_ALLOWED, "TEST");
    }
    else{
        ta->resp_status = HTTP_NOT_FOUND;
        http_add_header(&ta->resp_headers, "Content-Type", "%s", "application/json");
        return send_response(ta);
    }
    return send_response(ta);
}
static bool user_authenticate(struct http_transaction* ta){
    if(ta->authenticate){
    jwt_t *ymtoken;
        int rc = jwt_decode(&ymtoken, ta->token,
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
            strlen(NEVER_EMBED_A_SECRET_IN_CODE));
        // char *grants = jwt_get_grants_json(ymtoken, NULL);
        if (rc){
            return false;
        }
            
        time_t exp;
        const char * sub; 
        exp = jwt_get_grant_int(ymtoken, "exp");
        sub = jwt_get_grant(ymtoken, "sub");

        time_t now = time(NULL); 
        if(now - exp > 0 || strcmp(sub, "user0") != 0){ // expired
            // buffer_appends(&ta->resp_body, "{}");
            return false;
        }else{
            // buffer_appends(&ta->resp_body, grants);
            return true;
        }
    }
    else{
        return false;
    }
    
}

//handle static asset
// only done when user is authenticated
// token, 

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self, bool temp, int expired)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;

    if (!http_parse_request(&ta))
        return false;

    if (!http_process_headers(&ta))
        return false;

    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // printf("%s \n", body);
        // hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    if (strstr(req_path, ".."))
    {
        rc = send_error(&ta, HTTP_NOT_FOUND, "Not found");
    }

    if (STARTS_WITH(req_path, "/api")) {
        rc = handle_api(&ta, expired);
        
    } else if (STARTS_WITH(req_path, "/private")) {
            if(user_authenticate(&ta)){
                rc = handle_static_asset(&ta, server_root);
            }
            else {
                return send_error(&ta, HTTP_PERMISSION_DENIED, "Permission denied.");
            }
    }
    // else if(temp == false && STARTS_WITH(req_path, "/public")){
    //    return send_error(&ta, HTTP_NOT_FOUND, "NOT FOUND");
    // } 
    else {
        rc = handle_static_asset(&ta, server_root);
    }
    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    if(ta.req_version == HTTP_1_0){
        return false;
    }
    else if(ta.req_version == HTTP_1_1){
        if(ta.verify == true){
            return false;
        }
        else{
            return true;
        }
    }

    return rc;
}
