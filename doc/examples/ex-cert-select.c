
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* A TLS client that loads the certificate and key.
 */

#define MAX_BUF 1024
#define SA struct sockaddr
#define MSG "GET / HTTP/1.0\r\n\r\n"

#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#define CAFILE "ca.pem"

static int cert_callback(gnutls_session_t session,
			 const gnutls_datum_t * req_ca_rdn, int nreqs,
			 const gnutls_pk_algorithm_t * sign_algos,
			 int sign_algos_length, gnutls_retr_st * st);

gnutls_x509_crt_t crt;
gnutls_x509_privkey_t key;

/* Helper functions to load a certificate and key
 * files into memory. They use mmap for simplicity.
 */
static gnutls_datum_t mmap_file(const char *file)
{
    int fd;
    gnutls_datum_t mmaped_file = { NULL, 0 };
    struct stat stat_st;
    void *ptr;

    fd = open(file, 0);
    if (fd == -1)
	return mmaped_file;

    fstat(fd, &stat_st);

    ptr =
        mmap(NULL, stat_st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);

    if(ptr == MAP_FAILED)
	return mmaped_file;

    mmaped_file.data = ptr;
    mmaped_file.size = stat_st.st_size;

    return mmaped_file;
}

static void munmap_file(gnutls_datum_t data)
{
    munmap(data.data, data.size);
}

/* Load the certificate and the private key.
 */
static void load_keys(void)
{
    int ret;
    gnutls_datum_t data;

    data = mmap_file(CERT_FILE);
    if (data.data == NULL) {
	fprintf(stderr, "*** Error loading cert file.\n");
	exit(1);
    }
    gnutls_x509_crt_init(&crt);

    ret = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
	fprintf(stderr, "*** Error loading key file: %s\n",
		gnutls_strerror(ret));
	exit(1);
    }

    munmap_file(data);

    data = mmap_file(KEY_FILE);
    if (data.data == NULL) {
	fprintf(stderr, "*** Error loading key file.\n");
	exit(1);
    }

    gnutls_x509_privkey_init(&key);

    ret = gnutls_x509_privkey_import(key, &data, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
	fprintf(stderr, "*** Error loading key file: %s\n",
		gnutls_strerror(ret));
	exit(1);
    }

    munmap_file(data);

}

int main()
{
    int ret, sd, ii;
    gnutls_session_t session;
    char buffer[MAX_BUF + 1];
    gnutls_certificate_credentials_t xcred;
    /* Allow connections to servers that have OpenPGP keys as well.
     */

    gnutls_global_init();

    load_keys();

    /* X509 stuff */
    gnutls_certificate_allocate_credentials(&xcred);

    /* sets the trusted cas file
     */
    gnutls_certificate_set_x509_trust_file(xcred, CAFILE,
					   GNUTLS_X509_FMT_PEM);

    gnutls_certificate_client_set_retrieve_function(xcred, cert_callback);

    /* Initialize TLS session 
     */
    gnutls_init(&session, GNUTLS_CLIENT);

    /* Use default priorities */
    gnutls_set_default_priority(session);

    /* put the x509 credentials to the current session
     */
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

    /* connect to the peer
     */
    sd = tcp_connect();

    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) sd);

    /* Perform the TLS handshake
     */
    ret = gnutls_handshake(session);

    if (ret < 0) {
	fprintf(stderr, "*** Handshake failed\n");
	gnutls_perror(ret);
	goto end;
    } else {
	printf("- Handshake was completed\n");
    }

    gnutls_record_send(session, MSG, strlen(MSG));

    ret = gnutls_record_recv(session, buffer, MAX_BUF);
    if (ret == 0) {
	printf("- Peer has closed the TLS connection\n");
	goto end;
    } else if (ret < 0) {
	fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
	goto end;
    }

    printf("- Received %d bytes: ", ret);
    for (ii = 0; ii < ret; ii++) {
	fputc(buffer[ii], stdout);
    }
    fputs("\n", stdout);

    gnutls_bye(session, GNUTLS_SHUT_RDWR);

  end:

    tcp_close(sd);

    gnutls_deinit(session);

    gnutls_certificate_free_credentials(xcred);

    gnutls_global_deinit();

    return 0;
}



/* This callback should be associated with a session by calling
 * gnutls_certificate_client_set_retrieve_function( session, cert_callback),
 * before a handshake.
 */

static int cert_callback(gnutls_session_t session,
			 const gnutls_datum_t * req_ca_rdn, int nreqs,
			 const gnutls_pk_algorithm_t * sign_algos,
			 int sign_algos_length, gnutls_retr_st * st)
{
    char issuer_dn[256];
    int i, ret;
    size_t len;
    gnutls_certificate_type_t type;

    /* Print the server's trusted CAs
     */
    if (nreqs > 0)
	printf("- Server's trusted authorities:\n");
    else
	printf
	    ("- Server did not send us any trusted authorities names.\n");

    /* print the names (if any) */
    for (i = 0; i < nreqs; i++) {
	len = sizeof(issuer_dn);
	ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
	if (ret >= 0) {
	    printf("   [%d]: ", i);
	    printf("%s\n", issuer_dn);
	}
    }

    /* Select a certificate and return it.
     * The certificate must be of any of the "sign algorithms"
     * supported by the server.
     */

    type = gnutls_certificate_type_get(session);
    if (type == GNUTLS_CRT_X509) {
	st->type = type;
	st->ncerts = 1;

	st->cert.x509 = &crt;
	st->key.x509 = key;

	st->deinit_all = 0;
    } else {
	return -1;
    }

    return 0;

}
