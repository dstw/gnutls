#ifndef GNUTLS_MPI_H
# define GNUTLS_MPI_H

# include <gcrypt.h>
# include <libtasn1.h>

#define GNUTLS_MPI gcry_mpi_t

#define _gnutls_mpi_cmp_ui gcry_mpi_cmp_ui
#define _gnutls_mpi_mod gcry_mpi_mod
#define _gnutls_mpi_new gcry_mpi_new
#define _gnutls_mpi_snew gcry_mpi_snew
#define _gnutls_mpi_copy gcry_mpi_copy
#define _gnutls_mpi_set_ui gcry_mpi_set_ui
#define _gnutls_mpi_set gcry_mpi_set
#define _gnutls_mpi_randomize gcry_mpi_randomize
#define _gnutls_mpi_get_nbits gcry_mpi_get_nbits
#define _gnutls_mpi_powm gcry_mpi_powm
#define _gnutls_mpi_invm gcry_mpi_invm
#define _gnutls_mpi_addm gcry_mpi_addm
#define _gnutls_mpi_subm gcry_mpi_subm
#define _gnutls_mpi_mulm gcry_mpi_mulm
#define _gnutls_mpi_mul gcry_mpi_mul
#define _gnutls_mpi_add gcry_mpi_add
#define _gnutls_mpi_add_ui gcry_mpi_add_ui
#define _gnutls_mpi_mul_ui gcry_mpi_mul_ui

# define _gnutls_mpi_alloc_like(x) _gnutls_mpi_new(_gnutls_mpi_get_nbits(x)) 

void _gnutls_mpi_release( GNUTLS_MPI* x);

int _gnutls_mpi_scan( GNUTLS_MPI *ret_mpi, const opaque *buffer, size_t *nbytes );
int _gnutls_mpi_scan_pgp( GNUTLS_MPI *ret_mpi, const opaque *buffer, size_t *nbytes );

int _gnutls_mpi_print( opaque *buffer, size_t *nbytes, const GNUTLS_MPI a );
int _gnutls_mpi_print_lz( opaque *buffer, size_t *nbytes, const GNUTLS_MPI a );


#endif
