// Max Base - MaxBase.org
// https://github.com/BaseMax/ZMiniCArchiveCompressor
/*
Tested on: Linux base 5.3.0-40-generic
Compile: $ gcc mini.c -o mini -O3
Using: $ ./mini c input.txt output.x
       $ ./mini d output.x input.txt
max@base:~/compress$ ./mini d o.txt oi.txt
  Mode: d, Level: 10
  Input File: "o.txt"
  Output File: "oi.txt"
  Input file size: 2107
  Total input bytes: 2107
  Total output bytes: 4275
  Done.
max@base:~/compress$ ./mini c i.txt o.txt
  Mode: c, Level: 10
  Input File: "i.txt"
  Output File: "o.txt"
  Input file size: 4275
  Total input bytes: 4275
  Total output bytes: 2107
  Done.
*/
#ifndef MINI_HEADER_INCLUDED
#define MINI_HEADER_INCLUDED
#include <stdlib.h>
#if defined(__TINYC__) && (defined(__linux) || defined(__linux__))
#define MINI_NO_TIME
#endif
#if !defined(MINI_NO_TIME) && !defined(MINI_NO_ARCHIVE_APIS)
#include <time.h>
#endif
#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) ||                \
    defined(__i386) || defined(__i486__) || defined(__i486) ||                 \
    defined(i386) || defined(__ia64__) || defined(__x86_64__)
#define MINI_X86_OR_X64_CPU 1
#endif
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || MINI_X86_OR_X64_CPU
#define MINI_LITTLE_ENDIAN 1
#endif
#if MINI_X86_OR_X64_CPU
#define MINI_USE_UNALIGNED_LOADS_AND_STORES 1
#endif
#if defined(_M_X64) || defined(_WIN64) || defined(__MINGW64__) ||              \
    defined(_LP64) || defined(__LP64__) || defined(__ia64__) ||                \
    defined(__x86_64__)
#define MINI_HAS_64BIT_REGISTERS 1
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef unsigned long MINI_ulong;
void MINI_free(void *p);
#define MINI_ADLER32_INIT (1)
MINI_ulong MINI_adler32(MINI_ulong adler, const unsigned char *ptr, size_t buf_len);
#define MINI_CRC32_INIT (0)
MINI_ulong MINI_crc32(MINI_ulong crc, const unsigned char *ptr, size_t buf_len);
enum {
  MINI_DEFAULT_STRATEGY = 0, MINI_FILTERED = 1, MINI_HUFFMAN_ONLY = 2, MINI_RLE = 3, MINI_FIXED = 4
};
#define MINI_DEFLATED 8
#ifndef MINI_NO_ZLIB_APIS
typedef void *(*MINI_alloc_func)(void *opaque, size_t items, size_t size);
typedef void (*MINI_free_func)(void *opaque, void *address);
typedef void *(*MINI_realloc_func)(void *opaque, void *address, size_t items, size_t size);
#define MINI_VERSION "9.1.15"
#define MINI_VERNUM 0x91F0
#define MINI_VER_MAJOR 9
#define MINI_VER_MINOR 1
#define MINI_VER_REVISION 15
#define MINI_VER_SUBREVISION 0
enum {
  MINI_NO_FLUSH = 0, MINI_PARTIAL_FLUSH = 1, MINI_SYNC_FLUSH = 2, MINI_FULL_FLUSH = 3, MINI_FINISH = 4, MINI_BLOCK = 5
};
enum {
  MINI_OK = 0, MINI_STREAM_END = 1, MINI_NEED_DICT = 2, MINI_ERRNO = -1, MINI_STREAM_ERROR = -2, MINI_DATA_ERROR = -3, MINI_MEM_ERROR = -4, MINI_BUF_ERROR = -5, MINI_VERSION_ERROR = -6, MINI_PARAM_ERROR = -10000
};
enum {
  MINI_NO_COMPRESSION = 0, MINI_BEST_SPEED = 1, MINI_BEST_COMPRESSION = 9, MINI_UBER_COMPRESSION = 10, MINI_DEFAULT_LEVEL = 6, MINI_DEFAULT_COMPRESSION = -1
};
#define MINI_DEFAULT_WINDOW_BITS 15
struct MINI_internal_state;
typedef struct MINI_stream_s {
  const unsigned char *next_in;
  unsigned int avail_in;
  MINI_ulong total_in;
  unsigned char *next_out;
  unsigned int avail_out;
  MINI_ulong total_out;
  char *msg;
  struct MINI_internal_state *state;
  MINI_alloc_func zalloc;
  MINI_free_func zfree;
  void *opaque;
  int data_type;
  MINI_ulong adler;
  MINI_ulong reserved;
} MINI_stream;
typedef MINI_stream *MINI_streamp;
const char *MINI_version(void);
int MINI_deflateInit(MINI_streamp pStream, int level);
int MINI_deflateInit2(MINI_streamp pStream, int level, int method, int window_bits, int mem_level, int strategy);
int MINI_deflateReset(MINI_streamp pStream);
int MINI_deflate(MINI_streamp pStream, int flush);
int MINI_deflateEnd(MINI_streamp pStream);
MINI_ulong MINI_deflateBound(MINI_streamp pStream, MINI_ulong source_len);
int MINI_compress(unsigned char *pDest, MINI_ulong *pDest_len, const unsigned char *pSource, MINI_ulong source_len);
int MINI_compress2(unsigned char *pDest, MINI_ulong *pDest_len, const unsigned char *pSource, MINI_ulong source_len, int level);
MINI_ulong MINI_compressBound(MINI_ulong source_len);
int MINI_inflateInit(MINI_streamp pStream);
int MINI_inflateInit2(MINI_streamp pStream, int window_bits);
int MINI_inflate(MINI_streamp pStream, int flush);
int MINI_inflateEnd(MINI_streamp pStream);
int MINI_uncompress(unsigned char *pDest, MINI_ulong *pDest_len, const unsigned char *pSource, MINI_ulong source_len);
const char *MINI_error(int err);
#ifndef MINI_NO_ZLIB_COMPATIBLE_NAMES
typedef unsigned char Byte;
typedef unsigned int uInt;
typedef MINI_ulong uLong;
typedef Byte Bytef;
typedef uInt uIntf;
typedef char charf;
typedef int intf;
typedef void *voidpf;
typedef uLong uLongf;
typedef void *voidp;
typedef void *const voidpc;
#define Z_NULL 0
#define Z_NO_FLUSH MINI_NO_FLUSH
#define Z_PARTIAL_FLUSH MINI_PARTIAL_FLUSH
#define Z_SYNC_FLUSH MINI_SYNC_FLUSH
#define Z_FULL_FLUSH MINI_FULL_FLUSH
#define Z_FINISH MINI_FINISH
#define Z_BLOCK MINI_BLOCK
#define Z_OK MINI_OK
#define Z_STREAM_END MINI_STREAM_END
#define Z_NEED_DICT MINI_NEED_DICT
#define Z_ERRNO MINI_ERRNO
#define Z_STREAM_ERROR MINI_STREAM_ERROR
#define Z_DATA_ERROR MINI_DATA_ERROR
#define Z_MEM_ERROR MINI_MEM_ERROR
#define Z_BUF_ERROR MINI_BUF_ERROR
#define Z_VERSION_ERROR MINI_VERSION_ERROR
#define Z_PARAM_ERROR MINI_PARAM_ERROR
#define Z_NO_COMPRESSION MINI_NO_COMPRESSION
#define Z_BEST_SPEED MINI_BEST_SPEED
#define Z_BEST_COMPRESSION MINI_BEST_COMPRESSION
#define Z_DEFAULT_COMPRESSION MINI_DEFAULT_COMPRESSION
#define Z_DEFAULT_STRATEGY MINI_DEFAULT_STRATEGY
#define Z_FILTERED MINI_FILTERED
#define Z_HUFFMAN_ONLY MINI_HUFFMAN_ONLY
#define Z_RLE MINI_RLE
#define Z_FIXED MINI_FIXED
#define Z_DEFLATED MINI_DEFLATED
#define Z_DEFAULT_WINDOW_BITS MINI_DEFAULT_WINDOW_BITS
#define alloc_func MINI_alloc_func
#define free_func MINI_free_func
#define internal_state MINI_internal_state
#define z_stream MINI_stream
#define deflateInit MINI_deflateInit
#define deflateInit2 MINI_deflateInit2
#define deflateReset MINI_deflateReset
#define deflate MINI_deflate
#define deflateEnd MINI_deflateEnd
#define deflateBound MINI_deflateBound
#define compress MINI_compress
#define compress2 MINI_compress2
#define compressBound MINI_compressBound
#define inflateInit MINI_inflateInit
#define inflateInit2 MINI_inflateInit2
#define inflate MINI_inflate
#define inflateEnd MINI_inflateEnd
#define uncompress MINI_uncompress
#define crc32 MINI_crc32
#define adler32 MINI_adler32
#define MAX_WBITS 15
#define MAX_MEM_LEVEL 9
#define zError MINI_error
#define ZLIB_VERSION MINI_VERSION
#define ZLIB_VERNUM MINI_VERNUM
#define ZLIB_VER_MAJOR MINI_VER_MAJOR
#define ZLIB_VER_MINOR MINI_VER_MINOR
#define ZLIB_VER_REVISION MINI_VER_REVISION
#define ZLIB_VER_SUBREVISION MINI_VER_SUBREVISION
#define zlibVersion MINI_version
#define zlib_version MINI_version()
#endif
#endif
typedef unsigned char MINI_uint8;
typedef signed short MINI_int16;
typedef unsigned short MINI_uint16;
typedef unsigned int MINI_uint32;
typedef unsigned int MINI_uint;
typedef long long MINI_int64;
typedef unsigned long long MINI_uint64;
typedef int MINI_bool;
#define MINI_FALSE (0)
#define MINI_TRUE (1)
#ifdef _MSC_VER
#define MINI_MACRO_END while (0, 0)
#else
#define MINI_MACRO_END while (0)
#endif
#ifndef MINI_NO_ARCHIVE_APIS
enum {
  MINI_ZIP_MAX_IO_BUF_SIZE = 64 * 1024, MINI_ZIP_MAX_ARCHIVE_FILENAME_SIZE = 260, MINI_ZIP_MAX_ARCHIVE_FILE_COMMENT_SIZE = 256
};
typedef struct {
  MINI_uint32 m_file_index;
  MINI_uint32 m_central_dir_ofs;
  MINI_uint16 m_version_made_by;
  MINI_uint16 m_version_needed;
  MINI_uint16 m_bit_flag;
  MINI_uint16 m_method;
#ifndef MINI_NO_TIME
  time_t m_time;
#endif
  MINI_uint32 m_crc32;
  MINI_uint64 m_comp_size;
  MINI_uint64 m_uncomp_size;
  MINI_uint16 m_internal_attr;
  MINI_uint32 m_external_attr;
  MINI_uint64 m_local_header_ofs;
  MINI_uint32 m_comment_size;
  char m_filename[MINI_ZIP_MAX_ARCHIVE_FILENAME_SIZE];
  char m_comment[MINI_ZIP_MAX_ARCHIVE_FILE_COMMENT_SIZE];
} MINI_zip_archive_file_stat;
typedef size_t (*MINI_file_read_func)(void *pOpaque, MINI_uint64 file_ofs, void *pBuf, size_t n);
typedef size_t (*MINI_file_write_func)(void *pOpaque, MINI_uint64 file_ofs, const void *pBuf, size_t n);
struct MINI_zip_internal_state_tag;
typedef struct MINI_zip_internal_state_tag MINI_zip_internal_state;
typedef enum {
  MINI_ZIP_MODE_INVALID = 0, MINI_ZIP_MODE_READING = 1, MINI_ZIP_MODE_WRITING = 2, MINI_ZIP_MODE_WRITING_HAS_BEEN_FINALIZED = 3
} MINI_zip_mode;
typedef struct MINI_zip_archive_tag {
  MINI_uint64 m_archive_size;
  MINI_uint64 m_central_directory_file_ofs;
  MINI_uint m_total_files;
  MINI_zip_mode m_zip_mode;
  MINI_uint m_file_offset_alignment;
  MINI_alloc_func m_pAlloc;
  MINI_free_func m_pFree;
  MINI_realloc_func m_pRealloc;
  void *m_pAlloc_opaque;
  MINI_file_read_func m_pRead;
  MINI_file_write_func m_pWrite;
  void *m_pIO_opaque;
  MINI_zip_internal_state *m_pState;
} MINI_zip_archive;
typedef enum {
  MINI_ZIP_FLAG_CASE_SENSITIVE = 0x0100, MINI_ZIP_FLAG_IGNORE_PATH = 0x0200, MINI_ZIP_FLAG_COMPRESSED_DATA = 0x0400, MINI_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY = 0x0800
} MINI_zip_flags;
MINI_bool MINI_zip_reader_init(MINI_zip_archive *pZip, MINI_uint64 size, MINI_uint32 flags);
MINI_bool MINI_zip_reader_init_mem(MINI_zip_archive *pZip, const void *pMem, size_t size, MINI_uint32 flags);
#ifndef MINI_NO_STDIO
MINI_bool MINI_zip_reader_init_file(MINI_zip_archive *pZip, const char *pFilename, MINI_uint32 flags);
#endif
MINI_uint MINI_zip_reader_get_num_files(MINI_zip_archive *pZip);
MINI_bool MINI_zip_reader_file_stat(MINI_zip_archive *pZip, MINI_uint file_index, MINI_zip_archive_file_stat *pStat);
MINI_bool MINI_zip_reader_is_file_a_directory(MINI_zip_archive *pZip, MINI_uint file_index);
MINI_bool MINI_zip_reader_is_file_encrypted(MINI_zip_archive *pZip, MINI_uint file_index);
MINI_uint MINI_zip_reader_get_filename(MINI_zip_archive *pZip, MINI_uint file_index, char *pFilename, MINI_uint filename_buf_size);
int MINI_zip_reader_locate_file(MINI_zip_archive *pZip, const char *pName, const char *pComment, MINI_uint flags);
MINI_bool MINI_zip_reader_extract_to_mem_no_alloc(MINI_zip_archive *pZip, MINI_uint file_index, void *pBuf, size_t buf_size, MINI_uint flags, void *pUser_read_buf, size_t user_read_buf_size);
MINI_bool MINI_zip_reader_extract_file_to_mem_no_alloc(
    MINI_zip_archive *pZip, const char *pFilename, void *pBuf, size_t buf_size, MINI_uint flags, void *pUser_read_buf, size_t user_read_buf_size);
MINI_bool MINI_zip_reader_extract_to_mem(MINI_zip_archive *pZip, MINI_uint file_index, void *pBuf, size_t buf_size, MINI_uint flags);
MINI_bool MINI_zip_reader_extract_file_to_mem(MINI_zip_archive *pZip, const char *pFilename, void *pBuf, size_t buf_size, MINI_uint flags);
void *MINI_zip_reader_extract_to_heap(MINI_zip_archive *pZip, MINI_uint file_index, size_t *pSize, MINI_uint flags);
void *MINI_zip_reader_extract_file_to_heap(MINI_zip_archive *pZip, const char *pFilename, size_t *pSize, MINI_uint flags);
MINI_bool MINI_zip_reader_extract_to_callback(MINI_zip_archive *pZip, MINI_uint file_index, MINI_file_write_func pCallback, void *pOpaque, MINI_uint flags);
MINI_bool MINI_zip_reader_extract_file_to_callback(MINI_zip_archive *pZip, const char *pFilename, MINI_file_write_func pCallback, void *pOpaque, MINI_uint flags);
#ifndef MINI_NO_STDIO
MINI_bool MINI_zip_reader_extract_to_file(MINI_zip_archive *pZip, MINI_uint file_index, const char *pDst_filename, MINI_uint flags);
MINI_bool MINI_zip_reader_extract_file_to_file(MINI_zip_archive *pZip, const char *pArchive_filename, const char *pDst_filename, MINI_uint flags);
#endif
MINI_bool MINI_zip_reader_end(MINI_zip_archive *pZip);
#ifndef MINI_NO_ARCHIVE_WRITING_APIS
MINI_bool MINI_zip_writer_init(MINI_zip_archive *pZip, MINI_uint64 existing_size);
MINI_bool MINI_zip_writer_init_heap(MINI_zip_archive *pZip, size_t size_to_reserve_at_beginning, size_t initial_allocation_size);
#ifndef MINI_NO_STDIO
MINI_bool MINI_zip_writer_init_file(MINI_zip_archive *pZip, const char *pFilename, MINI_uint64 size_to_reserve_at_beginning);
#endif
MINI_bool MINI_zip_writer_init_from_reader(MINI_zip_archive *pZip, const char *pFilename);
MINI_bool MINI_zip_writer_add_mem(MINI_zip_archive *pZip, const char *pArchive_name, const void *pBuf, size_t buf_size, MINI_uint level_and_flags);
MINI_bool MINI_zip_writer_add_mem_ex(MINI_zip_archive *pZip, const char *pArchive_name, const void *pBuf, size_t buf_size, const void *pComment, MINI_uint16 comment_size, MINI_uint level_and_flags, MINI_uint64 uncomp_size, MINI_uint32 uncomp_crc32);
#ifndef MINI_NO_STDIO
MINI_bool MINI_zip_writer_add_file(MINI_zip_archive *pZip, const char *pArchive_name, const char *pSrc_filename, const void *pComment, MINI_uint16 comment_size, MINI_uint level_and_flags);
#endif
MINI_bool MINI_zip_writer_add_from_zip_reader(MINI_zip_archive *pZip, MINI_zip_archive *pSource_zip, MINI_uint file_index);
MINI_bool MINI_zip_writer_finalize_archive(MINI_zip_archive *pZip);
MINI_bool MINI_zip_writer_finalize_heap_archive(MINI_zip_archive *pZip, void **pBuf, size_t *pSize);
MINI_bool MINI_zip_writer_end(MINI_zip_archive *pZip);
MINI_bool MINI_zip_add_mem_to_archive_file_in_place(
    const char *pZip_filename, const char *pArchive_name, const void *pBuf, size_t buf_size, const void *pComment, MINI_uint16 comment_size, MINI_uint level_and_flags);
void *MINI_zip_extract_archive_file_to_heap(const char *pZip_filename, const char *pArchive_name, size_t *pSize, MINI_uint zip_flags);
#endif
#endif
enum {
  TINFL_FLAG_PARSE_ZLIB_HEADER = 1, TINFL_FLAG_HAS_MORE_INPUT = 2, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF = 4, TINFL_FLAG_COMPUTE_ADLER32 = 8
};
void *tinfl_decompress_mem_to_heap(const void *pSrc_buf, size_t src_buf_len, size_t *pOut_len, int flags);
#define TINFL_DECOMPRESS_MEM_TO_MEM_FAILED ((size_t)(-1))
size_t tinfl_decompress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len, int flags);
typedef int (*tinfl_put_buf_func_ptr)(const void *pBuf, int len, void *pUser);
int tinfl_decompress_mem_to_callback(const void *pIn_buf, size_t *pIn_buf_size, tinfl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags);
struct tinfl_decompressor_tag;
typedef struct tinfl_decompressor_tag tinfl_decompressor;
#define TINFL_LZ_DICT_SIZE 32768
typedef enum {
  TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS = -4,
  TINFL_STATUS_BAD_PARAM = -3,
  TINFL_STATUS_ADLER32_MISMATCH = -2,
  TINFL_STATUS_FAILED = -1,
  TINFL_STATUS_DONE = 0,
  TINFL_STATUS_NEEDS_MORE_INPUT = 1,
  TINFL_STATUS_HAS_MORE_OUTPUT = 2
} tinfl_status;
#define tinfl_init(r)                                                          \
  do {                                                                         \
    (r)->m_state = 0;                                                          \
  }                                                                            \
  MINI_MACRO_END
#define tinfl_get_adler32(r) (r)->m_check_adler32
tinfl_status tinfl_decompress(tinfl_decompressor *r, const MINI_uint8 *pIn_buf_next, size_t *pIn_buf_size, MINI_uint8 *pOut_buf_start, MINI_uint8 *pOut_buf_next, size_t *pOut_buf_size, const MINI_uint32 decomp_flags);
enum {
  TINFL_MAX_HUFF_TABLES = 3, TINFL_MAX_HUFF_SYMBOLS_0 = 288, TINFL_MAX_HUFF_SYMBOLS_1 = 32, TINFL_MAX_HUFF_SYMBOLS_2 = 19, TINFL_FAST_LOOKUP_BITS = 10, TINFL_FAST_LOOKUP_SIZE = 1 << TINFL_FAST_LOOKUP_BITS
};
typedef struct {
  MINI_uint8 m_code_size[TINFL_MAX_HUFF_SYMBOLS_0];
  MINI_int16 m_look_up[TINFL_FAST_LOOKUP_SIZE], m_tree[TINFL_MAX_HUFF_SYMBOLS_0 * 2];
} tinfl_huff_table;
#if MINI_HAS_64BIT_REGISTERS
#define TINFL_USE_64BIT_BITBUF 1
#endif
#if TINFL_USE_64BIT_BITBUF
typedef MINI_uint64 tinfl_bit_buf_t;
#define TINFL_BITBUF_SIZE (64)
#else
typedef MINI_uint32 tinfl_bit_buf_t;
#define TINFL_BITBUF_SIZE (32)
#endif
struct tinfl_decompressor_tag {
  MINI_uint32 m_state, m_num_bits, m_zhdr0, m_zhdr1, m_z_adler32, m_final, m_type, m_check_adler32, m_dist, m_counter, m_num_extra, m_table_sizes[TINFL_MAX_HUFF_TABLES];
  tinfl_bit_buf_t m_bit_buf;
  size_t m_dist_from_out_buf_start;
  tinfl_huff_table m_tables[TINFL_MAX_HUFF_TABLES];
  MINI_uint8 m_raw_header[4], m_len_codes[TINFL_MAX_HUFF_SYMBOLS_0 + TINFL_MAX_HUFF_SYMBOLS_1 + 137];
};
#define TDEFL_LESS_MEMORY 0
enum {
  TDEFL_HUFFMAN_ONLY = 0, TDEFL_DEFAULT_MAX_PROBES = 128, TDEFL_MAX_PROBES_MASK = 0xFFF
};
enum {
  TDEFL_WRITE_ZLIB_HEADER = 0x01000, TDEFL_COMPUTE_ADLER32 = 0x02000, TDEFL_GREEDY_PARSING_FLAG = 0x04000, TDEFL_NONDETERMINISTIC_PARSING_FLAG = 0x08000, TDEFL_RLE_MATCHES = 0x10000, TDEFL_FILTER_MATCHES = 0x20000, TDEFL_FORCE_ALL_STATIC_BLOCKS = 0x40000, TDEFL_FORCE_ALL_RAW_BLOCKS = 0x80000
};
void *tdefl_compress_mem_to_heap(const void *pSrc_buf, size_t src_buf_len, size_t *pOut_len, int flags);
size_t tdefl_compress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len, int flags);
void *tdefl_write_image_to_png_file_in_memory_ex(const void *pImage, int w, int h, int num_chans, size_t *pLen_out, MINI_uint level, MINI_bool flip);
void *tdefl_write_image_to_png_file_in_memory(const void *pImage, int w, int h, int num_chans, size_t *pLen_out);
typedef MINI_bool (*tdefl_put_buf_func_ptr)(const void *pBuf, int len, void *pUser);
MINI_bool tdefl_compress_mem_to_output(const void *pBuf, size_t buf_len, tdefl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags);
enum {
  TDEFL_MAX_HUFF_TABLES = 3, TDEFL_MAX_HUFF_SYMBOLS_0 = 288, TDEFL_MAX_HUFF_SYMBOLS_1 = 32, TDEFL_MAX_HUFF_SYMBOLS_2 = 19, TDEFL_LZ_DICT_SIZE = 32768, TDEFL_LZ_DICT_SIZE_MASK = TDEFL_LZ_DICT_SIZE - 1, TDEFL_MIN_MATCH_LEN = 3, TDEFL_MAX_MATCH_LEN = 258
};
#if TDEFL_LESS_MEMORY
enum {
  TDEFL_LZ_CODE_BUF_SIZE = 24 * 1024, TDEFL_OUT_BUF_SIZE = (TDEFL_LZ_CODE_BUF_SIZE * 13) / 10, TDEFL_MAX_HUFF_SYMBOLS = 288, TDEFL_LZ_HASH_BITS = 12, TDEFL_LEVEL1_HASH_SIZE_MASK = 4095, TDEFL_LZ_HASH_SHIFT = (TDEFL_LZ_HASH_BITS + 2) / 3, TDEFL_LZ_HASH_SIZE = 1 << TDEFL_LZ_HASH_BITS
};
#else
enum {
  TDEFL_LZ_CODE_BUF_SIZE = 64 * 1024, TDEFL_OUT_BUF_SIZE = (TDEFL_LZ_CODE_BUF_SIZE * 13) / 10, TDEFL_MAX_HUFF_SYMBOLS = 288, TDEFL_LZ_HASH_BITS = 15, TDEFL_LEVEL1_HASH_SIZE_MASK = 4095, TDEFL_LZ_HASH_SHIFT = (TDEFL_LZ_HASH_BITS + 2) / 3, TDEFL_LZ_HASH_SIZE = 1 << TDEFL_LZ_HASH_BITS
};
#endif
typedef enum {
  TDEFL_STATUS_BAD_PARAM = -2, TDEFL_STATUS_PUT_BUF_FAILED = -1, TDEFL_STATUS_OKAY = 0, TDEFL_STATUS_DONE = 1,
} tdefl_status;
typedef enum {
  TDEFL_NO_FLUSH = 0, TDEFL_SYNC_FLUSH = 2, TDEFL_FULL_FLUSH = 3, TDEFL_FINISH = 4
} tdefl_flush;
typedef struct {
  tdefl_put_buf_func_ptr m_pPut_buf_func;
  void *m_pPut_buf_user;
  MINI_uint m_flags, m_max_probes[2];
  int m_greedy_parsing;
  MINI_uint m_adler32, m_lookahead_pos, m_lookahead_size, m_dict_size;
  MINI_uint8 *m_pLZ_code_buf, *m_pLZ_flags, *m_pOutput_buf, *m_pOutput_buf_end;
  MINI_uint m_num_flags_left, m_total_lz_bytes, m_lz_code_buf_dict_pos, m_bits_in, m_bit_buffer;
  MINI_uint m_saved_match_dist, m_saved_match_len, m_saved_lit, m_output_flush_ofs, m_output_flush_remaining, m_finished, m_block_index, m_wants_to_finish;
  tdefl_status m_prev_return_status;
  const void *m_pIn_buf;
  void *m_pOut_buf;
  size_t *m_pIn_buf_size, *m_pOut_buf_size;
  tdefl_flush m_flush;
  const MINI_uint8 *m_pSrc;
  size_t m_src_buf_left, m_out_buf_ofs;
  MINI_uint8 m_dict[TDEFL_LZ_DICT_SIZE + TDEFL_MAX_MATCH_LEN - 1];
  MINI_uint16 m_huff_count[TDEFL_MAX_HUFF_TABLES][TDEFL_MAX_HUFF_SYMBOLS];
  MINI_uint16 m_huff_codes[TDEFL_MAX_HUFF_TABLES][TDEFL_MAX_HUFF_SYMBOLS];
  MINI_uint8 m_huff_code_sizes[TDEFL_MAX_HUFF_TABLES][TDEFL_MAX_HUFF_SYMBOLS];
  MINI_uint8 m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE];
  MINI_uint16 m_next[TDEFL_LZ_DICT_SIZE];
  MINI_uint16 m_hash[TDEFL_LZ_HASH_SIZE];
  MINI_uint8 m_output_buf[TDEFL_OUT_BUF_SIZE];
} tdefl_compressor;
tdefl_status tdefl_init(tdefl_compressor *d, tdefl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags);
tdefl_status tdefl_compress(tdefl_compressor *d, const void *pIn_buf, size_t *pIn_buf_size, void *pOut_buf, size_t *pOut_buf_size, tdefl_flush flush);
tdefl_status tdefl_compress_buffer(tdefl_compressor *d, const void *pIn_buf, size_t in_buf_size, tdefl_flush flush);
tdefl_status tdefl_get_prev_return_status(tdefl_compressor *d);
MINI_uint32 tdefl_get_adler32(tdefl_compressor *d);
#ifndef MINI_NO_ZLIB_APIS
MINI_uint tdefl_create_comp_flags_from_zip_params(int level, int window_bits, int strategy);
#endif
tdefl_compressor *tdefl_compressor_alloc();
void tdefl_compressor_free(tdefl_compressor *pComp);
tinfl_decompressor *tinfl_decompressor_alloc();
void tinfl_decompressor_free(tinfl_decompressor *pDecomp);
#ifdef __cplusplus
}
#endif
#endif
#ifndef MINI_HEADER_FILE_ONLY
typedef unsigned char MINI_validate_uint16[sizeof(MINI_uint16) == 2 ? 1 : -1];
typedef unsigned char MINI_validate_uint32[sizeof(MINI_uint32) == 4 ? 1 : -1];
typedef unsigned char MINI_validate_uint64[sizeof(MINI_uint64) == 8 ? 1 : -1];
#include <assert.h>
#include <string.h>
#define MINI_ASSERT(x) assert(x)
#ifdef MINI_NO_MALLOC
#define MINI_MALLOC(x) NULL
#define MINI_FREE(x) (void)x, ((void)0)
#define MINI_REALLOC(p, x) NULL
#else
#define MINI_MALLOC(x) malloc(x)
#define MINI_FREE(x) free(x)
#define MINI_REALLOC(p, x) realloc(p, x)
#endif
#define MINI_MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MINI_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MINI_CLEAR_OBJ(obj) memset(&(obj), 0, sizeof(obj))
#if MINI_USE_UNALIGNED_LOADS_AND_STORES && MINI_LITTLE_ENDIAN
#define MINI_READ_LE16(p) *((const MINI_uint16 *)(p))
#define MINI_READ_LE32(p) *((const MINI_uint32 *)(p))
#else
#define MINI_READ_LE16(p)                                                        \
  ((MINI_uint32)(((const MINI_uint8 *)(p))[0]) |                                   \
   ((MINI_uint32)(((const MINI_uint8 *)(p))[1]) << 8U))
#define MINI_READ_LE32(p)                                                        \
  ((MINI_uint32)(((const MINI_uint8 *)(p))[0]) |                                   \
   ((MINI_uint32)(((const MINI_uint8 *)(p))[1]) << 8U) |                           \
   ((MINI_uint32)(((const MINI_uint8 *)(p))[2]) << 16U) |                          \
   ((MINI_uint32)(((const MINI_uint8 *)(p))[3]) << 24U))
#endif
#ifdef _MSC_VER
#define MINI_FORCEINLINE __forceinline
#elif defined(__GNUC__)
#define MINI_FORCEINLINE inline __attribute__((__always_inline__))
#else
#define MINI_FORCEINLINE inline
#endif
#ifdef __cplusplus
extern "C" {
#endif
MINI_ulong MINI_adler32(MINI_ulong adler, const unsigned char *ptr, size_t buf_len) {
  MINI_uint32 i, s1 = (MINI_uint32)(adler & 0xffff), s2 = (MINI_uint32)(adler >> 16);
  size_t block_len = buf_len % 5552;
  if (!ptr)
    return MINI_ADLER32_INIT;
  while (buf_len) {
    for (i = 0; i + 7 < block_len; i += 8, ptr += 8) {
      s1 += ptr[0], s2 += s1;
      s1 += ptr[1], s2 += s1;
      s1 += ptr[2], s2 += s1;
      s1 += ptr[3], s2 += s1;
      s1 += ptr[4], s2 += s1;
      s1 += ptr[5], s2 += s1;
      s1 += ptr[6], s2 += s1;
      s1 += ptr[7], s2 += s1;
    }
    for (; i < block_len; ++i)
      s1 += *ptr++, s2 += s1;
    s1 %= 65521U, s2 %= 65521U;
    buf_len -= block_len;
    block_len = 5552;
  }
  return (s2 << 16) + s1;
}
MINI_ulong MINI_crc32(MINI_ulong crc, const MINI_uint8 *ptr, size_t buf_len) {
  static const MINI_uint32 s_crc32[16] = {
      0,          0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c, 0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c};
  MINI_uint32 crcu32 = (MINI_uint32)crc;
  if (!ptr)
    return MINI_CRC32_INIT;
  crcu32 = ~crcu32;
  while (buf_len--) {
    MINI_uint8 b = *ptr++;
    crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b & 0xF)];
    crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b >> 4)];
  }
  return ~crcu32;
}
void MINI_free(void *p) { MINI_FREE(p); }
#ifndef MINI_NO_ZLIB_APIS
static void *def_alloc_func(void *opaque, size_t items, size_t size) {
  (void)opaque, (void)items, (void)size;
  return MINI_MALLOC(items * size);
}
static void def_free_func(void *opaque, void *address) {
  (void)opaque, (void)address;
  MINI_FREE(address);
}
static void *def_realloc_func(void *opaque, void *address, size_t items, size_t size) {
  (void)opaque, (void)address, (void)items, (void)size;
  return MINI_REALLOC(address, items * size);
}
const char *MINI_version(void) { return MINI_VERSION; }
int MINI_deflateInit(MINI_streamp pStream, int level) {
  return MINI_deflateInit2(pStream, level, MINI_DEFLATED, MINI_DEFAULT_WINDOW_BITS, 9, MINI_DEFAULT_STRATEGY);
}
int MINI_deflateInit2(MINI_streamp pStream, int level, int method, int window_bits, int mem_level, int strategy) {
  tdefl_compressor *pComp;
  MINI_uint comp_flags = TDEFL_COMPUTE_ADLER32 |
      tdefl_create_comp_flags_from_zip_params(level, window_bits, strategy);
  if (!pStream)
    return MINI_STREAM_ERROR;
  if ((method != MINI_DEFLATED) || ((mem_level < 1) || (mem_level > 9)) ||
      ((window_bits != MINI_DEFAULT_WINDOW_BITS) &&
       (-window_bits != MINI_DEFAULT_WINDOW_BITS)))
    return MINI_PARAM_ERROR;
  pStream->data_type = 0;
  pStream->adler = MINI_ADLER32_INIT;
  pStream->msg = NULL;
  pStream->reserved = 0;
  pStream->total_in = 0;
  pStream->total_out = 0;
  if (!pStream->zalloc)
    pStream->zalloc = def_alloc_func;
  if (!pStream->zfree)
    pStream->zfree = def_free_func;
  pComp = (tdefl_compressor *)pStream->zalloc(pStream->opaque, 1, sizeof(tdefl_compressor));
  if (!pComp)
    return MINI_MEM_ERROR;
  pStream->state = (struct MINI_internal_state *)pComp;
  if (tdefl_init(pComp, NULL, NULL, comp_flags) != TDEFL_STATUS_OKAY) {
    MINI_deflateEnd(pStream);
    return MINI_PARAM_ERROR;
  }
  return MINI_OK;
}
int MINI_deflateReset(MINI_streamp pStream) {
  if ((!pStream) || (!pStream->state) || (!pStream->zalloc) ||
      (!pStream->zfree))
    return MINI_STREAM_ERROR;
  pStream->total_in = pStream->total_out = 0;
  tdefl_init((tdefl_compressor *)pStream->state, NULL, NULL, ((tdefl_compressor *)pStream->state)->m_flags);
  return MINI_OK;
}
int MINI_deflate(MINI_streamp pStream, int flush) {
  size_t in_bytes, out_bytes;
  MINI_ulong orig_total_in, orig_total_out;
  int MINI_status = MINI_OK;
  if ((!pStream) || (!pStream->state) || (flush < 0) || (flush > MINI_FINISH) ||
      (!pStream->next_out))
    return MINI_STREAM_ERROR;
  if (!pStream->avail_out)
    return MINI_BUF_ERROR;
  if (flush == MINI_PARTIAL_FLUSH)
    flush = MINI_SYNC_FLUSH;
  if (((tdefl_compressor *)pStream->state)->m_prev_return_status == TDEFL_STATUS_DONE)
    return (flush == MINI_FINISH) ? MINI_STREAM_END : MINI_BUF_ERROR;
  orig_total_in = pStream->total_in;
  orig_total_out = pStream->total_out;
  for (;;) {
    tdefl_status defl_status;
    in_bytes = pStream->avail_in;
    out_bytes = pStream->avail_out;
    defl_status = tdefl_compress((tdefl_compressor *)pStream->state, pStream->next_in, &in_bytes, pStream->next_out, &out_bytes, (tdefl_flush)flush);
    pStream->next_in += (MINI_uint)in_bytes;
    pStream->avail_in -= (MINI_uint)in_bytes;
    pStream->total_in += (MINI_uint)in_bytes;
    pStream->adler = tdefl_get_adler32((tdefl_compressor *)pStream->state);
    pStream->next_out += (MINI_uint)out_bytes;
    pStream->avail_out -= (MINI_uint)out_bytes;
    pStream->total_out += (MINI_uint)out_bytes;
    if (defl_status < 0) {
      MINI_status = MINI_STREAM_ERROR;
      break;
    } else if (defl_status == TDEFL_STATUS_DONE) {
      MINI_status = MINI_STREAM_END;
      break;
    } else if (!pStream->avail_out)
      break;
    else if ((!pStream->avail_in) && (flush != MINI_FINISH)) {
      if ((flush) || (pStream->total_in != orig_total_in) ||
          (pStream->total_out != orig_total_out))
        break;
      return MINI_BUF_ERROR;
    }
  }
  return MINI_status;
}
int MINI_deflateEnd(MINI_streamp pStream) {
  if (!pStream)
    return MINI_STREAM_ERROR;
  if (pStream->state) {
    pStream->zfree(pStream->opaque, pStream->state);
    pStream->state = NULL;
  }
  return MINI_OK;
}
MINI_ulong MINI_deflateBound(MINI_streamp pStream, MINI_ulong source_len) {
  (void)pStream;
  return MINI_MAX(128 + (source_len * 110) / 100, 128 + source_len + ((source_len / (31 * 1024)) + 1) * 5);
}
int MINI_compress2(unsigned char *pDest, MINI_ulong *pDest_len, const unsigned char *pSource, MINI_ulong source_len, int level) {
  int status;
  MINI_stream stream;
  memset(&stream, 0, sizeof(stream));
  if ((source_len | *pDest_len) > 0xFFFFFFFFU)
    return MINI_PARAM_ERROR;
  stream.next_in = pSource;
  stream.avail_in = (MINI_uint32)source_len;
  stream.next_out = pDest;
  stream.avail_out = (MINI_uint32)*pDest_len;
  status = MINI_deflateInit(&stream, level);
  if (status != MINI_OK)
    return status;
  status = MINI_deflate(&stream, MINI_FINISH);
  if (status != MINI_STREAM_END) {
    MINI_deflateEnd(&stream);
    return (status == MINI_OK) ? MINI_BUF_ERROR : status;
  }
  *pDest_len = stream.total_out;
  return MINI_deflateEnd(&stream);
}
int MINI_compress(unsigned char *pDest, MINI_ulong *pDest_len, const unsigned char *pSource, MINI_ulong source_len) {
  return MINI_compress2(pDest, pDest_len, pSource, source_len, MINI_DEFAULT_COMPRESSION);
}
MINI_ulong MINI_compressBound(MINI_ulong source_len) {
  return MINI_deflateBound(NULL, source_len);
}
typedef struct {
  tinfl_decompressor m_decomp;
  MINI_uint m_dict_ofs, m_dict_avail, m_first_call, m_has_flushed;
  int m_window_bits;
  MINI_uint8 m_dict[TINFL_LZ_DICT_SIZE];
  tinfl_status m_last_status;
} inflate_state;
int MINI_inflateInit2(MINI_streamp pStream, int window_bits) {
  inflate_state *pDecomp;
  if (!pStream)
    return MINI_STREAM_ERROR;
  if ((window_bits != MINI_DEFAULT_WINDOW_BITS) &&
      (-window_bits != MINI_DEFAULT_WINDOW_BITS))
    return MINI_PARAM_ERROR;
  pStream->data_type = 0;
  pStream->adler = 0;
  pStream->msg = NULL;
  pStream->total_in = 0;
  pStream->total_out = 0;
  pStream->reserved = 0;
  if (!pStream->zalloc)
    pStream->zalloc = def_alloc_func;
  if (!pStream->zfree)
    pStream->zfree = def_free_func;
  pDecomp = (inflate_state *)pStream->zalloc(pStream->opaque, 1, sizeof(inflate_state));
  if (!pDecomp)
    return MINI_MEM_ERROR;
  pStream->state = (struct MINI_internal_state *)pDecomp;
  tinfl_init(&pDecomp->m_decomp);
  pDecomp->m_dict_ofs = 0;
  pDecomp->m_dict_avail = 0;
  pDecomp->m_last_status = TINFL_STATUS_NEEDS_MORE_INPUT;
  pDecomp->m_first_call = 1;
  pDecomp->m_has_flushed = 0;
  pDecomp->m_window_bits = window_bits;
  return MINI_OK;
}
int MINI_inflateInit(MINI_streamp pStream) {
  return MINI_inflateInit2(pStream, MINI_DEFAULT_WINDOW_BITS);
}
int MINI_inflate(MINI_streamp pStream, int flush) {
  inflate_state *pState;
  MINI_uint n, first_call, decomp_flags = TINFL_FLAG_COMPUTE_ADLER32;
  size_t in_bytes, out_bytes, orig_avail_in;
  tinfl_status status;
  if ((!pStream) || (!pStream->state))
    return MINI_STREAM_ERROR;
  if (flush == MINI_PARTIAL_FLUSH)
    flush = MINI_SYNC_FLUSH;
  if ((flush) && (flush != MINI_SYNC_FLUSH) && (flush != MINI_FINISH))
    return MINI_STREAM_ERROR;
  pState = (inflate_state *)pStream->state;
  if (pState->m_window_bits > 0)
    decomp_flags |= TINFL_FLAG_PARSE_ZLIB_HEADER;
  orig_avail_in = pStream->avail_in;
  first_call = pState->m_first_call;
  pState->m_first_call = 0;
  if (pState->m_last_status < 0)
    return MINI_DATA_ERROR;
  if (pState->m_has_flushed && (flush != MINI_FINISH))
    return MINI_STREAM_ERROR;
  pState->m_has_flushed |= (flush == MINI_FINISH);
  if ((flush == MINI_FINISH) && (first_call)) {
    decomp_flags |= TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    in_bytes = pStream->avail_in;
    out_bytes = pStream->avail_out;
    status = tinfl_decompress(&pState->m_decomp, pStream->next_in, &in_bytes, pStream->next_out, pStream->next_out, &out_bytes, decomp_flags);
    pState->m_last_status = status;
    pStream->next_in += (MINI_uint)in_bytes;
    pStream->avail_in -= (MINI_uint)in_bytes;
    pStream->total_in += (MINI_uint)in_bytes;
    pStream->adler = tinfl_get_adler32(&pState->m_decomp);
    pStream->next_out += (MINI_uint)out_bytes;
    pStream->avail_out -= (MINI_uint)out_bytes;
    pStream->total_out += (MINI_uint)out_bytes;
    if (status < 0)
      return MINI_DATA_ERROR;
    else if (status != TINFL_STATUS_DONE) {
      pState->m_last_status = TINFL_STATUS_FAILED;
      return MINI_BUF_ERROR;
    }
    return MINI_STREAM_END;
  }
  if (flush != MINI_FINISH)
    decomp_flags |= TINFL_FLAG_HAS_MORE_INPUT;
  if (pState->m_dict_avail) {
    n = MINI_MIN(pState->m_dict_avail, pStream->avail_out);
    memcpy(pStream->next_out, pState->m_dict + pState->m_dict_ofs, n);
    pStream->next_out += n;
    pStream->avail_out -= n;
    pStream->total_out += n;
    pState->m_dict_avail -= n;
    pState->m_dict_ofs = (pState->m_dict_ofs + n) & (TINFL_LZ_DICT_SIZE - 1);
    return ((pState->m_last_status == TINFL_STATUS_DONE) &&
            (!pState->m_dict_avail))
               ? MINI_STREAM_END
               : MINI_OK;
  }
  for (;;) {
    in_bytes = pStream->avail_in;
    out_bytes = TINFL_LZ_DICT_SIZE - pState->m_dict_ofs;
    status = tinfl_decompress(
        &pState->m_decomp, pStream->next_in, &in_bytes, pState->m_dict, pState->m_dict + pState->m_dict_ofs, &out_bytes, decomp_flags);
    pState->m_last_status = status;
    pStream->next_in += (MINI_uint)in_bytes;
    pStream->avail_in -= (MINI_uint)in_bytes;
    pStream->total_in += (MINI_uint)in_bytes;
    pStream->adler = tinfl_get_adler32(&pState->m_decomp);
    pState->m_dict_avail = (MINI_uint)out_bytes;
    n = MINI_MIN(pState->m_dict_avail, pStream->avail_out);
    memcpy(pStream->next_out, pState->m_dict + pState->m_dict_ofs, n);
    pStream->next_out += n;
    pStream->avail_out -= n;
    pStream->total_out += n;
    pState->m_dict_avail -= n;
    pState->m_dict_ofs = (pState->m_dict_ofs + n) & (TINFL_LZ_DICT_SIZE - 1);
    if (status < 0)
      return MINI_DATA_ERROR;
    else if ((status == TINFL_STATUS_NEEDS_MORE_INPUT) && (!orig_avail_in))
      return MINI_BUF_ERROR;
    else if (flush == MINI_FINISH) {
      if (status == TINFL_STATUS_DONE)
        return pState->m_dict_avail ? MINI_BUF_ERROR : MINI_STREAM_END;
      else if (!pStream->avail_out)
        return MINI_BUF_ERROR;
    } else if ((status == TINFL_STATUS_DONE) || (!pStream->avail_in) ||
               (!pStream->avail_out) || (pState->m_dict_avail))
      break;
  }
  return ((status == TINFL_STATUS_DONE) && (!pState->m_dict_avail))
             ? MINI_STREAM_END
             : MINI_OK;
}
int MINI_inflateEnd(MINI_streamp pStream) {
  if (!pStream)
    return MINI_STREAM_ERROR;
  if (pStream->state) {
    pStream->zfree(pStream->opaque, pStream->state);
    pStream->state = NULL;
  }
  return MINI_OK;
}
int MINI_uncompress(unsigned char *pDest, MINI_ulong *pDest_len, const unsigned char *pSource, MINI_ulong source_len) {
  MINI_stream stream;
  int status;
  memset(&stream, 0, sizeof(stream));
  if ((source_len | *pDest_len) > 0xFFFFFFFFU)
    return MINI_PARAM_ERROR;
  stream.next_in = pSource;
  stream.avail_in = (MINI_uint32)source_len;
  stream.next_out = pDest;
  stream.avail_out = (MINI_uint32)*pDest_len;
  status = MINI_inflateInit(&stream);
  if (status != MINI_OK)
    return status;
  status = MINI_inflate(&stream, MINI_FINISH);
  if (status != MINI_STREAM_END) {
    MINI_inflateEnd(&stream);
    return ((status == MINI_BUF_ERROR) && (!stream.avail_in)) ? MINI_DATA_ERROR
                                                            : status;
  }
  *pDest_len = stream.total_out;
  return MINI_inflateEnd(&stream);
}
const char *MINI_error(int err) {
  static struct {
    int m_err;
    const char *m_pDesc;
  } s_error_descs[] = {{MINI_OK, ""}, {MINI_STREAM_END, "stream end"}, {MINI_NEED_DICT, "need dictionary"}, {MINI_ERRNO, "file error"}, {MINI_STREAM_ERROR, "stream error"}, {MINI_DATA_ERROR, "data error"}, {MINI_MEM_ERROR, "out of memory"}, {MINI_BUF_ERROR, "buf error"}, {MINI_VERSION_ERROR, "version error"}, {MINI_PARAM_ERROR, "parameter error"}};
  MINI_uint i;
  for (i = 0; i < sizeof(s_error_descs) / sizeof(s_error_descs[0]); ++i)
    if (s_error_descs[i].m_err == err)
      return s_error_descs[i].m_pDesc;
  return NULL;
}
#endif
#define TINFL_MEMCPY(d, s, l) memcpy(d, s, l)
#define TINFL_MEMSET(p, c, l) memset(p, c, l)
#define TINFL_CR_BEGIN                                                         \
  switch (r->m_state) {                                                        \
  case 0:
#define TINFL_CR_RETURN(state_index, result)                                   \
  do {                                                                         \
    status = result;                                                           \
    r->m_state = state_index;                                                  \
    goto common_exit;                                                          \
  case state_index:;                                                           \
  }                                                                            \
  MINI_MACRO_END
#define TINFL_CR_RETURN_FOREVER(state_index, result)                           \
  do {                                                                         \
    for (;;) {                                                                 \
      TINFL_CR_RETURN(state_index, result);                                    \
    }                                                                          \
  }                                                                            \
  MINI_MACRO_END
#define TINFL_CR_FINISH }
#define TINFL_GET_BYTE(state_index, c)                                         \
  do {                                                                         \
    while (pIn_buf_cur >= pIn_buf_end) {                                       \
      TINFL_CR_RETURN(state_index,                                             \
                      (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT)               \
                          ? TINFL_STATUS_NEEDS_MORE_INPUT                      \
                          : TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS);         \
    }                                                                          \
    c = *pIn_buf_cur++;                                                        \
  }                                                                            \
  MINI_MACRO_END
#define TINFL_NEED_BITS(state_index, n)                                        \
  do {                                                                         \
    MINI_uint c;                                                                 \
    TINFL_GET_BYTE(state_index, c);                                            \
    bit_buf |= (((tinfl_bit_buf_t)c) << num_bits);                             \
    num_bits += 8;                                                             \
  } while (num_bits < (MINI_uint)(n))
#define TINFL_SKIP_BITS(state_index, n)                                        \
  do {                                                                         \
    if (num_bits < (MINI_uint)(n)) {                                             \
      TINFL_NEED_BITS(state_index, n);                                         \
    }                                                                          \
    bit_buf >>= (n);                                                           \
    num_bits -= (n);                                                           \
  }                                                                            \
  MINI_MACRO_END
#define TINFL_GET_BITS(state_index, b, n)                                      \
  do {                                                                         \
    if (num_bits < (MINI_uint)(n)) {                                             \
      TINFL_NEED_BITS(state_index, n);                                         \
    }                                                                          \
    b = bit_buf & ((1 << (n)) - 1);                                            \
    bit_buf >>= (n);                                                           \
    num_bits -= (n);                                                           \
  }                                                                            \
  MINI_MACRO_END
#define TINFL_HUFF_BITBUF_FILL(state_index, pHuff)                             \
  do {                                                                         \
    temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)];         \
    if (temp >= 0) {                                                           \
      code_len = temp >> 9;                                                    \
      if ((code_len) && (num_bits >= code_len))                                \
        break;                                                                 \
    } else if (num_bits > TINFL_FAST_LOOKUP_BITS) {                            \
      code_len = TINFL_FAST_LOOKUP_BITS;                                       \
      do {                                                                     \
        temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)];         \
      } while ((temp < 0) && (num_bits >= (code_len + 1)));                    \
      if (temp >= 0)                                                           \
        break;                                                                 \
    }                                                                          \
    TINFL_GET_BYTE(state_index, c);                                            \
    bit_buf |= (((tinfl_bit_buf_t)c) << num_bits);                             \
    num_bits += 8;                                                             \
  } while (num_bits < 15);
#define TINFL_HUFF_DECODE(state_index, sym, pHuff)                             \
  do {                                                                         \
    int temp;                                                                  \
    MINI_uint code_len, c;                                                       \
    if (num_bits < 15) {                                                       \
      if ((pIn_buf_end - pIn_buf_cur) < 2) {                                   \
        TINFL_HUFF_BITBUF_FILL(state_index, pHuff);                            \
      } else {                                                                 \
        bit_buf |= (((tinfl_bit_buf_t)pIn_buf_cur[0]) << num_bits) |           \
                   (((tinfl_bit_buf_t)pIn_buf_cur[1]) << (num_bits + 8));      \
        pIn_buf_cur += 2;                                                      \
        num_bits += 16;                                                        \
      }                                                                        \
    }                                                                          \
    if ((temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= \
        0)                                                                     \
      code_len = temp >> 9, temp &= 511;                                       \
    else {                                                                     \
      code_len = TINFL_FAST_LOOKUP_BITS;                                       \
      do {                                                                     \
        temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)];         \
      } while (temp < 0);                                                      \
    }                                                                          \
    sym = temp;                                                                \
    bit_buf >>= code_len;                                                      \
    num_bits -= code_len;                                                      \
  }                                                                            \
  MINI_MACRO_END
tinfl_status tinfl_decompress(tinfl_decompressor *r, const MINI_uint8 *pIn_buf_next, size_t *pIn_buf_size, MINI_uint8 *pOut_buf_start, MINI_uint8 *pOut_buf_next, size_t *pOut_buf_size, const MINI_uint32 decomp_flags) {
  static const int s_length_base[31] = {
      3,  4,  5,  6,  7,  8,  9,  10,  11,  13,  15,  17,  19,  23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0,  0};
  static const int s_length_extra[31] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0};
  static const int s_dist_base[32] = {
      1,    2,    3,    4,    5,    7,     9,     13,    17,  25,   33, 49,   65,   97,   129,  193,  257,   385,   513,   769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0,   0};
  static const int s_dist_extra[32] = {0, 0, 0,  0,  1,  1,  2,  2,  3,  3, 4, 4, 5,  5,  6,  6,  7,  7,  8,  8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
  static const MINI_uint8 s_length_dezigzag[19] = {
      16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
  static const int s_min_table_sizes[3] = {257, 1, 4};
  tinfl_status status = TINFL_STATUS_FAILED;
  MINI_uint32 num_bits, dist, counter, num_extra;
  tinfl_bit_buf_t bit_buf;
  const MINI_uint8 *pIn_buf_cur = pIn_buf_next, *const pIn_buf_end = pIn_buf_next + *pIn_buf_size;
  MINI_uint8 *pOut_buf_cur = pOut_buf_next, *const pOut_buf_end = pOut_buf_next + *pOut_buf_size;
  size_t out_buf_size_mask = (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF)
                 ? (size_t)-1
                 : ((pOut_buf_next - pOut_buf_start) + *pOut_buf_size) - 1, dist_from_out_buf_start;
  if (((out_buf_size_mask + 1) & out_buf_size_mask) ||
      (pOut_buf_next < pOut_buf_start)) {
    *pIn_buf_size = *pOut_buf_size = 0;
    return TINFL_STATUS_BAD_PARAM;
  }
  num_bits = r->m_num_bits;
  bit_buf = r->m_bit_buf;
  dist = r->m_dist;
  counter = r->m_counter;
  num_extra = r->m_num_extra;
  dist_from_out_buf_start = r->m_dist_from_out_buf_start;
  TINFL_CR_BEGIN
  bit_buf = num_bits = dist = counter = num_extra = r->m_zhdr0 = r->m_zhdr1 = 0;
  r->m_z_adler32 = r->m_check_adler32 = 1;
  if (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER) {
    TINFL_GET_BYTE(1, r->m_zhdr0);
    TINFL_GET_BYTE(2, r->m_zhdr1);
    counter = (((r->m_zhdr0 * 256 + r->m_zhdr1) % 31 != 0) ||
               (r->m_zhdr1 & 32) || ((r->m_zhdr0 & 15) != 8));
    if (!(decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF))
      counter |= (((1U << (8U + (r->m_zhdr0 >> 4))) > 32768U) ||
                  ((out_buf_size_mask + 1) <
                   (size_t)(1U << (8U + (r->m_zhdr0 >> 4)))));
    if (counter) {
      TINFL_CR_RETURN_FOREVER(36, TINFL_STATUS_FAILED);
    }
  }
  do {
    TINFL_GET_BITS(3, r->m_final, 3);
    r->m_type = r->m_final >> 1;
    if (r->m_type == 0) {
      TINFL_SKIP_BITS(5, num_bits & 7);
      for (counter = 0; counter < 4; ++counter) {
        if (num_bits)
          TINFL_GET_BITS(6, r->m_raw_header[counter], 8);
        else
          TINFL_GET_BYTE(7, r->m_raw_header[counter]);
      }
      if ((counter = (r->m_raw_header[0] | (r->m_raw_header[1] << 8))) != (MINI_uint)(0xFFFF ^
                    (r->m_raw_header[2] | (r->m_raw_header[3] << 8)))) {
        TINFL_CR_RETURN_FOREVER(39, TINFL_STATUS_FAILED);
      }
      while ((counter) && (num_bits)) {
        TINFL_GET_BITS(51, dist, 8);
        while (pOut_buf_cur >= pOut_buf_end) {
          TINFL_CR_RETURN(52, TINFL_STATUS_HAS_MORE_OUTPUT);
        }
        *pOut_buf_cur++ = (MINI_uint8)dist;
        counter--;
      }
      while (counter) {
        size_t n;
        while (pOut_buf_cur >= pOut_buf_end) {
          TINFL_CR_RETURN(9, TINFL_STATUS_HAS_MORE_OUTPUT);
        }
        while (pIn_buf_cur >= pIn_buf_end) {
          TINFL_CR_RETURN(38, (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT)
                                  ? TINFL_STATUS_NEEDS_MORE_INPUT
                                  : TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS);
        }
        n = MINI_MIN(MINI_MIN((size_t)(pOut_buf_end - pOut_buf_cur), (size_t)(pIn_buf_end - pIn_buf_cur)), counter);
        TINFL_MEMCPY(pOut_buf_cur, pIn_buf_cur, n);
        pIn_buf_cur += n;
        pOut_buf_cur += n;
        counter -= (MINI_uint)n;
      }
    } else if (r->m_type == 3) {
      TINFL_CR_RETURN_FOREVER(10, TINFL_STATUS_FAILED);
    } else {
      if (r->m_type == 1) {
        MINI_uint8 *p = r->m_tables[0].m_code_size;
        MINI_uint i;
        r->m_table_sizes[0] = 288;
        r->m_table_sizes[1] = 32;
        TINFL_MEMSET(r->m_tables[1].m_code_size, 5, 32);
        for (i = 0; i <= 143; ++i)
          *p++ = 8;
        for (; i <= 255; ++i)
          *p++ = 9;
        for (; i <= 279; ++i)
          *p++ = 7;
        for (; i <= 287; ++i)
          *p++ = 8;
      } else {
        for (counter = 0; counter < 3; counter++) {
          TINFL_GET_BITS(11, r->m_table_sizes[counter], "\05\05\04"[counter]);
          r->m_table_sizes[counter] += s_min_table_sizes[counter];
        }
        MINI_CLEAR_OBJ(r->m_tables[2].m_code_size);
        for (counter = 0; counter < r->m_table_sizes[2]; counter++) {
          MINI_uint s;
          TINFL_GET_BITS(14, s, 3);
          r->m_tables[2].m_code_size[s_length_dezigzag[counter]] = (MINI_uint8)s;
        }
        r->m_table_sizes[2] = 19;
      }
      for (; (int)r->m_type >= 0; r->m_type--) {
        int tree_next, tree_cur;
        tinfl_huff_table *pTable;
        MINI_uint i, j, used_syms, total, sym_index, next_code[17], total_syms[16];
        pTable = &r->m_tables[r->m_type];
        MINI_CLEAR_OBJ(total_syms);
        MINI_CLEAR_OBJ(pTable->m_look_up);
        MINI_CLEAR_OBJ(pTable->m_tree);
        for (i = 0; i < r->m_table_sizes[r->m_type]; ++i)
          total_syms[pTable->m_code_size[i]]++;
        used_syms = 0, total = 0;
        next_code[0] = next_code[1] = 0;
        for (i = 1; i <= 15; ++i) {
          used_syms += total_syms[i];
          next_code[i + 1] = (total = ((total + total_syms[i]) << 1));
        }
        if ((65536 != total) && (used_syms > 1)) {
          TINFL_CR_RETURN_FOREVER(35, TINFL_STATUS_FAILED);
        }
        for (tree_next = -1, sym_index = 0;
             sym_index < r->m_table_sizes[r->m_type]; ++sym_index) {
          MINI_uint rev_code = 0, l, cur_code, code_size = pTable->m_code_size[sym_index];
          if (!code_size)
            continue;
          cur_code = next_code[code_size]++;
          for (l = code_size; l > 0; l--, cur_code >>= 1)
            rev_code = (rev_code << 1) | (cur_code & 1);
          if (code_size <= TINFL_FAST_LOOKUP_BITS) {
            MINI_int16 k = (MINI_int16)((code_size << 9) | sym_index);
            while (rev_code < TINFL_FAST_LOOKUP_SIZE) {
              pTable->m_look_up[rev_code] = k;
              rev_code += (1 << code_size);
            }
            continue;
          }
          if (0 == (tree_cur = pTable->m_look_up[rev_code &
                                            (TINFL_FAST_LOOKUP_SIZE - 1)])) {
            pTable->m_look_up[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)] = (MINI_int16)tree_next;
            tree_cur = tree_next;
            tree_next -= 2;
          }
          rev_code >>= (TINFL_FAST_LOOKUP_BITS - 1);
          for (j = code_size; j > (TINFL_FAST_LOOKUP_BITS + 1); j--) {
            tree_cur -= ((rev_code >>= 1) & 1);
            if (!pTable->m_tree[-tree_cur - 1]) {
              pTable->m_tree[-tree_cur - 1] = (MINI_int16)tree_next;
              tree_cur = tree_next;
              tree_next -= 2;
            } else
              tree_cur = pTable->m_tree[-tree_cur - 1];
          }
          tree_cur -= ((rev_code >>= 1) & 1);
          pTable->m_tree[-tree_cur - 1] = (MINI_int16)sym_index;
        }
        if (r->m_type == 2) {
          for (counter = 0;
               counter < (r->m_table_sizes[0] + r->m_table_sizes[1]);) {
            MINI_uint s;
            TINFL_HUFF_DECODE(16, dist, &r->m_tables[2]);
            if (dist < 16) {
              r->m_len_codes[counter++] = (MINI_uint8)dist;
              continue;
            }
            if ((dist == 16) && (!counter)) {
              TINFL_CR_RETURN_FOREVER(17, TINFL_STATUS_FAILED);
            }
            num_extra = "\02\03\07"[dist - 16];
            TINFL_GET_BITS(18, s, num_extra);
            s += "\03\03\013"[dist - 16];
            TINFL_MEMSET(r->m_len_codes + counter, (dist == 16) ? r->m_len_codes[counter - 1] : 0, s);
            counter += s;
          }
          if ((r->m_table_sizes[0] + r->m_table_sizes[1]) != counter) {
            TINFL_CR_RETURN_FOREVER(21, TINFL_STATUS_FAILED);
          }
          TINFL_MEMCPY(r->m_tables[0].m_code_size, r->m_len_codes, r->m_table_sizes[0]);
          TINFL_MEMCPY(r->m_tables[1].m_code_size, r->m_len_codes + r->m_table_sizes[0], r->m_table_sizes[1]);
        }
      }
      for (;;) {
        MINI_uint8 *pSrc;
        for (;;) {
          if (((pIn_buf_end - pIn_buf_cur) < 4) ||
              ((pOut_buf_end - pOut_buf_cur) < 2)) {
            TINFL_HUFF_DECODE(23, counter, &r->m_tables[0]);
            if (counter >= 256)
              break;
            while (pOut_buf_cur >= pOut_buf_end) {
              TINFL_CR_RETURN(24, TINFL_STATUS_HAS_MORE_OUTPUT);
            }
            *pOut_buf_cur++ = (MINI_uint8)counter;
          } else {
            int sym2;
            MINI_uint code_len;
#if TINFL_USE_64BIT_BITBUF
            if (num_bits < 30) {
              bit_buf |= (((tinfl_bit_buf_t)MINI_READ_LE32(pIn_buf_cur)) << num_bits);
              pIn_buf_cur += 4;
              num_bits += 32;
            }
#else
            if (num_bits < 15) {
              bit_buf |= (((tinfl_bit_buf_t)MINI_READ_LE16(pIn_buf_cur)) << num_bits);
              pIn_buf_cur += 2;
              num_bits += 16;
            }
#endif
            if ((sym2 = r->m_tables[0]
                         .m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
              code_len = sym2 >> 9;
            else {
              code_len = TINFL_FAST_LOOKUP_BITS;
              do {
                sym2 = r->m_tables[0]
                           .m_tree[~sym2 + ((bit_buf >> code_len++) & 1)];
              } while (sym2 < 0);
            }
            counter = sym2;
            bit_buf >>= code_len;
            num_bits -= code_len;
            if (counter & 256)
              break;
#if !TINFL_USE_64BIT_BITBUF
            if (num_bits < 15) {
              bit_buf |= (((tinfl_bit_buf_t)MINI_READ_LE16(pIn_buf_cur)) << num_bits);
              pIn_buf_cur += 2;
              num_bits += 16;
            }
#endif
            if ((sym2 = r->m_tables[0]
                         .m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
              code_len = sym2 >> 9;
            else {
              code_len = TINFL_FAST_LOOKUP_BITS;
              do {
                sym2 = r->m_tables[0]
                           .m_tree[~sym2 + ((bit_buf >> code_len++) & 1)];
              } while (sym2 < 0);
            }
            bit_buf >>= code_len;
            num_bits -= code_len;
            pOut_buf_cur[0] = (MINI_uint8)counter;
            if (sym2 & 256) {
              pOut_buf_cur++;
              counter = sym2;
              break;
            }
            pOut_buf_cur[1] = (MINI_uint8)sym2;
            pOut_buf_cur += 2;
          }
        }
        if ((counter &= 511) == 256)
          break;
        num_extra = s_length_extra[counter - 257];
        counter = s_length_base[counter - 257];
        if (num_extra) {
          MINI_uint extra_bits;
          TINFL_GET_BITS(25, extra_bits, num_extra);
          counter += extra_bits;
        }
        TINFL_HUFF_DECODE(26, dist, &r->m_tables[1]);
        num_extra = s_dist_extra[dist];
        dist = s_dist_base[dist];
        if (num_extra) {
          MINI_uint extra_bits;
          TINFL_GET_BITS(27, extra_bits, num_extra);
          dist += extra_bits;
        }
        dist_from_out_buf_start = pOut_buf_cur - pOut_buf_start;
        if ((dist > dist_from_out_buf_start) &&
            (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF)) {
          TINFL_CR_RETURN_FOREVER(37, TINFL_STATUS_FAILED);
        }
        pSrc = pOut_buf_start +
               ((dist_from_out_buf_start - dist) & out_buf_size_mask);
        if ((MINI_MAX(pOut_buf_cur, pSrc) + counter) > pOut_buf_end) {
          while (counter--) {
            while (pOut_buf_cur >= pOut_buf_end) {
              TINFL_CR_RETURN(53, TINFL_STATUS_HAS_MORE_OUTPUT);
            }
            *pOut_buf_cur++ = pOut_buf_start[(dist_from_out_buf_start++ - dist) &
                               out_buf_size_mask];
          }
          continue;
        }
#if MINI_USE_UNALIGNED_LOADS_AND_STORES
        else if ((counter >= 9) && (counter <= dist)) {
          const MINI_uint8 *pSrc_end = pSrc + (counter & ~7);
          do {
            ((MINI_uint32 *)pOut_buf_cur)[0] = ((const MINI_uint32 *)pSrc)[0];
            ((MINI_uint32 *)pOut_buf_cur)[1] = ((const MINI_uint32 *)pSrc)[1];
            pOut_buf_cur += 8;
          } while ((pSrc += 8) < pSrc_end);
          if ((counter &= 7) < 3) {
            if (counter) {
              pOut_buf_cur[0] = pSrc[0];
              if (counter > 1)
                pOut_buf_cur[1] = pSrc[1];
              pOut_buf_cur += counter;
            }
            continue;
          }
        }
#endif
        do {
          pOut_buf_cur[0] = pSrc[0];
          pOut_buf_cur[1] = pSrc[1];
          pOut_buf_cur[2] = pSrc[2];
          pOut_buf_cur += 3;
          pSrc += 3;
        } while ((int)(counter -= 3) > 2);
        if ((int)counter > 0) {
          pOut_buf_cur[0] = pSrc[0];
          if ((int)counter > 1)
            pOut_buf_cur[1] = pSrc[1];
          pOut_buf_cur += counter;
        }
      }
    }
  } while (!(r->m_final & 1));
  TINFL_SKIP_BITS(32, num_bits & 7);
  while ((pIn_buf_cur > pIn_buf_next) && (num_bits >= 8)) {
    --pIn_buf_cur;
    num_bits -= 8;
  }
  bit_buf &= (tinfl_bit_buf_t)((1ULL << num_bits) - 1ULL);
  MINI_ASSERT(!num_bits);
  if (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER) {
    for (counter = 0; counter < 4; ++counter) {
      MINI_uint s;
      if (num_bits)
        TINFL_GET_BITS(41, s, 8);
      else
        TINFL_GET_BYTE(42, s);
      r->m_z_adler32 = (r->m_z_adler32 << 8) | s;
    }
  }
  TINFL_CR_RETURN_FOREVER(34, TINFL_STATUS_DONE);
  TINFL_CR_FINISH
common_exit:
  if ((status != TINFL_STATUS_NEEDS_MORE_INPUT) &&
      (status != TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS)) {
    while ((pIn_buf_cur > pIn_buf_next) && (num_bits >= 8)) {
      --pIn_buf_cur;
      num_bits -= 8;
    }
  }
  r->m_num_bits = num_bits;
  r->m_bit_buf = bit_buf & (tinfl_bit_buf_t)((1ULL << num_bits) - 1ULL);
  r->m_dist = dist;
  r->m_counter = counter;
  r->m_num_extra = num_extra;
  r->m_dist_from_out_buf_start = dist_from_out_buf_start;
  *pIn_buf_size = pIn_buf_cur - pIn_buf_next;
  *pOut_buf_size = pOut_buf_cur - pOut_buf_next;
  if ((decomp_flags &
       (TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32)) &&
      (status >= 0)) {
    const MINI_uint8 *ptr = pOut_buf_next;
    size_t buf_len = *pOut_buf_size;
    MINI_uint32 i, s1 = r->m_check_adler32 & 0xffff, s2 = r->m_check_adler32 >> 16;
    size_t block_len = buf_len % 5552;
    while (buf_len) {
      for (i = 0; i + 7 < block_len; i += 8, ptr += 8) {
        s1 += ptr[0], s2 += s1;
        s1 += ptr[1], s2 += s1;
        s1 += ptr[2], s2 += s1;
        s1 += ptr[3], s2 += s1;
        s1 += ptr[4], s2 += s1;
        s1 += ptr[5], s2 += s1;
        s1 += ptr[6], s2 += s1;
        s1 += ptr[7], s2 += s1;
      }
      for (; i < block_len; ++i)
        s1 += *ptr++, s2 += s1;
      s1 %= 65521U, s2 %= 65521U;
      buf_len -= block_len;
      block_len = 5552;
    }
    r->m_check_adler32 = (s2 << 16) + s1;
    if ((status == TINFL_STATUS_DONE) &&
        (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER) &&
        (r->m_check_adler32 != r->m_z_adler32))
      status = TINFL_STATUS_ADLER32_MISMATCH;
  }
  return status;
}
void *tinfl_decompress_mem_to_heap(const void *pSrc_buf, size_t src_buf_len, size_t *pOut_len, int flags) {
  tinfl_decompressor decomp;
  void *pBuf = NULL, *pNew_buf;
  size_t src_buf_ofs = 0, out_buf_capacity = 0;
  *pOut_len = 0;
  tinfl_init(&decomp);
  for (;;) {
    size_t src_buf_size = src_buf_len - src_buf_ofs, dst_buf_size = out_buf_capacity - *pOut_len, new_out_buf_capacity;
    tinfl_status status = tinfl_decompress(
        &decomp, (const MINI_uint8 *)pSrc_buf + src_buf_ofs, &src_buf_size, (MINI_uint8 *)pBuf, pBuf ? (MINI_uint8 *)pBuf + *pOut_len : NULL, &dst_buf_size, (flags & ~TINFL_FLAG_HAS_MORE_INPUT) |
            TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if ((status < 0) || (status == TINFL_STATUS_NEEDS_MORE_INPUT)) {
      MINI_FREE(pBuf);
      *pOut_len = 0;
      return NULL;
    }
    src_buf_ofs += src_buf_size;
    *pOut_len += dst_buf_size;
    if (status == TINFL_STATUS_DONE)
      break;
    new_out_buf_capacity = out_buf_capacity * 2;
    if (new_out_buf_capacity < 128)
      new_out_buf_capacity = 128;
    pNew_buf = MINI_REALLOC(pBuf, new_out_buf_capacity);
    if (!pNew_buf) {
      MINI_FREE(pBuf);
      *pOut_len = 0;
      return NULL;
    }
    pBuf = pNew_buf;
    out_buf_capacity = new_out_buf_capacity;
  }
  return pBuf;
}
size_t tinfl_decompress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len, int flags) {
  tinfl_decompressor decomp;
  tinfl_status status;
  tinfl_init(&decomp);
  status = tinfl_decompress(&decomp, (const MINI_uint8 *)pSrc_buf, &src_buf_len, (MINI_uint8 *)pOut_buf, (MINI_uint8 *)pOut_buf, &out_buf_len, (flags & ~TINFL_FLAG_HAS_MORE_INPUT) |
                           TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
  return (status != TINFL_STATUS_DONE) ? TINFL_DECOMPRESS_MEM_TO_MEM_FAILED
                                       : out_buf_len;
}
int tinfl_decompress_mem_to_callback(const void *pIn_buf, size_t *pIn_buf_size, tinfl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags) {
  int result = 0;
  tinfl_decompressor decomp;
  MINI_uint8 *pDict = (MINI_uint8 *)MINI_MALLOC(TINFL_LZ_DICT_SIZE);
  size_t in_buf_ofs = 0, dict_ofs = 0;
  if (!pDict)
    return TINFL_STATUS_FAILED;
  tinfl_init(&decomp);
  for (;;) {
    size_t in_buf_size = *pIn_buf_size - in_buf_ofs, dst_buf_size = TINFL_LZ_DICT_SIZE - dict_ofs;
    tinfl_status status = tinfl_decompress(&decomp, (const MINI_uint8 *)pIn_buf + in_buf_ofs, &in_buf_size, pDict, pDict + dict_ofs, &dst_buf_size, (flags & ~(TINFL_FLAG_HAS_MORE_INPUT |
                                    TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF)));
    in_buf_ofs += in_buf_size;
    if ((dst_buf_size) &&
        (!(*pPut_buf_func)(pDict + dict_ofs, (int)dst_buf_size, pPut_buf_user)))
      break;
    if (status != TINFL_STATUS_HAS_MORE_OUTPUT) {
      result = (status == TINFL_STATUS_DONE);
      break;
    }
    dict_ofs = (dict_ofs + dst_buf_size) & (TINFL_LZ_DICT_SIZE - 1);
  }
  MINI_FREE(pDict);
  *pIn_buf_size = in_buf_ofs;
  return result;
}
static const MINI_uint16 s_tdefl_len_sym[256] = {
    257, 258, 259, 260, 261, 262, 263, 264, 265, 265, 266, 266, 267, 267, 268, 268, 269, 269, 269, 269, 270, 270, 270, 270, 271, 271, 271, 271, 272, 272, 272, 272, 273, 273, 273, 273, 273, 273, 273, 273, 274, 274, 274, 274, 274, 274, 274, 274, 275, 275, 275, 275, 275, 275, 275, 275, 276, 276, 276, 276, 276, 276, 276, 276, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 285};
static const MINI_uint8 s_tdefl_len_extra[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0};
static const MINI_uint8 s_tdefl_small_dist_sym[512] = {
    0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,  8,  8,  8, 8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,  10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17};
static const MINI_uint8 s_tdefl_small_dist_extra[512] = {
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
static const MINI_uint8 s_tdefl_large_dist_sym[128] = {
    0,  0,  18, 19, 20, 20, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29};
static const MINI_uint8 s_tdefl_large_dist_extra[128] = {
    0,  0,  8,  8,  9,  9,  9,  9,  10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13};
typedef struct {
  MINI_uint16 m_key, m_sym_index;
} tdefl_sym_freq;
static tdefl_sym_freq *tdefl_radix_sort_syms(MINI_uint num_syms, tdefl_sym_freq *pSyms0, tdefl_sym_freq *pSyms1) {
  MINI_uint32 total_passes = 2, pass_shift, pass, i, hist[256 * 2];
  tdefl_sym_freq *pCur_syms = pSyms0, *pNew_syms = pSyms1;
  MINI_CLEAR_OBJ(hist);
  for (i = 0; i < num_syms; i++) {
    MINI_uint freq = pSyms0[i].m_key;
    hist[freq & 0xFF]++;
    hist[256 + ((freq >> 8) & 0xFF)]++;
  }
  while ((total_passes > 1) && (num_syms == hist[(total_passes - 1) * 256]))
    total_passes--;
  for (pass_shift = 0, pass = 0; pass < total_passes; pass++, pass_shift += 8) {
    const MINI_uint32 *pHist = &hist[pass << 8];
    MINI_uint offsets[256], cur_ofs = 0;
    for (i = 0; i < 256; i++) {
      offsets[i] = cur_ofs;
      cur_ofs += pHist[i];
    }
    for (i = 0; i < num_syms; i++)
      pNew_syms[offsets[(pCur_syms[i].m_key >> pass_shift) & 0xFF]++] = pCur_syms[i];
    {
      tdefl_sym_freq *t = pCur_syms;
      pCur_syms = pNew_syms;
      pNew_syms = t;
    }
  }
  return pCur_syms;
}
static void tdefl_calculate_minimum_redundancy(tdefl_sym_freq *A, int n) {
  int root, leaf, next, avbl, used, dpth;
  if (n == 0)
    return;
  else if (n == 1) {
    A[0].m_key = 1;
    return;
  }
  A[0].m_key += A[1].m_key;
  root = 0;
  leaf = 2;
  for (next = 1; next < n - 1; next++) {
    if (leaf >= n || A[root].m_key < A[leaf].m_key) {
      A[next].m_key = A[root].m_key;
      A[root++].m_key = (MINI_uint16)next;
    } else
      A[next].m_key = A[leaf++].m_key;
    if (leaf >= n || (root < next && A[root].m_key < A[leaf].m_key)) {
      A[next].m_key = (MINI_uint16)(A[next].m_key + A[root].m_key);
      A[root++].m_key = (MINI_uint16)next;
    } else
      A[next].m_key = (MINI_uint16)(A[next].m_key + A[leaf++].m_key);
  }
  A[n - 2].m_key = 0;
  for (next = n - 3; next >= 0; next--)
    A[next].m_key = A[A[next].m_key].m_key + 1;
  avbl = 1;
  used = dpth = 0;
  root = n - 2;
  next = n - 1;
  while (avbl > 0) {
    while (root >= 0 && (int)A[root].m_key == dpth) {
      used++;
      root--;
    }
    while (avbl > used) {
      A[next--].m_key = (MINI_uint16)(dpth);
      avbl--;
    }
    avbl = 2 * used;
    dpth++;
    used = 0;
  }
}
enum { TDEFL_MAX_SUPPORTED_HUFF_CODESIZE = 32 };
static void tdefl_huffman_enforce_max_code_size(int *pNum_codes, int code_list_len, int max_code_size) {
  int i;
  MINI_uint32 total = 0;
  if (code_list_len <= 1)
    return;
  for (i = max_code_size + 1; i <= TDEFL_MAX_SUPPORTED_HUFF_CODESIZE; i++)
    pNum_codes[max_code_size] += pNum_codes[i];
  for (i = max_code_size; i > 0; i--)
    total += (((MINI_uint32)pNum_codes[i]) << (max_code_size - i));
  while (total != (1UL << max_code_size)) {
    pNum_codes[max_code_size]--;
    for (i = max_code_size - 1; i > 0; i--)
      if (pNum_codes[i]) {
        pNum_codes[i]--;
        pNum_codes[i + 1] += 2;
        break;
      }
    total--;
  }
}
static void tdefl_optimize_huffman_table(tdefl_compressor *d, int table_num, int table_len, int code_size_limit, int static_table) {
  int i, j, l, num_codes[1 + TDEFL_MAX_SUPPORTED_HUFF_CODESIZE];
  MINI_uint next_code[TDEFL_MAX_SUPPORTED_HUFF_CODESIZE + 1];
  MINI_CLEAR_OBJ(num_codes);
  if (static_table) {
    for (i = 0; i < table_len; i++)
      num_codes[d->m_huff_code_sizes[table_num][i]]++;
  } else {
    tdefl_sym_freq syms0[TDEFL_MAX_HUFF_SYMBOLS], syms1[TDEFL_MAX_HUFF_SYMBOLS], *pSyms;
    int num_used_syms = 0;
    const MINI_uint16 *pSym_count = &d->m_huff_count[table_num][0];
    for (i = 0; i < table_len; i++)
      if (pSym_count[i]) {
        syms0[num_used_syms].m_key = (MINI_uint16)pSym_count[i];
        syms0[num_used_syms++].m_sym_index = (MINI_uint16)i;
      }
    pSyms = tdefl_radix_sort_syms(num_used_syms, syms0, syms1);
    tdefl_calculate_minimum_redundancy(pSyms, num_used_syms);
    for (i = 0; i < num_used_syms; i++)
      num_codes[pSyms[i].m_key]++;
    tdefl_huffman_enforce_max_code_size(num_codes, num_used_syms, code_size_limit);
    MINI_CLEAR_OBJ(d->m_huff_code_sizes[table_num]);
    MINI_CLEAR_OBJ(d->m_huff_codes[table_num]);
    for (i = 1, j = num_used_syms; i <= code_size_limit; i++)
      for (l = num_codes[i]; l > 0; l--)
        d->m_huff_code_sizes[table_num][pSyms[--j].m_sym_index] = (MINI_uint8)(i);
  }
  next_code[1] = 0;
  for (j = 0, i = 2; i <= code_size_limit; i++)
    next_code[i] = j = ((j + num_codes[i - 1]) << 1);
  for (i = 0; i < table_len; i++) {
    MINI_uint rev_code = 0, code, code_size;
    if ((code_size = d->m_huff_code_sizes[table_num][i]) == 0)
      continue;
    code = next_code[code_size]++;
    for (l = code_size; l > 0; l--, code >>= 1)
      rev_code = (rev_code << 1) | (code & 1);
    d->m_huff_codes[table_num][i] = (MINI_uint16)rev_code;
  }
}
#define TDEFL_PUT_BITS(b, l)                                                   \
  do {                                                                         \
    MINI_uint bits = b;                                                          \
    MINI_uint len = l;                                                           \
    MINI_ASSERT(bits <= ((1U << len) - 1U));                                     \
    d->m_bit_buffer |= (bits << d->m_bits_in);                                 \
    d->m_bits_in += len;                                                       \
    while (d->m_bits_in >= 8) {                                                \
      if (d->m_pOutput_buf < d->m_pOutput_buf_end)                             \
        *d->m_pOutput_buf++ = (MINI_uint8)(d->m_bit_buffer);                     \
      d->m_bit_buffer >>= 8;                                                   \
      d->m_bits_in -= 8;                                                       \
    }                                                                          \
  }                                                                            \
  MINI_MACRO_END
#define TDEFL_RLE_PREV_CODE_SIZE()                                             \
  {                                                                            \
    if (rle_repeat_count) {                                                    \
      if (rle_repeat_count < 3) {                                              \
        d->m_huff_count[2][prev_code_size] = (MINI_uint16)(                      \
            d->m_huff_count[2][prev_code_size] + rle_repeat_count);            \
        while (rle_repeat_count--)                                             \
          packed_code_sizes[num_packed_code_sizes++] = prev_code_size;         \
      } else {                                                                 \
        d->m_huff_count[2][16] = (MINI_uint16)(d->m_huff_count[2][16] + 1);      \
        packed_code_sizes[num_packed_code_sizes++] = 16;                       \
        packed_code_sizes[num_packed_code_sizes++] =                           \
            (MINI_uint8)(rle_repeat_count - 3);                                  \
      }                                                                        \
      rle_repeat_count = 0;                                                    \
    }                                                                          \
  }
#define TDEFL_RLE_ZERO_CODE_SIZE()                                             \
  {                                                                            \
    if (rle_z_count) {                                                         \
      if (rle_z_count < 3) {                                                   \
        d->m_huff_count[2][0] =                                                \
            (MINI_uint16)(d->m_huff_count[2][0] + rle_z_count);                  \
        while (rle_z_count--)                                                  \
          packed_code_sizes[num_packed_code_sizes++] = 0;                      \
      } else if (rle_z_count <= 10) {                                          \
        d->m_huff_count[2][17] = (MINI_uint16)(d->m_huff_count[2][17] + 1);      \
        packed_code_sizes[num_packed_code_sizes++] = 17;                       \
        packed_code_sizes[num_packed_code_sizes++] =                           \
            (MINI_uint8)(rle_z_count - 3);                                       \
      } else {                                                                 \
        d->m_huff_count[2][18] = (MINI_uint16)(d->m_huff_count[2][18] + 1);      \
        packed_code_sizes[num_packed_code_sizes++] = 18;                       \
        packed_code_sizes[num_packed_code_sizes++] =                           \
            (MINI_uint8)(rle_z_count - 11);                                      \
      }                                                                        \
      rle_z_count = 0;                                                         \
    }                                                                          \
  }
static MINI_uint8 s_tdefl_packed_code_size_syms_swizzle[] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
static void tdefl_start_dynamic_block(tdefl_compressor *d) {
  int num_lit_codes, num_dist_codes, num_bit_lengths;
  MINI_uint i, total_code_sizes_to_pack, num_packed_code_sizes, rle_z_count, rle_repeat_count, packed_code_sizes_index;
  MINI_uint8
      code_sizes_to_pack[TDEFL_MAX_HUFF_SYMBOLS_0 + TDEFL_MAX_HUFF_SYMBOLS_1], packed_code_sizes[TDEFL_MAX_HUFF_SYMBOLS_0 + TDEFL_MAX_HUFF_SYMBOLS_1], prev_code_size = 0xFF;
  d->m_huff_count[0][256] = 1;
  tdefl_optimize_huffman_table(d, 0, TDEFL_MAX_HUFF_SYMBOLS_0, 15, MINI_FALSE);
  tdefl_optimize_huffman_table(d, 1, TDEFL_MAX_HUFF_SYMBOLS_1, 15, MINI_FALSE);
  for (num_lit_codes = 286; num_lit_codes > 257; num_lit_codes--)
    if (d->m_huff_code_sizes[0][num_lit_codes - 1])
      break;
  for (num_dist_codes = 30; num_dist_codes > 1; num_dist_codes--)
    if (d->m_huff_code_sizes[1][num_dist_codes - 1])
      break;
  memcpy(code_sizes_to_pack, &d->m_huff_code_sizes[0][0], num_lit_codes);
  memcpy(code_sizes_to_pack + num_lit_codes, &d->m_huff_code_sizes[1][0], num_dist_codes);
  total_code_sizes_to_pack = num_lit_codes + num_dist_codes;
  num_packed_code_sizes = 0;
  rle_z_count = 0;
  rle_repeat_count = 0;
  memset(&d->m_huff_count[2][0], 0, sizeof(d->m_huff_count[2][0]) * TDEFL_MAX_HUFF_SYMBOLS_2);
  for (i = 0; i < total_code_sizes_to_pack; i++) {
    MINI_uint8 code_size = code_sizes_to_pack[i];
    if (!code_size) {
      TDEFL_RLE_PREV_CODE_SIZE();
      if (++rle_z_count == 138) {
        TDEFL_RLE_ZERO_CODE_SIZE();
      }
    } else {
      TDEFL_RLE_ZERO_CODE_SIZE();
      if (code_size != prev_code_size) {
        TDEFL_RLE_PREV_CODE_SIZE();
        d->m_huff_count[2][code_size] = (MINI_uint16)(d->m_huff_count[2][code_size] + 1);
        packed_code_sizes[num_packed_code_sizes++] = code_size;
      } else if (++rle_repeat_count == 6) {
        TDEFL_RLE_PREV_CODE_SIZE();
      }
    }
    prev_code_size = code_size;
  }
  if (rle_repeat_count) {
    TDEFL_RLE_PREV_CODE_SIZE();
  } else {
    TDEFL_RLE_ZERO_CODE_SIZE();
  }
  tdefl_optimize_huffman_table(d, 2, TDEFL_MAX_HUFF_SYMBOLS_2, 7, MINI_FALSE);
  TDEFL_PUT_BITS(2, 2);
  TDEFL_PUT_BITS(num_lit_codes - 257, 5);
  TDEFL_PUT_BITS(num_dist_codes - 1, 5);
  for (num_bit_lengths = 18; num_bit_lengths >= 0; num_bit_lengths--)
    if (d->m_huff_code_sizes
            [2][s_tdefl_packed_code_size_syms_swizzle[num_bit_lengths]])
      break;
  num_bit_lengths = MINI_MAX(4, (num_bit_lengths + 1));
  TDEFL_PUT_BITS(num_bit_lengths - 4, 4);
  for (i = 0; (int)i < num_bit_lengths; i++)
    TDEFL_PUT_BITS(
        d->m_huff_code_sizes[2][s_tdefl_packed_code_size_syms_swizzle[i]], 3);
  for (packed_code_sizes_index = 0;
       packed_code_sizes_index < num_packed_code_sizes;) {
    MINI_uint code = packed_code_sizes[packed_code_sizes_index++];
    MINI_ASSERT(code < TDEFL_MAX_HUFF_SYMBOLS_2);
    TDEFL_PUT_BITS(d->m_huff_codes[2][code], d->m_huff_code_sizes[2][code]);
    if (code >= 16)
      TDEFL_PUT_BITS(packed_code_sizes[packed_code_sizes_index++], "\02\03\07"[code - 16]);
  }
}
static void tdefl_start_static_block(tdefl_compressor *d) {
  MINI_uint i;
  MINI_uint8 *p = &d->m_huff_code_sizes[0][0];
  for (i = 0; i <= 143; ++i)
    *p++ = 8;
  for (; i <= 255; ++i)
    *p++ = 9;
  for (; i <= 279; ++i)
    *p++ = 7;
  for (; i <= 287; ++i)
    *p++ = 8;
  memset(d->m_huff_code_sizes[1], 5, 32);
  tdefl_optimize_huffman_table(d, 0, 288, 15, MINI_TRUE);
  tdefl_optimize_huffman_table(d, 1, 32, 15, MINI_TRUE);
  TDEFL_PUT_BITS(1, 2);
}
static const MINI_uint MINI_bitmasks[17] = {
    0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F, 0x003F, 0x007F, 0x00FF, 0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF};
#if MINI_USE_UNALIGNED_LOADS_AND_STORES && MINI_LITTLE_ENDIAN &&               \
    MINI_HAS_64BIT_REGISTERS
static MINI_bool tdefl_compress_lz_codes(tdefl_compressor *d) {
  MINI_uint flags;
  MINI_uint8 *pLZ_codes;
  MINI_uint8 *pOutput_buf = d->m_pOutput_buf;
  MINI_uint8 *pLZ_code_buf_end = d->m_pLZ_code_buf;
  MINI_uint64 bit_buffer = d->m_bit_buffer;
  MINI_uint bits_in = d->m_bits_in;
#define TDEFL_PUT_BITS_FAST(b, l)                                              \
  {                                                                            \
    bit_buffer |= (((MINI_uint64)(b)) << bits_in);                               \
    bits_in += (l);                                                            \
  }
  flags = 1;
  for (pLZ_codes = d->m_lz_code_buf; pLZ_codes < pLZ_code_buf_end;
       flags >>= 1) {
    if (flags == 1)
      flags = *pLZ_codes++ | 0x100;
    if (flags & 1) {
      MINI_uint s0, s1, n0, n1, sym, num_extra_bits;
      MINI_uint match_len = pLZ_codes[0], match_dist = *(const MINI_uint16 *)(pLZ_codes + 1);
      pLZ_codes += 3;
      MINI_ASSERT(d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
      TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][s_tdefl_len_sym[match_len]], d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
      TDEFL_PUT_BITS_FAST(match_len & MINI_bitmasks[s_tdefl_len_extra[match_len]], s_tdefl_len_extra[match_len]);
      s0 = s_tdefl_small_dist_sym[match_dist & 511];
      n0 = s_tdefl_small_dist_extra[match_dist & 511];
      s1 = s_tdefl_large_dist_sym[match_dist >> 8];
      n1 = s_tdefl_large_dist_extra[match_dist >> 8];
      sym = (match_dist < 512) ? s0 : s1;
      num_extra_bits = (match_dist < 512) ? n0 : n1;
      MINI_ASSERT(d->m_huff_code_sizes[1][sym]);
      TDEFL_PUT_BITS_FAST(d->m_huff_codes[1][sym], d->m_huff_code_sizes[1][sym]);
      TDEFL_PUT_BITS_FAST(match_dist & MINI_bitmasks[num_extra_bits], num_extra_bits);
    } else {
      MINI_uint lit = *pLZ_codes++;
      MINI_ASSERT(d->m_huff_code_sizes[0][lit]);
      TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);
      if (((flags & 2) == 0) && (pLZ_codes < pLZ_code_buf_end)) {
        flags >>= 1;
        lit = *pLZ_codes++;
        MINI_ASSERT(d->m_huff_code_sizes[0][lit]);
        TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);
        if (((flags & 2) == 0) && (pLZ_codes < pLZ_code_buf_end)) {
          flags >>= 1;
          lit = *pLZ_codes++;
          MINI_ASSERT(d->m_huff_code_sizes[0][lit]);
          TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);
        }
      }
    }
    if (pOutput_buf >= d->m_pOutput_buf_end)
      return MINI_FALSE;
    *(MINI_uint64 *)pOutput_buf = bit_buffer;
    pOutput_buf += (bits_in >> 3);
    bit_buffer >>= (bits_in & ~7);
    bits_in &= 7;
  }
#undef TDEFL_PUT_BITS_FAST
  d->m_pOutput_buf = pOutput_buf;
  d->m_bits_in = 0;
  d->m_bit_buffer = 0;
  while (bits_in) {
    MINI_uint32 n = MINI_MIN(bits_in, 16);
    TDEFL_PUT_BITS((MINI_uint)bit_buffer & MINI_bitmasks[n], n);
    bit_buffer >>= n;
    bits_in -= n;
  }
  TDEFL_PUT_BITS(d->m_huff_codes[0][256], d->m_huff_code_sizes[0][256]);
  return (d->m_pOutput_buf < d->m_pOutput_buf_end);
}
#else
static MINI_bool tdefl_compress_lz_codes(tdefl_compressor *d) {
  MINI_uint flags;
  MINI_uint8 *pLZ_codes;
  flags = 1;
  for (pLZ_codes = d->m_lz_code_buf; pLZ_codes < d->m_pLZ_code_buf;
       flags >>= 1) {
    if (flags == 1)
      flags = *pLZ_codes++ | 0x100;
    if (flags & 1) {
      MINI_uint sym, num_extra_bits;
      MINI_uint match_len = pLZ_codes[0], match_dist = (pLZ_codes[1] | (pLZ_codes[2] << 8));
      pLZ_codes += 3;
      MINI_ASSERT(d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
      TDEFL_PUT_BITS(d->m_huff_codes[0][s_tdefl_len_sym[match_len]], d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
      TDEFL_PUT_BITS(match_len & MINI_bitmasks[s_tdefl_len_extra[match_len]], s_tdefl_len_extra[match_len]);
      if (match_dist < 512) {
        sym = s_tdefl_small_dist_sym[match_dist];
        num_extra_bits = s_tdefl_small_dist_extra[match_dist];
      } else {
        sym = s_tdefl_large_dist_sym[match_dist >> 8];
        num_extra_bits = s_tdefl_large_dist_extra[match_dist >> 8];
      }
      MINI_ASSERT(d->m_huff_code_sizes[1][sym]);
      TDEFL_PUT_BITS(d->m_huff_codes[1][sym], d->m_huff_code_sizes[1][sym]);
      TDEFL_PUT_BITS(match_dist & MINI_bitmasks[num_extra_bits], num_extra_bits);
    } else {
      MINI_uint lit = *pLZ_codes++;
      MINI_ASSERT(d->m_huff_code_sizes[0][lit]);
      TDEFL_PUT_BITS(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);
    }
  }
  TDEFL_PUT_BITS(d->m_huff_codes[0][256], d->m_huff_code_sizes[0][256]);
  return (d->m_pOutput_buf < d->m_pOutput_buf_end);
}
#endif
static MINI_bool tdefl_compress_block(tdefl_compressor *d, MINI_bool static_block) {
  if (static_block)
    tdefl_start_static_block(d);
  else
    tdefl_start_dynamic_block(d);
  return tdefl_compress_lz_codes(d);
}
static int tdefl_flush_block(tdefl_compressor *d, int flush) {
  MINI_uint saved_bit_buf, saved_bits_in;
  MINI_uint8 *pSaved_output_buf;
  MINI_bool comp_block_succeeded = MINI_FALSE;
  int n, use_raw_block = ((d->m_flags & TDEFL_FORCE_ALL_RAW_BLOCKS) != 0) &&
             (d->m_lookahead_pos - d->m_lz_code_buf_dict_pos) <= d->m_dict_size;
  MINI_uint8 *pOutput_buf_start = ((d->m_pPut_buf_func == NULL) &&
       ((*d->m_pOut_buf_size - d->m_out_buf_ofs) >= TDEFL_OUT_BUF_SIZE))
          ? ((MINI_uint8 *)d->m_pOut_buf + d->m_out_buf_ofs)
          : d->m_output_buf;
  d->m_pOutput_buf = pOutput_buf_start;
  d->m_pOutput_buf_end = d->m_pOutput_buf + TDEFL_OUT_BUF_SIZE - 16;
  MINI_ASSERT(!d->m_output_flush_remaining);
  d->m_output_flush_ofs = 0;
  d->m_output_flush_remaining = 0;
  *d->m_pLZ_flags = (MINI_uint8)(*d->m_pLZ_flags >> d->m_num_flags_left);
  d->m_pLZ_code_buf -= (d->m_num_flags_left == 8);
  if ((d->m_flags & TDEFL_WRITE_ZLIB_HEADER) && (!d->m_block_index)) {
    TDEFL_PUT_BITS(0x78, 8);
    TDEFL_PUT_BITS(0x01, 8);
  }
  TDEFL_PUT_BITS(flush == TDEFL_FINISH, 1);
  pSaved_output_buf = d->m_pOutput_buf;
  saved_bit_buf = d->m_bit_buffer;
  saved_bits_in = d->m_bits_in;
  if (!use_raw_block)
    comp_block_succeeded = tdefl_compress_block(d, (d->m_flags & TDEFL_FORCE_ALL_STATIC_BLOCKS) ||
                                    (d->m_total_lz_bytes < 48));
  if (((use_raw_block) ||
       ((d->m_total_lz_bytes) && ((d->m_pOutput_buf - pSaved_output_buf + 1U) >= d->m_total_lz_bytes))) &&
      ((d->m_lookahead_pos - d->m_lz_code_buf_dict_pos) <= d->m_dict_size)) {
    MINI_uint i;
    d->m_pOutput_buf = pSaved_output_buf;
    d->m_bit_buffer = saved_bit_buf, d->m_bits_in = saved_bits_in;
    TDEFL_PUT_BITS(0, 2);
    if (d->m_bits_in) {
      TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
    }
    for (i = 2; i; --i, d->m_total_lz_bytes ^= 0xFFFF) {
      TDEFL_PUT_BITS(d->m_total_lz_bytes & 0xFFFF, 16);
    }
    for (i = 0; i < d->m_total_lz_bytes; ++i) {
      TDEFL_PUT_BITS(
          d->m_dict[(d->m_lz_code_buf_dict_pos + i) & TDEFL_LZ_DICT_SIZE_MASK], 8);
    }
  } else if (!comp_block_succeeded) {
    d->m_pOutput_buf = pSaved_output_buf;
    d->m_bit_buffer = saved_bit_buf, d->m_bits_in = saved_bits_in;
    tdefl_compress_block(d, MINI_TRUE);
  }
  if (flush) {
    if (flush == TDEFL_FINISH) {
      if (d->m_bits_in) {
        TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
      }
      if (d->m_flags & TDEFL_WRITE_ZLIB_HEADER) {
        MINI_uint i, a = d->m_adler32;
        for (i = 0; i < 4; i++) {
          TDEFL_PUT_BITS((a >> 24) & 0xFF, 8);
          a <<= 8;
        }
      }
    } else {
      MINI_uint i, z = 0;
      TDEFL_PUT_BITS(0, 3);
      if (d->m_bits_in) {
        TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
      }
      for (i = 2; i; --i, z ^= 0xFFFF) {
        TDEFL_PUT_BITS(z & 0xFFFF, 16);
      }
    }
  }
  MINI_ASSERT(d->m_pOutput_buf < d->m_pOutput_buf_end);
  memset(&d->m_huff_count[0][0], 0, sizeof(d->m_huff_count[0][0]) * TDEFL_MAX_HUFF_SYMBOLS_0);
  memset(&d->m_huff_count[1][0], 0, sizeof(d->m_huff_count[1][0]) * TDEFL_MAX_HUFF_SYMBOLS_1);
  d->m_pLZ_code_buf = d->m_lz_code_buf + 1;
  d->m_pLZ_flags = d->m_lz_code_buf;
  d->m_num_flags_left = 8;
  d->m_lz_code_buf_dict_pos += d->m_total_lz_bytes;
  d->m_total_lz_bytes = 0;
  d->m_block_index++;
  if ((n = (int)(d->m_pOutput_buf - pOutput_buf_start)) != 0) {
    if (d->m_pPut_buf_func) {
      *d->m_pIn_buf_size = d->m_pSrc - (const MINI_uint8 *)d->m_pIn_buf;
      if (!(*d->m_pPut_buf_func)(d->m_output_buf, n, d->m_pPut_buf_user))
        return (d->m_prev_return_status = TDEFL_STATUS_PUT_BUF_FAILED);
    } else if (pOutput_buf_start == d->m_output_buf) {
      int bytes_to_copy = (int)MINI_MIN(
          (size_t)n, (size_t)(*d->m_pOut_buf_size - d->m_out_buf_ofs));
      memcpy((MINI_uint8 *)d->m_pOut_buf + d->m_out_buf_ofs, d->m_output_buf, bytes_to_copy);
      d->m_out_buf_ofs += bytes_to_copy;
      if ((n -= bytes_to_copy) != 0) {
        d->m_output_flush_ofs = bytes_to_copy;
        d->m_output_flush_remaining = n;
      }
    } else {
      d->m_out_buf_ofs += n;
    }
  }
  return d->m_output_flush_remaining;
}
#if MINI_USE_UNALIGNED_LOADS_AND_STORES
#define TDEFL_READ_UNALIGNED_WORD(p) *(const MINI_uint16 *)(p)
static MINI_FORCEINLINE void
tdefl_find_match(tdefl_compressor *d, MINI_uint lookahead_pos, MINI_uint max_dist, MINI_uint max_match_len, MINI_uint *pMatch_dist, MINI_uint *pMatch_len) {
  MINI_uint dist, pos = lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK, match_len = *pMatch_len, probe_pos = pos, next_probe_pos, probe_len;
  MINI_uint num_probes_left = d->m_max_probes[match_len >= 32];
  const MINI_uint16 *s = (const MINI_uint16 *)(d->m_dict + pos), *p, *q;
  MINI_uint16 c01 = TDEFL_READ_UNALIGNED_WORD(&d->m_dict[pos + match_len - 1]), s01 = TDEFL_READ_UNALIGNED_WORD(s);
  MINI_ASSERT(max_match_len <= TDEFL_MAX_MATCH_LEN);
  if (max_match_len <= match_len)
    return;
  for (;;) {
    for (;;) {
      if (--num_probes_left == 0)
        return;
#define TDEFL_PROBE                                                            \
  next_probe_pos = d->m_next[probe_pos];                                       \
  if ((!next_probe_pos) ||                                                     \
      ((dist = (MINI_uint16)(lookahead_pos - next_probe_pos)) > max_dist))       \
    return;                                                                    \
  probe_pos = next_probe_pos & TDEFL_LZ_DICT_SIZE_MASK;                        \
  if (TDEFL_READ_UNALIGNED_WORD(&d->m_dict[probe_pos + match_len - 1]) == c01) \
    break;
      TDEFL_PROBE;
      TDEFL_PROBE;
      TDEFL_PROBE;
    }
    if (!dist)
      break;
    q = (const MINI_uint16 *)(d->m_dict + probe_pos);
    if (TDEFL_READ_UNALIGNED_WORD(q) != s01)
      continue;
    p = s;
    probe_len = 32;
    do {
    } while (
        (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
        (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
        (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
        (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
        (--probe_len > 0));
    if (!probe_len) {
      *pMatch_dist = dist;
      *pMatch_len = MINI_MIN(max_match_len, TDEFL_MAX_MATCH_LEN);
      break;
    } else if ((probe_len = ((MINI_uint)(p - s) * 2) +
                            (MINI_uint)(*(const MINI_uint8 *)p == *(const MINI_uint8 *)q)) > match_len) {
      *pMatch_dist = dist;
      if ((*pMatch_len = match_len = MINI_MIN(max_match_len, probe_len)) == max_match_len)
        break;
      c01 = TDEFL_READ_UNALIGNED_WORD(&d->m_dict[pos + match_len - 1]);
    }
  }
}
#else
static MINI_FORCEINLINE void
tdefl_find_match(tdefl_compressor *d, MINI_uint lookahead_pos, MINI_uint max_dist, MINI_uint max_match_len, MINI_uint *pMatch_dist, MINI_uint *pMatch_len) {
  MINI_uint dist, pos = lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK, match_len = *pMatch_len, probe_pos = pos, next_probe_pos, probe_len;
  MINI_uint num_probes_left = d->m_max_probes[match_len >= 32];
  const MINI_uint8 *s = d->m_dict + pos, *p, *q;
  MINI_uint8 c0 = d->m_dict[pos + match_len], c1 = d->m_dict[pos + match_len - 1];
  MINI_ASSERT(max_match_len <= TDEFL_MAX_MATCH_LEN);
  if (max_match_len <= match_len)
    return;
  for (;;) {
    for (;;) {
      if (--num_probes_left == 0)
        return;
#define TDEFL_PROBE                                                            \
  next_probe_pos = d->m_next[probe_pos];                                       \
  if ((!next_probe_pos) ||                                                     \
      ((dist = (MINI_uint16)(lookahead_pos - next_probe_pos)) > max_dist))       \
    return;                                                                    \
  probe_pos = next_probe_pos & TDEFL_LZ_DICT_SIZE_MASK;                        \
  if ((d->m_dict[probe_pos + match_len] == c0) &&                              \
      (d->m_dict[probe_pos + match_len - 1] == c1))                            \
    break;
      TDEFL_PROBE;
      TDEFL_PROBE;
      TDEFL_PROBE;
    }
    if (!dist)
      break;
    p = s;
    q = d->m_dict + probe_pos;
    for (probe_len = 0; probe_len < max_match_len; probe_len++)
      if (*p++ != *q++)
        break;
    if (probe_len > match_len) {
      *pMatch_dist = dist;
      if ((*pMatch_len = match_len = probe_len) == max_match_len)
        return;
      c0 = d->m_dict[pos + match_len];
      c1 = d->m_dict[pos + match_len - 1];
    }
  }
}
#endif
#if MINI_USE_UNALIGNED_LOADS_AND_STORES && MINI_LITTLE_ENDIAN
static MINI_bool tdefl_compress_fast(tdefl_compressor *d) {
  MINI_uint lookahead_pos = d->m_lookahead_pos, lookahead_size = d->m_lookahead_size, dict_size = d->m_dict_size, total_lz_bytes = d->m_total_lz_bytes, num_flags_left = d->m_num_flags_left;
  MINI_uint8 *pLZ_code_buf = d->m_pLZ_code_buf, *pLZ_flags = d->m_pLZ_flags;
  MINI_uint cur_pos = lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK;
  while ((d->m_src_buf_left) || ((d->m_flush) && (lookahead_size))) {
    const MINI_uint TDEFL_COMP_FAST_LOOKAHEAD_SIZE = 4096;
    MINI_uint dst_pos = (lookahead_pos + lookahead_size) & TDEFL_LZ_DICT_SIZE_MASK;
    MINI_uint num_bytes_to_process = (MINI_uint)MINI_MIN(
        d->m_src_buf_left, TDEFL_COMP_FAST_LOOKAHEAD_SIZE - lookahead_size);
    d->m_src_buf_left -= num_bytes_to_process;
    lookahead_size += num_bytes_to_process;
    while (num_bytes_to_process) {
      MINI_uint32 n = MINI_MIN(TDEFL_LZ_DICT_SIZE - dst_pos, num_bytes_to_process);
      memcpy(d->m_dict + dst_pos, d->m_pSrc, n);
      if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
        memcpy(d->m_dict + TDEFL_LZ_DICT_SIZE + dst_pos, d->m_pSrc, MINI_MIN(n, (TDEFL_MAX_MATCH_LEN - 1) - dst_pos));
      d->m_pSrc += n;
      dst_pos = (dst_pos + n) & TDEFL_LZ_DICT_SIZE_MASK;
      num_bytes_to_process -= n;
    }
    dict_size = MINI_MIN(TDEFL_LZ_DICT_SIZE - lookahead_size, dict_size);
    if ((!d->m_flush) && (lookahead_size < TDEFL_COMP_FAST_LOOKAHEAD_SIZE))
      break;
    while (lookahead_size >= 4) {
      MINI_uint cur_match_dist, cur_match_len = 1;
      MINI_uint8 *pCur_dict = d->m_dict + cur_pos;
      MINI_uint first_trigram = (*(const MINI_uint32 *)pCur_dict) & 0xFFFFFF;
      MINI_uint hash = (first_trigram ^ (first_trigram >> (24 - (TDEFL_LZ_HASH_BITS - 8)))) &
          TDEFL_LEVEL1_HASH_SIZE_MASK;
      MINI_uint probe_pos = d->m_hash[hash];
      d->m_hash[hash] = (MINI_uint16)lookahead_pos;
      if (((cur_match_dist = (MINI_uint16)(lookahead_pos - probe_pos)) <= dict_size) &&
          ((*(const MINI_uint32 *)(d->m_dict +
                                 (probe_pos &= TDEFL_LZ_DICT_SIZE_MASK)) &
            0xFFFFFF) == first_trigram)) {
        const MINI_uint16 *p = (const MINI_uint16 *)pCur_dict;
        const MINI_uint16 *q = (const MINI_uint16 *)(d->m_dict + probe_pos);
        MINI_uint32 probe_len = 32;
        do {
        } while ((TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
                 (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
                 (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
                 (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
                 (--probe_len > 0));
        cur_match_len = ((MINI_uint)(p - (const MINI_uint16 *)pCur_dict) * 2) +
                        (MINI_uint)(*(const MINI_uint8 *)p == *(const MINI_uint8 *)q);
        if (!probe_len)
          cur_match_len = cur_match_dist ? TDEFL_MAX_MATCH_LEN : 0;
        if ((cur_match_len < TDEFL_MIN_MATCH_LEN) ||
            ((cur_match_len == TDEFL_MIN_MATCH_LEN) &&
             (cur_match_dist >= 8U * 1024U))) {
          cur_match_len = 1;
          *pLZ_code_buf++ = (MINI_uint8)first_trigram;
          *pLZ_flags = (MINI_uint8)(*pLZ_flags >> 1);
          d->m_huff_count[0][(MINI_uint8)first_trigram]++;
        } else {
          MINI_uint32 s0, s1;
          cur_match_len = MINI_MIN(cur_match_len, lookahead_size);
          MINI_ASSERT((cur_match_len >= TDEFL_MIN_MATCH_LEN) &&
                    (cur_match_dist >= 1) &&
                    (cur_match_dist <= TDEFL_LZ_DICT_SIZE));
          cur_match_dist--;
          pLZ_code_buf[0] = (MINI_uint8)(cur_match_len - TDEFL_MIN_MATCH_LEN);
          *(MINI_uint16 *)(&pLZ_code_buf[1]) = (MINI_uint16)cur_match_dist;
          pLZ_code_buf += 3;
          *pLZ_flags = (MINI_uint8)((*pLZ_flags >> 1) | 0x80);
          s0 = s_tdefl_small_dist_sym[cur_match_dist & 511];
          s1 = s_tdefl_large_dist_sym[cur_match_dist >> 8];
          d->m_huff_count[1][(cur_match_dist < 512) ? s0 : s1]++;
          d->m_huff_count[0][s_tdefl_len_sym[cur_match_len -
                                             TDEFL_MIN_MATCH_LEN]]++;
        }
      } else {
        *pLZ_code_buf++ = (MINI_uint8)first_trigram;
        *pLZ_flags = (MINI_uint8)(*pLZ_flags >> 1);
        d->m_huff_count[0][(MINI_uint8)first_trigram]++;
      }
      if (--num_flags_left == 0) {
        num_flags_left = 8;
        pLZ_flags = pLZ_code_buf++;
      }
      total_lz_bytes += cur_match_len;
      lookahead_pos += cur_match_len;
      dict_size = MINI_MIN(dict_size + cur_match_len, TDEFL_LZ_DICT_SIZE);
      cur_pos = (cur_pos + cur_match_len) & TDEFL_LZ_DICT_SIZE_MASK;
      MINI_ASSERT(lookahead_size >= cur_match_len);
      lookahead_size -= cur_match_len;
      if (pLZ_code_buf > &d->m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE - 8]) {
        int n;
        d->m_lookahead_pos = lookahead_pos;
        d->m_lookahead_size = lookahead_size;
        d->m_dict_size = dict_size;
        d->m_total_lz_bytes = total_lz_bytes;
        d->m_pLZ_code_buf = pLZ_code_buf;
        d->m_pLZ_flags = pLZ_flags;
        d->m_num_flags_left = num_flags_left;
        if ((n = tdefl_flush_block(d, 0)) != 0)
          return (n < 0) ? MINI_FALSE : MINI_TRUE;
        total_lz_bytes = d->m_total_lz_bytes;
        pLZ_code_buf = d->m_pLZ_code_buf;
        pLZ_flags = d->m_pLZ_flags;
        num_flags_left = d->m_num_flags_left;
      }
    }
    while (lookahead_size) {
      MINI_uint8 lit = d->m_dict[cur_pos];
      total_lz_bytes++;
      *pLZ_code_buf++ = lit;
      *pLZ_flags = (MINI_uint8)(*pLZ_flags >> 1);
      if (--num_flags_left == 0) {
        num_flags_left = 8;
        pLZ_flags = pLZ_code_buf++;
      }
      d->m_huff_count[0][lit]++;
      lookahead_pos++;
      dict_size = MINI_MIN(dict_size + 1, TDEFL_LZ_DICT_SIZE);
      cur_pos = (cur_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK;
      lookahead_size--;
      if (pLZ_code_buf > &d->m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE - 8]) {
        int n;
        d->m_lookahead_pos = lookahead_pos;
        d->m_lookahead_size = lookahead_size;
        d->m_dict_size = dict_size;
        d->m_total_lz_bytes = total_lz_bytes;
        d->m_pLZ_code_buf = pLZ_code_buf;
        d->m_pLZ_flags = pLZ_flags;
        d->m_num_flags_left = num_flags_left;
        if ((n = tdefl_flush_block(d, 0)) != 0)
          return (n < 0) ? MINI_FALSE : MINI_TRUE;
        total_lz_bytes = d->m_total_lz_bytes;
        pLZ_code_buf = d->m_pLZ_code_buf;
        pLZ_flags = d->m_pLZ_flags;
        num_flags_left = d->m_num_flags_left;
      }
    }
  }
  d->m_lookahead_pos = lookahead_pos;
  d->m_lookahead_size = lookahead_size;
  d->m_dict_size = dict_size;
  d->m_total_lz_bytes = total_lz_bytes;
  d->m_pLZ_code_buf = pLZ_code_buf;
  d->m_pLZ_flags = pLZ_flags;
  d->m_num_flags_left = num_flags_left;
  return MINI_TRUE;
}
#endif
static MINI_FORCEINLINE void tdefl_record_literal(tdefl_compressor *d, MINI_uint8 lit) {
  d->m_total_lz_bytes++;
  *d->m_pLZ_code_buf++ = lit;
  *d->m_pLZ_flags = (MINI_uint8)(*d->m_pLZ_flags >> 1);
  if (--d->m_num_flags_left == 0) {
    d->m_num_flags_left = 8;
    d->m_pLZ_flags = d->m_pLZ_code_buf++;
  }
  d->m_huff_count[0][lit]++;
}
static MINI_FORCEINLINE void
tdefl_record_match(tdefl_compressor *d, MINI_uint match_len, MINI_uint match_dist) {
  MINI_uint32 s0, s1;
  MINI_ASSERT((match_len >= TDEFL_MIN_MATCH_LEN) && (match_dist >= 1) &&
            (match_dist <= TDEFL_LZ_DICT_SIZE));
  d->m_total_lz_bytes += match_len;
  d->m_pLZ_code_buf[0] = (MINI_uint8)(match_len - TDEFL_MIN_MATCH_LEN);
  match_dist -= 1;
  d->m_pLZ_code_buf[1] = (MINI_uint8)(match_dist & 0xFF);
  d->m_pLZ_code_buf[2] = (MINI_uint8)(match_dist >> 8);
  d->m_pLZ_code_buf += 3;
  *d->m_pLZ_flags = (MINI_uint8)((*d->m_pLZ_flags >> 1) | 0x80);
  if (--d->m_num_flags_left == 0) {
    d->m_num_flags_left = 8;
    d->m_pLZ_flags = d->m_pLZ_code_buf++;
  }
  s0 = s_tdefl_small_dist_sym[match_dist & 511];
  s1 = s_tdefl_large_dist_sym[(match_dist >> 8) & 127];
  d->m_huff_count[1][(match_dist < 512) ? s0 : s1]++;
  if (match_len >= TDEFL_MIN_MATCH_LEN)
    d->m_huff_count[0][s_tdefl_len_sym[match_len - TDEFL_MIN_MATCH_LEN]]++;
}
static MINI_bool tdefl_compress_normal(tdefl_compressor *d) {
  const MINI_uint8 *pSrc = d->m_pSrc;
  size_t src_buf_left = d->m_src_buf_left;
  tdefl_flush flush = d->m_flush;
  while ((src_buf_left) || ((flush) && (d->m_lookahead_size))) {
    MINI_uint len_to_move, cur_match_dist, cur_match_len, cur_pos;
    if ((d->m_lookahead_size + d->m_dict_size) >= (TDEFL_MIN_MATCH_LEN - 1)) {
      MINI_uint dst_pos = (d->m_lookahead_pos + d->m_lookahead_size) &
                        TDEFL_LZ_DICT_SIZE_MASK, ins_pos = d->m_lookahead_pos + d->m_lookahead_size - 2;
      MINI_uint hash = (d->m_dict[ins_pos & TDEFL_LZ_DICT_SIZE_MASK]
                      << TDEFL_LZ_HASH_SHIFT) ^
                     d->m_dict[(ins_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK];
      MINI_uint num_bytes_to_process = (MINI_uint)MINI_MIN(
          src_buf_left, TDEFL_MAX_MATCH_LEN - d->m_lookahead_size);
      const MINI_uint8 *pSrc_end = pSrc + num_bytes_to_process;
      src_buf_left -= num_bytes_to_process;
      d->m_lookahead_size += num_bytes_to_process;
      while (pSrc != pSrc_end) {
        MINI_uint8 c = *pSrc++;
        d->m_dict[dst_pos] = c;
        if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
          d->m_dict[TDEFL_LZ_DICT_SIZE + dst_pos] = c;
        hash = ((hash << TDEFL_LZ_HASH_SHIFT) ^ c) & (TDEFL_LZ_HASH_SIZE - 1);
        d->m_next[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] = d->m_hash[hash];
        d->m_hash[hash] = (MINI_uint16)(ins_pos);
        dst_pos = (dst_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK;
        ins_pos++;
      }
    } else {
      while ((src_buf_left) && (d->m_lookahead_size < TDEFL_MAX_MATCH_LEN)) {
        MINI_uint8 c = *pSrc++;
        MINI_uint dst_pos = (d->m_lookahead_pos + d->m_lookahead_size) &
                          TDEFL_LZ_DICT_SIZE_MASK;
        src_buf_left--;
        d->m_dict[dst_pos] = c;
        if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
          d->m_dict[TDEFL_LZ_DICT_SIZE + dst_pos] = c;
        if ((++d->m_lookahead_size + d->m_dict_size) >= TDEFL_MIN_MATCH_LEN) {
          MINI_uint ins_pos = d->m_lookahead_pos + (d->m_lookahead_size - 1) - 2;
          MINI_uint hash = ((d->m_dict[ins_pos & TDEFL_LZ_DICT_SIZE_MASK]
                           << (TDEFL_LZ_HASH_SHIFT * 2)) ^
                          (d->m_dict[(ins_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK]
                           << TDEFL_LZ_HASH_SHIFT) ^
                          c) &
                         (TDEFL_LZ_HASH_SIZE - 1);
          d->m_next[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] = d->m_hash[hash];
          d->m_hash[hash] = (MINI_uint16)(ins_pos);
        }
      }
    }
    d->m_dict_size = MINI_MIN(TDEFL_LZ_DICT_SIZE - d->m_lookahead_size, d->m_dict_size);
    if ((!flush) && (d->m_lookahead_size < TDEFL_MAX_MATCH_LEN))
      break;
    len_to_move = 1;
    cur_match_dist = 0;
    cur_match_len = d->m_saved_match_len ? d->m_saved_match_len : (TDEFL_MIN_MATCH_LEN - 1);
    cur_pos = d->m_lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK;
    if (d->m_flags & (TDEFL_RLE_MATCHES | TDEFL_FORCE_ALL_RAW_BLOCKS)) {
      if ((d->m_dict_size) && (!(d->m_flags & TDEFL_FORCE_ALL_RAW_BLOCKS))) {
        MINI_uint8 c = d->m_dict[(cur_pos - 1) & TDEFL_LZ_DICT_SIZE_MASK];
        cur_match_len = 0;
        while (cur_match_len < d->m_lookahead_size) {
          if (d->m_dict[cur_pos + cur_match_len] != c)
            break;
          cur_match_len++;
        }
        if (cur_match_len < TDEFL_MIN_MATCH_LEN)
          cur_match_len = 0;
        else
          cur_match_dist = 1;
      }
    } else {
      tdefl_find_match(d, d->m_lookahead_pos, d->m_dict_size, d->m_lookahead_size, &cur_match_dist, &cur_match_len);
    }
    if (((cur_match_len == TDEFL_MIN_MATCH_LEN) &&
         (cur_match_dist >= 8U * 1024U)) ||
        (cur_pos == cur_match_dist) ||
        ((d->m_flags & TDEFL_FILTER_MATCHES) && (cur_match_len <= 5))) {
      cur_match_dist = cur_match_len = 0;
    }
    if (d->m_saved_match_len) {
      if (cur_match_len > d->m_saved_match_len) {
        tdefl_record_literal(d, (MINI_uint8)d->m_saved_lit);
        if (cur_match_len >= 128) {
          tdefl_record_match(d, cur_match_len, cur_match_dist);
          d->m_saved_match_len = 0;
          len_to_move = cur_match_len;
        } else {
          d->m_saved_lit = d->m_dict[cur_pos];
          d->m_saved_match_dist = cur_match_dist;
          d->m_saved_match_len = cur_match_len;
        }
      } else {
        tdefl_record_match(d, d->m_saved_match_len, d->m_saved_match_dist);
        len_to_move = d->m_saved_match_len - 1;
        d->m_saved_match_len = 0;
      }
    } else if (!cur_match_dist)
      tdefl_record_literal(d, d->m_dict[MINI_MIN(cur_pos, sizeof(d->m_dict) - 1)]);
    else if ((d->m_greedy_parsing) || (d->m_flags & TDEFL_RLE_MATCHES) ||
             (cur_match_len >= 128)) {
      tdefl_record_match(d, cur_match_len, cur_match_dist);
      len_to_move = cur_match_len;
    } else {
      d->m_saved_lit = d->m_dict[MINI_MIN(cur_pos, sizeof(d->m_dict) - 1)];
      d->m_saved_match_dist = cur_match_dist;
      d->m_saved_match_len = cur_match_len;
    }
    d->m_lookahead_pos += len_to_move;
    MINI_ASSERT(d->m_lookahead_size >= len_to_move);
    d->m_lookahead_size -= len_to_move;
    d->m_dict_size = MINI_MIN(d->m_dict_size + len_to_move, TDEFL_LZ_DICT_SIZE);
    if ((d->m_pLZ_code_buf > &d->m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE - 8]) ||
        ((d->m_total_lz_bytes > 31 * 1024) &&
         (((((MINI_uint)(d->m_pLZ_code_buf - d->m_lz_code_buf) * 115) >> 7) >= d->m_total_lz_bytes) ||
          (d->m_flags & TDEFL_FORCE_ALL_RAW_BLOCKS)))) {
      int n;
      d->m_pSrc = pSrc;
      d->m_src_buf_left = src_buf_left;
      if ((n = tdefl_flush_block(d, 0)) != 0)
        return (n < 0) ? MINI_FALSE : MINI_TRUE;
    }
  }
  d->m_pSrc = pSrc;
  d->m_src_buf_left = src_buf_left;
  return MINI_TRUE;
}
static tdefl_status tdefl_flush_output_buffer(tdefl_compressor *d) {
  if (d->m_pIn_buf_size) {
    *d->m_pIn_buf_size = d->m_pSrc - (const MINI_uint8 *)d->m_pIn_buf;
  }
  if (d->m_pOut_buf_size) {
    size_t n = MINI_MIN(*d->m_pOut_buf_size - d->m_out_buf_ofs, d->m_output_flush_remaining);
    memcpy((MINI_uint8 *)d->m_pOut_buf + d->m_out_buf_ofs, d->m_output_buf + d->m_output_flush_ofs, n);
    d->m_output_flush_ofs += (MINI_uint)n;
    d->m_output_flush_remaining -= (MINI_uint)n;
    d->m_out_buf_ofs += n;
    *d->m_pOut_buf_size = d->m_out_buf_ofs;
  }
  return (d->m_finished && !d->m_output_flush_remaining) ? TDEFL_STATUS_DONE
                                                         : TDEFL_STATUS_OKAY;
}
tdefl_status tdefl_compress(tdefl_compressor *d, const void *pIn_buf, size_t *pIn_buf_size, void *pOut_buf, size_t *pOut_buf_size, tdefl_flush flush) {
  if (!d) {
    if (pIn_buf_size)
      *pIn_buf_size = 0;
    if (pOut_buf_size)
      *pOut_buf_size = 0;
    return TDEFL_STATUS_BAD_PARAM;
  }
  d->m_pIn_buf = pIn_buf;
  d->m_pIn_buf_size = pIn_buf_size;
  d->m_pOut_buf = pOut_buf;
  d->m_pOut_buf_size = pOut_buf_size;
  d->m_pSrc = (const MINI_uint8 *)(pIn_buf);
  d->m_src_buf_left = pIn_buf_size ? *pIn_buf_size : 0;
  d->m_out_buf_ofs = 0;
  d->m_flush = flush;
  if (((d->m_pPut_buf_func != NULL) == ((pOut_buf != NULL) || (pOut_buf_size != NULL))) ||
      (d->m_prev_return_status != TDEFL_STATUS_OKAY) ||
      (d->m_wants_to_finish && (flush != TDEFL_FINISH)) ||
      (pIn_buf_size && *pIn_buf_size && !pIn_buf) ||
      (pOut_buf_size && *pOut_buf_size && !pOut_buf)) {
    if (pIn_buf_size)
      *pIn_buf_size = 0;
    if (pOut_buf_size)
      *pOut_buf_size = 0;
    return (d->m_prev_return_status = TDEFL_STATUS_BAD_PARAM);
  }
  d->m_wants_to_finish |= (flush == TDEFL_FINISH);
  if ((d->m_output_flush_remaining) || (d->m_finished))
    return (d->m_prev_return_status = tdefl_flush_output_buffer(d));
#if MINI_USE_UNALIGNED_LOADS_AND_STORES && MINI_LITTLE_ENDIAN
  if (((d->m_flags & TDEFL_MAX_PROBES_MASK) == 1) &&
      ((d->m_flags & TDEFL_GREEDY_PARSING_FLAG) != 0) &&
      ((d->m_flags & (TDEFL_FILTER_MATCHES | TDEFL_FORCE_ALL_RAW_BLOCKS |
                      TDEFL_RLE_MATCHES)) == 0)) {
    if (!tdefl_compress_fast(d))
      return d->m_prev_return_status;
  } else
#endif
  {
    if (!tdefl_compress_normal(d))
      return d->m_prev_return_status;
  }
  if ((d->m_flags & (TDEFL_WRITE_ZLIB_HEADER | TDEFL_COMPUTE_ADLER32)) &&
      (pIn_buf))
    d->m_adler32 = (MINI_uint32)MINI_adler32(d->m_adler32, (const MINI_uint8 *)pIn_buf, d->m_pSrc - (const MINI_uint8 *)pIn_buf);
  if ((flush) && (!d->m_lookahead_size) && (!d->m_src_buf_left) &&
      (!d->m_output_flush_remaining)) {
    if (tdefl_flush_block(d, flush) < 0)
      return d->m_prev_return_status;
    d->m_finished = (flush == TDEFL_FINISH);
    if (flush == TDEFL_FULL_FLUSH) {
      MINI_CLEAR_OBJ(d->m_hash);
      MINI_CLEAR_OBJ(d->m_next);
      d->m_dict_size = 0;
    }
  }
  return (d->m_prev_return_status = tdefl_flush_output_buffer(d));
}
tdefl_status tdefl_compress_buffer(tdefl_compressor *d, const void *pIn_buf, size_t in_buf_size, tdefl_flush flush) {
  MINI_ASSERT(d->m_pPut_buf_func);
  return tdefl_compress(d, pIn_buf, &in_buf_size, NULL, NULL, flush);
}
tdefl_status tdefl_init(tdefl_compressor *d, tdefl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags) {
  d->m_pPut_buf_func = pPut_buf_func;
  d->m_pPut_buf_user = pPut_buf_user;
  d->m_flags = (MINI_uint)(flags);
  d->m_max_probes[0] = 1 + ((flags & 0xFFF) + 2) / 3;
  d->m_greedy_parsing = (flags & TDEFL_GREEDY_PARSING_FLAG) != 0;
  d->m_max_probes[1] = 1 + (((flags & 0xFFF) >> 2) + 2) / 3;
  if (!(flags & TDEFL_NONDETERMINISTIC_PARSING_FLAG))
    MINI_CLEAR_OBJ(d->m_hash);
  d->m_lookahead_pos = d->m_lookahead_size = d->m_dict_size = d->m_total_lz_bytes = d->m_lz_code_buf_dict_pos = d->m_bits_in = 0;
  d->m_output_flush_ofs = d->m_output_flush_remaining = d->m_finished = d->m_block_index = d->m_bit_buffer = d->m_wants_to_finish = 0;
  d->m_pLZ_code_buf = d->m_lz_code_buf + 1;
  d->m_pLZ_flags = d->m_lz_code_buf;
  d->m_num_flags_left = 8;
  d->m_pOutput_buf = d->m_output_buf;
  d->m_pOutput_buf_end = d->m_output_buf;
  d->m_prev_return_status = TDEFL_STATUS_OKAY;
  d->m_saved_match_dist = d->m_saved_match_len = d->m_saved_lit = 0;
  d->m_adler32 = 1;
  d->m_pIn_buf = NULL;
  d->m_pOut_buf = NULL;
  d->m_pIn_buf_size = NULL;
  d->m_pOut_buf_size = NULL;
  d->m_flush = TDEFL_NO_FLUSH;
  d->m_pSrc = NULL;
  d->m_src_buf_left = 0;
  d->m_out_buf_ofs = 0;
  memset(&d->m_huff_count[0][0], 0, sizeof(d->m_huff_count[0][0]) * TDEFL_MAX_HUFF_SYMBOLS_0);
  memset(&d->m_huff_count[1][0], 0, sizeof(d->m_huff_count[1][0]) * TDEFL_MAX_HUFF_SYMBOLS_1);
  return TDEFL_STATUS_OKAY;
}
tdefl_status tdefl_get_prev_return_status(tdefl_compressor *d) {
  return d->m_prev_return_status;
}
MINI_uint32 tdefl_get_adler32(tdefl_compressor *d) { return d->m_adler32; }
MINI_bool tdefl_compress_mem_to_output(const void *pBuf, size_t buf_len, tdefl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags) {
  tdefl_compressor *pComp;
  MINI_bool succeeded;
  if (((buf_len) && (!pBuf)) || (!pPut_buf_func))
    return MINI_FALSE;
  pComp = (tdefl_compressor *)MINI_MALLOC(sizeof(tdefl_compressor));
  if (!pComp)
    return MINI_FALSE;
  succeeded = (tdefl_init(pComp, pPut_buf_func, pPut_buf_user, flags) == TDEFL_STATUS_OKAY);
  succeeded = succeeded && (tdefl_compress_buffer(pComp, pBuf, buf_len, TDEFL_FINISH) == TDEFL_STATUS_DONE);
  MINI_FREE(pComp);
  return succeeded;
}
typedef struct {
  size_t m_size, m_capacity;
  MINI_uint8 *m_pBuf;
  MINI_bool m_expandable;
} tdefl_output_buffer;
static MINI_bool tdefl_output_buffer_putter(const void *pBuf, int len, void *pUser) {
  tdefl_output_buffer *p = (tdefl_output_buffer *)pUser;
  size_t new_size = p->m_size + len;
  if (new_size > p->m_capacity) {
    size_t new_capacity = p->m_capacity;
    MINI_uint8 *pNew_buf;
    if (!p->m_expandable)
      return MINI_FALSE;
    do {
      new_capacity = MINI_MAX(128U, new_capacity << 1U);
    } while (new_size > new_capacity);
    pNew_buf = (MINI_uint8 *)MINI_REALLOC(p->m_pBuf, new_capacity);
    if (!pNew_buf)
      return MINI_FALSE;
    p->m_pBuf = pNew_buf;
    p->m_capacity = new_capacity;
  }
  memcpy((MINI_uint8 *)p->m_pBuf + p->m_size, pBuf, len);
  p->m_size = new_size;
  return MINI_TRUE;
}
void *tdefl_compress_mem_to_heap(const void *pSrc_buf, size_t src_buf_len, size_t *pOut_len, int flags) {
  tdefl_output_buffer out_buf;
  MINI_CLEAR_OBJ(out_buf);
  if (!pOut_len)
    return MINI_FALSE;
  else
    *pOut_len = 0;
  out_buf.m_expandable = MINI_TRUE;
  if (!tdefl_compress_mem_to_output(
          pSrc_buf, src_buf_len, tdefl_output_buffer_putter, &out_buf, flags))
    return NULL;
  *pOut_len = out_buf.m_size;
  return out_buf.m_pBuf;
}
size_t tdefl_compress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len, int flags) {
  tdefl_output_buffer out_buf;
  MINI_CLEAR_OBJ(out_buf);
  if (!pOut_buf)
    return 0;
  out_buf.m_pBuf = (MINI_uint8 *)pOut_buf;
  out_buf.m_capacity = out_buf_len;
  if (!tdefl_compress_mem_to_output(
          pSrc_buf, src_buf_len, tdefl_output_buffer_putter, &out_buf, flags))
    return 0;
  return out_buf.m_size;
}
#ifndef MINI_NO_ZLIB_APIS
static const MINI_uint s_tdefl_num_probes[11] = {0,   1,   6,   32,  16,  32, 128, 256, 512, 768, 1500};
MINI_uint tdefl_create_comp_flags_from_zip_params(int level, int window_bits, int strategy) {
  MINI_uint comp_flags = s_tdefl_num_probes[(level >= 0) ? MINI_MIN(10, level) : MINI_DEFAULT_LEVEL] |
      ((level <= 3) ? TDEFL_GREEDY_PARSING_FLAG : 0);
  if (window_bits > 0)
    comp_flags |= TDEFL_WRITE_ZLIB_HEADER;
  if (!level)
    comp_flags |= TDEFL_FORCE_ALL_RAW_BLOCKS;
  else if (strategy == MINI_FILTERED)
    comp_flags |= TDEFL_FILTER_MATCHES;
  else if (strategy == MINI_HUFFMAN_ONLY)
    comp_flags &= ~TDEFL_MAX_PROBES_MASK;
  else if (strategy == MINI_FIXED)
    comp_flags |= TDEFL_FORCE_ALL_STATIC_BLOCKS;
  else if (strategy == MINI_RLE)
    comp_flags |= TDEFL_RLE_MATCHES;
  return comp_flags;
}
#endif
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4204)
#endif
void *tdefl_write_image_to_png_file_in_memory_ex(const void *pImage, int w, int h, int num_chans, size_t *pLen_out, MINI_uint level, MINI_bool flip) {
  static const MINI_uint s_tdefl_png_num_probes[11] = {
      0, 1, 6, 32, 16, 32, 128, 256, 512, 768, 1500};
  tdefl_compressor *pComp = (tdefl_compressor *)MINI_MALLOC(sizeof(tdefl_compressor));
  tdefl_output_buffer out_buf;
  int i, bpl = w * num_chans, y, z;
  MINI_uint32 c;
  *pLen_out = 0;
  if (!pComp)
    return NULL;
  MINI_CLEAR_OBJ(out_buf);
  out_buf.m_expandable = MINI_TRUE;
  out_buf.m_capacity = 57 + MINI_MAX(64, (1 + bpl) * h);
  if (NULL == (out_buf.m_pBuf = (MINI_uint8 *)MINI_MALLOC(out_buf.m_capacity))) {
    MINI_FREE(pComp);
    return NULL;
  }
  for (z = 41; z; --z)
    tdefl_output_buffer_putter(&z, 1, &out_buf);
  tdefl_init(pComp, tdefl_output_buffer_putter, &out_buf, s_tdefl_png_num_probes[MINI_MIN(10, level)] |
                 TDEFL_WRITE_ZLIB_HEADER);
  for (y = 0; y < h; ++y) {
    tdefl_compress_buffer(pComp, &z, 1, TDEFL_NO_FLUSH);
    tdefl_compress_buffer(pComp, (MINI_uint8 *)pImage + (flip ? (h - 1 - y) : y) * bpl, bpl, TDEFL_NO_FLUSH);
  }
  if (tdefl_compress_buffer(pComp, NULL, 0, TDEFL_FINISH) != TDEFL_STATUS_DONE) {
    MINI_FREE(pComp);
    MINI_FREE(out_buf.m_pBuf);
    return NULL;
  }
  *pLen_out = out_buf.m_size - 41;
  {
    static const MINI_uint8 chans[] = {0x00, 0x00, 0x04, 0x02, 0x06};
    MINI_uint8 pnghdr[41] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0, 0, (MINI_uint8)(w >> 8), (MINI_uint8)w, 0, 0, (MINI_uint8)(h >> 8), (MINI_uint8)h, 8, chans[num_chans], 0, 0, 0, 0, 0, 0, 0, (MINI_uint8)(*pLen_out >> 24), (MINI_uint8)(*pLen_out >> 16), (MINI_uint8)(*pLen_out >> 8), (MINI_uint8)*pLen_out, 0x49, 0x44, 0x41, 0x54};
    c = (MINI_uint32)MINI_crc32(MINI_CRC32_INIT, pnghdr + 12, 17);
    for (i = 0; i < 4; ++i, c <<= 8)
      ((MINI_uint8 *)(pnghdr + 29))[i] = (MINI_uint8)(c >> 24);
    memcpy(out_buf.m_pBuf, pnghdr, 41);
  }
  if (!tdefl_output_buffer_putter(
          "\0\0\0\0\0\0\0\0\x49\x45\x4e\x44\xae\x42\x60\x82", 16, &out_buf)) {
    *pLen_out = 0;
    MINI_FREE(pComp);
    MINI_FREE(out_buf.m_pBuf);
    return NULL;
  }
  c = (MINI_uint32)MINI_crc32(MINI_CRC32_INIT, out_buf.m_pBuf + 41 - 4, *pLen_out + 4);
  for (i = 0; i < 4; ++i, c <<= 8)
    (out_buf.m_pBuf + out_buf.m_size - 16)[i] = (MINI_uint8)(c >> 24);
  *pLen_out += 57;
  MINI_FREE(pComp);
  return out_buf.m_pBuf;
}
void *tdefl_write_image_to_png_file_in_memory(const void *pImage, int w, int h, int num_chans, size_t *pLen_out) {
  return tdefl_write_image_to_png_file_in_memory_ex(pImage, w, h, num_chans, pLen_out, 6, MINI_FALSE);
}
tdefl_compressor *tdefl_compressor_alloc() {
  return (tdefl_compressor *)MINI_MALLOC(sizeof(tdefl_compressor));
}
void tdefl_compressor_free(tdefl_compressor *pComp) { MINI_FREE(pComp); }
tinfl_decompressor *tinfl_decompressor_alloc() {
  tinfl_decompressor *pDecomp = (tinfl_decompressor *)MINI_MALLOC(sizeof(tinfl_decompressor));
  if (pDecomp)
    tinfl_init(pDecomp);
  return pDecomp;
}
void tinfl_decompressor_free(tinfl_decompressor *pDecomp) { MINI_FREE(pDecomp); }
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#ifndef MINI_NO_ARCHIVE_APIS
#ifdef MINI_NO_STDIO
#define MINI_FILE void *
#else
#include <stdio.h>
#include <sys/stat.h>
#if defined(_MSC_VER) || defined(__MINGW64__)
static FILE *MINI_fopen(const char *pFilename, const char *pMode) {
  FILE *pFile = NULL;
  fopen_s(&pFile, pFilename, pMode);
  return pFile;
}
static FILE *MINI_freopen(const char *pPath, const char *pMode, FILE *pStream) {
  FILE *pFile = NULL;
  if (freopen_s(&pFile, pPath, pMode, pStream))
    return NULL;
  return pFile;
}
#ifndef MINI_NO_TIME
#include <sys/utime.h>
#endif
#define MINI_FILE FILE
#define MINI_FOPEN MINI_fopen
#define MINI_FCLOSE fclose
#define MINI_FREAD fread
#define MINI_FWRITE fwrite
#define MINI_FTELL64 _ftelli64
#define MINI_FSEEK64 _fseeki64
#define MINI_FILE_STAT_STRUCT _stat
#define MINI_FILE_STAT _stat
#define MINI_FFLUSH fflush
#define MINI_FREOPEN MINI_freopen
#define MINI_DELETE_FILE remove
#elif defined(__MINGW32__)
#ifndef MINI_NO_TIME
#include <sys/utime.h>
#endif
#define MINI_FILE FILE
#define MINI_FOPEN(f, m) fopen(f, m)
#define MINI_FCLOSE fclose
#define MINI_FREAD fread
#define MINI_FWRITE fwrite
#define MINI_FTELL64 ftello64
#define MINI_FSEEK64 fseeko64
#define MINI_FILE_STAT_STRUCT _stat
#define MINI_FILE_STAT _stat
#define MINI_FFLUSH fflush
#define MINI_FREOPEN(f, m, s) freopen(f, m, s)
#define MINI_DELETE_FILE remove
#elif defined(__TINYC__)
#ifndef MINI_NO_TIME
#include <sys/utime.h>
#endif
#define MINI_FILE FILE
#define MINI_FOPEN(f, m) fopen(f, m)
#define MINI_FCLOSE fclose
#define MINI_FREAD fread
#define MINI_FWRITE fwrite
#define MINI_FTELL64 ftell
#define MINI_FSEEK64 fseek
#define MINI_FILE_STAT_STRUCT stat
#define MINI_FILE_STAT stat
#define MINI_FFLUSH fflush
#define MINI_FREOPEN(f, m, s) freopen(f, m, s)
#define MINI_DELETE_FILE remove
#elif defined(__GNUC__) && _LARGEFILE64_SOURCE
#ifndef MINI_NO_TIME
#include <utime.h>
#endif
#define MINI_FILE FILE
#define MINI_FOPEN(f, m) fopen64(f, m)
#define MINI_FCLOSE fclose
#define MINI_FREAD fread
#define MINI_FWRITE fwrite
#define MINI_FTELL64 ftello64
#define MINI_FSEEK64 fseeko64
#define MINI_FILE_STAT_STRUCT stat64
#define MINI_FILE_STAT stat64
#define MINI_FFLUSH fflush
#define MINI_FREOPEN(p, m, s) freopen64(p, m, s)
#define MINI_DELETE_FILE remove
#else
#ifndef MINI_NO_TIME
#include <utime.h>
#endif
#define MINI_FILE FILE
#define MINI_FOPEN(f, m) fopen(f, m)
#define MINI_FCLOSE fclose
#define MINI_FREAD fread
#define MINI_FWRITE fwrite
#define MINI_FTELL64 ftello
#define MINI_FSEEK64 fseeko
#define MINI_FILE_STAT_STRUCT stat
#define MINI_FILE_STAT stat
#define MINI_FFLUSH fflush
#define MINI_FREOPEN(f, m, s) freopen(f, m, s)
#define MINI_DELETE_FILE remove
#endif
#endif
#define MINI_TOLOWER(c) ((((c) >= 'A') && ((c) <= 'Z')) ? ((c) - 'A' + 'a') : (c))
enum {
  MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG = 0x06054b50, MINI_ZIP_CENTRAL_DIR_HEADER_SIG = 0x02014b50, MINI_ZIP_LOCAL_DIR_HEADER_SIG = 0x04034b50, MINI_ZIP_LOCAL_DIR_HEADER_SIZE = 30, MINI_ZIP_CENTRAL_DIR_HEADER_SIZE = 46, MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE = 22, MINI_ZIP_CDH_SIG_OFS = 0, MINI_ZIP_CDH_VERSION_MADE_BY_OFS = 4, MINI_ZIP_CDH_VERSION_NEEDED_OFS = 6, MINI_ZIP_CDH_BIT_FLAG_OFS = 8, MINI_ZIP_CDH_METHOD_OFS = 10, MINI_ZIP_CDH_FILE_TIME_OFS = 12, MINI_ZIP_CDH_FILE_DATE_OFS = 14, MINI_ZIP_CDH_CRC32_OFS = 16, MINI_ZIP_CDH_COMPRESSED_SIZE_OFS = 20, MINI_ZIP_CDH_DECOMPRESSED_SIZE_OFS = 24, MINI_ZIP_CDH_FILENAME_LEN_OFS = 28, MINI_ZIP_CDH_EXTRA_LEN_OFS = 30, MINI_ZIP_CDH_COMMENT_LEN_OFS = 32, MINI_ZIP_CDH_DISK_START_OFS = 34, MINI_ZIP_CDH_INTERNAL_ATTR_OFS = 36, MINI_ZIP_CDH_EXTERNAL_ATTR_OFS = 38, MINI_ZIP_CDH_LOCAL_HEADER_OFS = 42, MINI_ZIP_LDH_SIG_OFS = 0, MINI_ZIP_LDH_VERSION_NEEDED_OFS = 4, MINI_ZIP_LDH_BIT_FLAG_OFS = 6, MINI_ZIP_LDH_METHOD_OFS = 8, MINI_ZIP_LDH_FILE_TIME_OFS = 10, MINI_ZIP_LDH_FILE_DATE_OFS = 12, MINI_ZIP_LDH_CRC32_OFS = 14, MINI_ZIP_LDH_COMPRESSED_SIZE_OFS = 18, MINI_ZIP_LDH_DECOMPRESSED_SIZE_OFS = 22, MINI_ZIP_LDH_FILENAME_LEN_OFS = 26, MINI_ZIP_LDH_EXTRA_LEN_OFS = 28, MINI_ZIP_ECDH_SIG_OFS = 0, MINI_ZIP_ECDH_NUM_THIS_DISK_OFS = 4, MINI_ZIP_ECDH_NUM_DISK_CDIR_OFS = 6, MINI_ZIP_ECDH_CDIR_NUM_ENTRIES_ON_DISK_OFS = 8, MINI_ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS = 10, MINI_ZIP_ECDH_CDIR_SIZE_OFS = 12, MINI_ZIP_ECDH_CDIR_OFS_OFS = 16, MINI_ZIP_ECDH_COMMENT_SIZE_OFS = 20,
};
typedef struct {
  void *m_p;
  size_t m_size, m_capacity;
  MINI_uint m_element_size;
} MINI_zip_array;
struct MINI_zip_internal_state_tag {
  MINI_zip_array m_central_dir;
  MINI_zip_array m_central_dir_offsets;
  MINI_zip_array m_sorted_central_dir_offsets;
  MINI_FILE *m_pFile;
  void *m_pMem;
  size_t m_mem_size;
  size_t m_mem_capacity;
};
#define MINI_ZIP_ARRAY_SET_ELEMENT_SIZE(array_ptr, element_size)                 \
  (array_ptr)->m_element_size = element_size
#define MINI_ZIP_ARRAY_ELEMENT(array_ptr, element_type, index)                   \
  ((element_type *)((array_ptr)->m_p))[index]
static MINI_FORCEINLINE void MINI_zip_array_clear(MINI_zip_archive *pZip, MINI_zip_array *pArray) {
  pZip->m_pFree(pZip->m_pAlloc_opaque, pArray->m_p);
  memset(pArray, 0, sizeof(MINI_zip_array));
}
static MINI_bool MINI_zip_array_ensure_capacity(MINI_zip_archive *pZip, MINI_zip_array *pArray, size_t min_new_capacity, MINI_uint growing) {
  void *pNew_p;
  size_t new_capacity = min_new_capacity;
  MINI_ASSERT(pArray->m_element_size);
  if (pArray->m_capacity >= min_new_capacity)
    return MINI_TRUE;
  if (growing) {
    new_capacity = MINI_MAX(1, pArray->m_capacity);
    while (new_capacity < min_new_capacity)
      new_capacity *= 2;
  }
  if (NULL == (pNew_p = pZip->m_pRealloc(pZip->m_pAlloc_opaque, pArray->m_p, pArray->m_element_size, new_capacity)))
    return MINI_FALSE;
  pArray->m_p = pNew_p;
  pArray->m_capacity = new_capacity;
  return MINI_TRUE;
}
static MINI_FORCEINLINE MINI_bool MINI_zip_array_reserve(MINI_zip_archive *pZip, MINI_zip_array *pArray, size_t new_capacity, MINI_uint growing) {
  if (new_capacity > pArray->m_capacity) {
    if (!MINI_zip_array_ensure_capacity(pZip, pArray, new_capacity, growing))
      return MINI_FALSE;
  }
  return MINI_TRUE;
}
static MINI_FORCEINLINE MINI_bool MINI_zip_array_resize(MINI_zip_archive *pZip, MINI_zip_array *pArray, size_t new_size, MINI_uint growing) {
  if (new_size > pArray->m_capacity) {
    if (!MINI_zip_array_ensure_capacity(pZip, pArray, new_size, growing))
      return MINI_FALSE;
  }
  pArray->m_size = new_size;
  return MINI_TRUE;
}
static MINI_FORCEINLINE MINI_bool MINI_zip_array_ensure_room(MINI_zip_archive *pZip, MINI_zip_array *pArray, size_t n) {
  return MINI_zip_array_reserve(pZip, pArray, pArray->m_size + n, MINI_TRUE);
}
static MINI_FORCEINLINE MINI_bool MINI_zip_array_push_back(MINI_zip_archive *pZip, MINI_zip_array *pArray, const void *pElements, size_t n) {
  size_t orig_size = pArray->m_size;
  if (!MINI_zip_array_resize(pZip, pArray, orig_size + n, MINI_TRUE))
    return MINI_FALSE;
  memcpy((MINI_uint8 *)pArray->m_p + orig_size * pArray->m_element_size, pElements, n * pArray->m_element_size);
  return MINI_TRUE;
}
#ifndef MINI_NO_TIME
static time_t MINI_zip_dos_to_time_t(int dos_time, int dos_date) {
  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  tm.tm_isdst = -1;
  tm.tm_year = ((dos_date >> 9) & 127) + 1980 - 1900;
  tm.tm_mon = ((dos_date >> 5) & 15) - 1;
  tm.tm_mday = dos_date & 31;
  tm.tm_hour = (dos_time >> 11) & 31;
  tm.tm_min = (dos_time >> 5) & 63;
  tm.tm_sec = (dos_time << 1) & 62;
  return mktime(&tm);
}
static void MINI_zip_time_to_dos_time(time_t time, MINI_uint16 *pDOS_time, MINI_uint16 *pDOS_date) {
#ifdef _MSC_VER
  struct tm tm_struct;
  struct tm *tm = &tm_struct;
  errno_t err = localtime_s(tm, &time);
  if (err) {
    *pDOS_date = 0;
    *pDOS_time = 0;
    return;
  }
#else
  struct tm *tm = localtime(&time);
#endif
  *pDOS_time = (MINI_uint16)(((tm->tm_hour) << 11) + ((tm->tm_min) << 5) +
                           ((tm->tm_sec) >> 1));
  *pDOS_date = (MINI_uint16)(((tm->tm_year + 1900 - 1980) << 9) +
                           ((tm->tm_mon + 1) << 5) + tm->tm_mday);
}
#endif
#ifndef MINI_NO_STDIO
static MINI_bool MINI_zip_get_file_modified_time(const char *pFilename, MINI_uint16 *pDOS_time, MINI_uint16 *pDOS_date) {
#ifdef MINI_NO_TIME
  (void)pFilename;
  *pDOS_date = *pDOS_time = 0;
#else
  struct MINI_FILE_STAT_STRUCT file_stat;
  if (MINI_FILE_STAT(pFilename, &file_stat) != 0)
    return MINI_FALSE;
  MINI_zip_time_to_dos_time(file_stat.st_mtime, pDOS_time, pDOS_date);
#endif
  return MINI_TRUE;
}
#ifndef MINI_NO_TIME
static MINI_bool MINI_zip_set_file_times(const char *pFilename, time_t access_time, time_t modified_time) {
  struct utimbuf t;
  t.actime = access_time;
  t.modtime = modified_time;
  return !utime(pFilename, &t);
}
#endif
#endif
static MINI_bool MINI_zip_reader_init_internal(MINI_zip_archive *pZip, MINI_uint32 flags) {
  (void)flags;
  if ((!pZip) || (pZip->m_pState) || (pZip->m_zip_mode != MINI_ZIP_MODE_INVALID))
    return MINI_FALSE;
  if (!pZip->m_pAlloc)
    pZip->m_pAlloc = def_alloc_func;
  if (!pZip->m_pFree)
    pZip->m_pFree = def_free_func;
  if (!pZip->m_pRealloc)
    pZip->m_pRealloc = def_realloc_func;
  pZip->m_zip_mode = MINI_ZIP_MODE_READING;
  pZip->m_archive_size = 0;
  pZip->m_central_directory_file_ofs = 0;
  pZip->m_total_files = 0;
  if (NULL == (pZip->m_pState = (MINI_zip_internal_state *)pZip->m_pAlloc(
                   pZip->m_pAlloc_opaque, 1, sizeof(MINI_zip_internal_state))))
    return MINI_FALSE;
  memset(pZip->m_pState, 0, sizeof(MINI_zip_internal_state));
  MINI_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir, sizeof(MINI_uint8));
  MINI_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir_offsets, sizeof(MINI_uint32));
  MINI_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_sorted_central_dir_offsets, sizeof(MINI_uint32));
  return MINI_TRUE;
}
static MINI_FORCEINLINE MINI_bool
MINI_zip_reader_filename_less(const MINI_zip_array *pCentral_dir_array, const MINI_zip_array *pCentral_dir_offsets, MINI_uint l_index, MINI_uint r_index) {
  const MINI_uint8 *pL = &MINI_ZIP_ARRAY_ELEMENT(
                     pCentral_dir_array, MINI_uint8, MINI_ZIP_ARRAY_ELEMENT(pCentral_dir_offsets, MINI_uint32, l_index)), *pE;
  const MINI_uint8 *pR = &MINI_ZIP_ARRAY_ELEMENT(
      pCentral_dir_array, MINI_uint8, MINI_ZIP_ARRAY_ELEMENT(pCentral_dir_offsets, MINI_uint32, r_index));
  MINI_uint l_len = MINI_READ_LE16(pL + MINI_ZIP_CDH_FILENAME_LEN_OFS), r_len = MINI_READ_LE16(pR + MINI_ZIP_CDH_FILENAME_LEN_OFS);
  MINI_uint8 l = 0, r = 0;
  pL += MINI_ZIP_CENTRAL_DIR_HEADER_SIZE;
  pR += MINI_ZIP_CENTRAL_DIR_HEADER_SIZE;
  pE = pL + MINI_MIN(l_len, r_len);
  while (pL < pE) {
    if ((l = MINI_TOLOWER(*pL)) != (r = MINI_TOLOWER(*pR)))
      break;
    pL++;
    pR++;
  }
  return (pL == pE) ? (l_len < r_len) : (l < r);
}
#define MINI_SWAP_UINT32(a, b)                                                   \
  do {                                                                         \
    MINI_uint32 t = a;                                                           \
    a = b;                                                                     \
    b = t;                                                                     \
  }                                                                            \
  MINI_MACRO_END
static void
MINI_zip_reader_sort_central_dir_offsets_by_filename(MINI_zip_archive *pZip) {
  MINI_zip_internal_state *pState = pZip->m_pState;
  const MINI_zip_array *pCentral_dir_offsets = &pState->m_central_dir_offsets;
  const MINI_zip_array *pCentral_dir = &pState->m_central_dir;
  MINI_uint32 *pIndices = &MINI_ZIP_ARRAY_ELEMENT(
      &pState->m_sorted_central_dir_offsets, MINI_uint32, 0);
  const int size = pZip->m_total_files;
  int start = (size - 2) >> 1, end;
  while (start >= 0) {
    int child, root = start;
    for (;;) {
      if ((child = (root << 1) + 1) >= size)
        break;
      child += (((child + 1) < size) &&
           (MINI_zip_reader_filename_less(pCentral_dir, pCentral_dir_offsets, pIndices[child], pIndices[child + 1])));
      if (!MINI_zip_reader_filename_less(pCentral_dir, pCentral_dir_offsets, pIndices[root], pIndices[child]))
        break;
      MINI_SWAP_UINT32(pIndices[root], pIndices[child]);
      root = child;
    }
    start--;
  }
  end = size - 1;
  while (end > 0) {
    int child, root = 0;
    MINI_SWAP_UINT32(pIndices[end], pIndices[0]);
    for (;;) {
      if ((child = (root << 1) + 1) >= end)
        break;
      child += (((child + 1) < end) &&
           MINI_zip_reader_filename_less(pCentral_dir, pCentral_dir_offsets, pIndices[child], pIndices[child + 1]));
      if (!MINI_zip_reader_filename_less(pCentral_dir, pCentral_dir_offsets, pIndices[root], pIndices[child]))
        break;
      MINI_SWAP_UINT32(pIndices[root], pIndices[child]);
      root = child;
    }
    end--;
  }
}
static MINI_bool MINI_zip_reader_read_central_dir(MINI_zip_archive *pZip, MINI_uint32 flags) {
  MINI_uint cdir_size, num_this_disk, cdir_disk_index;
  MINI_uint64 cdir_ofs;
  MINI_int64 cur_file_ofs;
  const MINI_uint8 *p;
  MINI_uint32 buf_u32[4096 / sizeof(MINI_uint32)];
  MINI_uint8 *pBuf = (MINI_uint8 *)buf_u32;
  MINI_bool sort_central_dir = ((flags & MINI_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY) == 0);
  if (pZip->m_archive_size < MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)
    return MINI_FALSE;
  cur_file_ofs = MINI_MAX((MINI_int64)pZip->m_archive_size - (MINI_int64)sizeof(buf_u32), 0);
  for (;;) {
    int i, n = (int)MINI_MIN(sizeof(buf_u32), pZip->m_archive_size - cur_file_ofs);
    if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pBuf, n) != (MINI_uint)n)
      return MINI_FALSE;
    for (i = n - 4; i >= 0; --i)
      if (MINI_READ_LE32(pBuf + i) == MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG)
        break;
    if (i >= 0) {
      cur_file_ofs += i;
      break;
    }
    if ((!cur_file_ofs) || ((pZip->m_archive_size - cur_file_ofs) >= (0xFFFF + MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)))
      return MINI_FALSE;
    cur_file_ofs = MINI_MAX(cur_file_ofs - (sizeof(buf_u32) - 3), 0);
  }
  if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pBuf, MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE) != MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)
    return MINI_FALSE;
  if ((MINI_READ_LE32(pBuf + MINI_ZIP_ECDH_SIG_OFS) != MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG) ||
      ((pZip->m_total_files = MINI_READ_LE16(pBuf + MINI_ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS)) != MINI_READ_LE16(pBuf + MINI_ZIP_ECDH_CDIR_NUM_ENTRIES_ON_DISK_OFS)))
    return MINI_FALSE;
  num_this_disk = MINI_READ_LE16(pBuf + MINI_ZIP_ECDH_NUM_THIS_DISK_OFS);
  cdir_disk_index = MINI_READ_LE16(pBuf + MINI_ZIP_ECDH_NUM_DISK_CDIR_OFS);
  if (((num_this_disk | cdir_disk_index) != 0) &&
      ((num_this_disk != 1) || (cdir_disk_index != 1)))
    return MINI_FALSE;
  if ((cdir_size = MINI_READ_LE32(pBuf + MINI_ZIP_ECDH_CDIR_SIZE_OFS)) <
      pZip->m_total_files * MINI_ZIP_CENTRAL_DIR_HEADER_SIZE)
    return MINI_FALSE;
  cdir_ofs = MINI_READ_LE32(pBuf + MINI_ZIP_ECDH_CDIR_OFS_OFS);
  if ((cdir_ofs + (MINI_uint64)cdir_size) > pZip->m_archive_size)
    return MINI_FALSE;
  pZip->m_central_directory_file_ofs = cdir_ofs;
  if (pZip->m_total_files) {
    MINI_uint i, n;
    if ((!MINI_zip_array_resize(pZip, &pZip->m_pState->m_central_dir, cdir_size, MINI_FALSE)) ||
        (!MINI_zip_array_resize(pZip, &pZip->m_pState->m_central_dir_offsets, pZip->m_total_files, MINI_FALSE)))
      return MINI_FALSE;
    if (sort_central_dir) {
      if (!MINI_zip_array_resize(pZip, &pZip->m_pState->m_sorted_central_dir_offsets, pZip->m_total_files, MINI_FALSE))
        return MINI_FALSE;
    }
    if (pZip->m_pRead(pZip->m_pIO_opaque, cdir_ofs, pZip->m_pState->m_central_dir.m_p, cdir_size) != cdir_size)
      return MINI_FALSE;
    p = (const MINI_uint8 *)pZip->m_pState->m_central_dir.m_p;
    for (n = cdir_size, i = 0; i < pZip->m_total_files; ++i) {
      MINI_uint total_header_size, comp_size, decomp_size, disk_index;
      if ((n < MINI_ZIP_CENTRAL_DIR_HEADER_SIZE) ||
          (MINI_READ_LE32(p) != MINI_ZIP_CENTRAL_DIR_HEADER_SIG))
        return MINI_FALSE;
      MINI_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir_offsets, MINI_uint32, i) = (MINI_uint32)(p - (const MINI_uint8 *)pZip->m_pState->m_central_dir.m_p);
      if (sort_central_dir)
        MINI_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_sorted_central_dir_offsets, MINI_uint32, i) = i;
      comp_size = MINI_READ_LE32(p + MINI_ZIP_CDH_COMPRESSED_SIZE_OFS);
      decomp_size = MINI_READ_LE32(p + MINI_ZIP_CDH_DECOMPRESSED_SIZE_OFS);
      if (((!MINI_READ_LE32(p + MINI_ZIP_CDH_METHOD_OFS)) &&
           (decomp_size != comp_size)) ||
          (decomp_size && !comp_size) || (decomp_size == 0xFFFFFFFF) ||
          (comp_size == 0xFFFFFFFF))
        return MINI_FALSE;
      disk_index = MINI_READ_LE16(p + MINI_ZIP_CDH_DISK_START_OFS);
      if ((disk_index != num_this_disk) && (disk_index != 1))
        return MINI_FALSE;
      if (((MINI_uint64)MINI_READ_LE32(p + MINI_ZIP_CDH_LOCAL_HEADER_OFS) +
           MINI_ZIP_LOCAL_DIR_HEADER_SIZE + comp_size) > pZip->m_archive_size)
        return MINI_FALSE;
      if ((total_header_size = MINI_ZIP_CENTRAL_DIR_HEADER_SIZE +
                               MINI_READ_LE16(p + MINI_ZIP_CDH_FILENAME_LEN_OFS) +
                               MINI_READ_LE16(p + MINI_ZIP_CDH_EXTRA_LEN_OFS) +
                               MINI_READ_LE16(p + MINI_ZIP_CDH_COMMENT_LEN_OFS)) >
          n)
        return MINI_FALSE;
      n -= total_header_size;
      p += total_header_size;
    }
  }
  if (sort_central_dir)
    MINI_zip_reader_sort_central_dir_offsets_by_filename(pZip);
  return MINI_TRUE;
}
MINI_bool MINI_zip_reader_init(MINI_zip_archive *pZip, MINI_uint64 size, MINI_uint32 flags) {
  if ((!pZip) || (!pZip->m_pRead))
    return MINI_FALSE;
  if (!MINI_zip_reader_init_internal(pZip, flags))
    return MINI_FALSE;
  pZip->m_archive_size = size;
  if (!MINI_zip_reader_read_central_dir(pZip, flags)) {
    MINI_zip_reader_end(pZip);
    return MINI_FALSE;
  }
  return MINI_TRUE;
}
static size_t MINI_zip_mem_read_func(void *pOpaque, MINI_uint64 file_ofs, void *pBuf, size_t n) {
  MINI_zip_archive *pZip = (MINI_zip_archive *)pOpaque;
  size_t s = (file_ofs >= pZip->m_archive_size)
                 ? 0
                 : (size_t)MINI_MIN(pZip->m_archive_size - file_ofs, n);
  memcpy(pBuf, (const MINI_uint8 *)pZip->m_pState->m_pMem + file_ofs, s);
  return s;
}
MINI_bool MINI_zip_reader_init_mem(MINI_zip_archive *pZip, const void *pMem, size_t size, MINI_uint32 flags) {
  if (!MINI_zip_reader_init_internal(pZip, flags))
    return MINI_FALSE;
  pZip->m_archive_size = size;
  pZip->m_pRead = MINI_zip_mem_read_func;
  pZip->m_pIO_opaque = pZip;
#ifdef __cplusplus
  pZip->m_pState->m_pMem = const_cast<void *>(pMem);
#else
  pZip->m_pState->m_pMem = (void *)pMem;
#endif
  pZip->m_pState->m_mem_size = size;
  if (!MINI_zip_reader_read_central_dir(pZip, flags)) {
    MINI_zip_reader_end(pZip);
    return MINI_FALSE;
  }
  return MINI_TRUE;
}
#ifndef MINI_NO_STDIO
static size_t MINI_zip_file_read_func(void *pOpaque, MINI_uint64 file_ofs, void *pBuf, size_t n) {
  MINI_zip_archive *pZip = (MINI_zip_archive *)pOpaque;
  MINI_int64 cur_ofs = MINI_FTELL64(pZip->m_pState->m_pFile);
  if (((MINI_int64)file_ofs < 0) ||
      (((cur_ofs != (MINI_int64)file_ofs)) &&
       (MINI_FSEEK64(pZip->m_pState->m_pFile, (MINI_int64)file_ofs, SEEK_SET))))
    return 0;
  return MINI_FREAD(pBuf, 1, n, pZip->m_pState->m_pFile);
}
MINI_bool MINI_zip_reader_init_file(MINI_zip_archive *pZip, const char *pFilename, MINI_uint32 flags) {
  MINI_uint64 file_size;
  MINI_FILE *pFile = MINI_FOPEN(pFilename, "rb");
  if (!pFile)
    return MINI_FALSE;
  if (MINI_FSEEK64(pFile, 0, SEEK_END)) {
    MINI_FCLOSE(pFile);
    return MINI_FALSE;
  }
  file_size = MINI_FTELL64(pFile);
  if (!MINI_zip_reader_init_internal(pZip, flags)) {
    MINI_FCLOSE(pFile);
    return MINI_FALSE;
  }
  pZip->m_pRead = MINI_zip_file_read_func;
  pZip->m_pIO_opaque = pZip;
  pZip->m_pState->m_pFile = pFile;
  pZip->m_archive_size = file_size;
  if (!MINI_zip_reader_read_central_dir(pZip, flags)) {
    MINI_zip_reader_end(pZip);
    return MINI_FALSE;
  }
  return MINI_TRUE;
}
#endif
MINI_uint MINI_zip_reader_get_num_files(MINI_zip_archive *pZip) {
  return pZip ? pZip->m_total_files : 0;
}
static MINI_FORCEINLINE const MINI_uint8 *
MINI_zip_reader_get_cdh(MINI_zip_archive *pZip, MINI_uint file_index) {
  if ((!pZip) || (!pZip->m_pState) || (file_index >= pZip->m_total_files) ||
      (pZip->m_zip_mode != MINI_ZIP_MODE_READING))
    return NULL;
  return &MINI_ZIP_ARRAY_ELEMENT(
      &pZip->m_pState->m_central_dir, MINI_uint8, MINI_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir_offsets, MINI_uint32, file_index));
}
MINI_bool MINI_zip_reader_is_file_encrypted(MINI_zip_archive *pZip, MINI_uint file_index) {
  MINI_uint m_bit_flag;
  const MINI_uint8 *p = MINI_zip_reader_get_cdh(pZip, file_index);
  if (!p)
    return MINI_FALSE;
  m_bit_flag = MINI_READ_LE16(p + MINI_ZIP_CDH_BIT_FLAG_OFS);
  return (m_bit_flag & 1);
}
MINI_bool MINI_zip_reader_is_file_a_directory(MINI_zip_archive *pZip, MINI_uint file_index) {
  MINI_uint filename_len, external_attr;
  const MINI_uint8 *p = MINI_zip_reader_get_cdh(pZip, file_index);
  if (!p)
    return MINI_FALSE;
  filename_len = MINI_READ_LE16(p + MINI_ZIP_CDH_FILENAME_LEN_OFS);
  if (filename_len) {
    if (*(p + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE + filename_len - 1) == '/')
      return MINI_TRUE;
  }
  external_attr = MINI_READ_LE32(p + MINI_ZIP_CDH_EXTERNAL_ATTR_OFS);
  if ((external_attr & 0x10) != 0)
    return MINI_TRUE;
  return MINI_FALSE;
}
MINI_bool MINI_zip_reader_file_stat(MINI_zip_archive *pZip, MINI_uint file_index, MINI_zip_archive_file_stat *pStat) {
  MINI_uint n;
  const MINI_uint8 *p = MINI_zip_reader_get_cdh(pZip, file_index);
  if ((!p) || (!pStat))
    return MINI_FALSE;
  pStat->m_file_index = file_index;
  pStat->m_central_dir_ofs = MINI_ZIP_ARRAY_ELEMENT(
      &pZip->m_pState->m_central_dir_offsets, MINI_uint32, file_index);
  pStat->m_version_made_by = MINI_READ_LE16(p + MINI_ZIP_CDH_VERSION_MADE_BY_OFS);
  pStat->m_version_needed = MINI_READ_LE16(p + MINI_ZIP_CDH_VERSION_NEEDED_OFS);
  pStat->m_bit_flag = MINI_READ_LE16(p + MINI_ZIP_CDH_BIT_FLAG_OFS);
  pStat->m_method = MINI_READ_LE16(p + MINI_ZIP_CDH_METHOD_OFS);
#ifndef MINI_NO_TIME
  pStat->m_time = MINI_zip_dos_to_time_t(MINI_READ_LE16(p + MINI_ZIP_CDH_FILE_TIME_OFS), MINI_READ_LE16(p + MINI_ZIP_CDH_FILE_DATE_OFS));
#endif
  pStat->m_crc32 = MINI_READ_LE32(p + MINI_ZIP_CDH_CRC32_OFS);
  pStat->m_comp_size = MINI_READ_LE32(p + MINI_ZIP_CDH_COMPRESSED_SIZE_OFS);
  pStat->m_uncomp_size = MINI_READ_LE32(p + MINI_ZIP_CDH_DECOMPRESSED_SIZE_OFS);
  pStat->m_internal_attr = MINI_READ_LE16(p + MINI_ZIP_CDH_INTERNAL_ATTR_OFS);
  pStat->m_external_attr = MINI_READ_LE32(p + MINI_ZIP_CDH_EXTERNAL_ATTR_OFS);
  pStat->m_local_header_ofs = MINI_READ_LE32(p + MINI_ZIP_CDH_LOCAL_HEADER_OFS);
  n = MINI_READ_LE16(p + MINI_ZIP_CDH_FILENAME_LEN_OFS);
  n = MINI_MIN(n, MINI_ZIP_MAX_ARCHIVE_FILENAME_SIZE - 1);
  memcpy(pStat->m_filename, p + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE, n);
  pStat->m_filename[n] = '\0';
  n = MINI_READ_LE16(p + MINI_ZIP_CDH_COMMENT_LEN_OFS);
  n = MINI_MIN(n, MINI_ZIP_MAX_ARCHIVE_FILE_COMMENT_SIZE - 1);
  pStat->m_comment_size = n;
  memcpy(pStat->m_comment, p + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE +
             MINI_READ_LE16(p + MINI_ZIP_CDH_FILENAME_LEN_OFS) +
             MINI_READ_LE16(p + MINI_ZIP_CDH_EXTRA_LEN_OFS), n);
  pStat->m_comment[n] = '\0';
  return MINI_TRUE;
}
MINI_uint MINI_zip_reader_get_filename(MINI_zip_archive *pZip, MINI_uint file_index, char *pFilename, MINI_uint filename_buf_size) {
  MINI_uint n;
  const MINI_uint8 *p = MINI_zip_reader_get_cdh(pZip, file_index);
  if (!p) {
    if (filename_buf_size)
      pFilename[0] = '\0';
    return 0;
  }
  n = MINI_READ_LE16(p + MINI_ZIP_CDH_FILENAME_LEN_OFS);
  if (filename_buf_size) {
    n = MINI_MIN(n, filename_buf_size - 1);
    memcpy(pFilename, p + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE, n);
    pFilename[n] = '\0';
  }
  return n + 1;
}
static MINI_FORCEINLINE MINI_bool MINI_zip_reader_string_equal(const char *pA, const char *pB, MINI_uint len, MINI_uint flags) {
  MINI_uint i;
  if (flags & MINI_ZIP_FLAG_CASE_SENSITIVE)
    return 0 == memcmp(pA, pB, len);
  for (i = 0; i < len; ++i)
    if (MINI_TOLOWER(pA[i]) != MINI_TOLOWER(pB[i]))
      return MINI_FALSE;
  return MINI_TRUE;
}
static MINI_FORCEINLINE int
MINI_zip_reader_filename_compare(const MINI_zip_array *pCentral_dir_array, const MINI_zip_array *pCentral_dir_offsets, MINI_uint l_index, const char *pR, MINI_uint r_len) {
  const MINI_uint8 *pL = &MINI_ZIP_ARRAY_ELEMENT(
                     pCentral_dir_array, MINI_uint8, MINI_ZIP_ARRAY_ELEMENT(pCentral_dir_offsets, MINI_uint32, l_index)), *pE;
  MINI_uint l_len = MINI_READ_LE16(pL + MINI_ZIP_CDH_FILENAME_LEN_OFS);
  MINI_uint8 l = 0, r = 0;
  pL += MINI_ZIP_CENTRAL_DIR_HEADER_SIZE;
  pE = pL + MINI_MIN(l_len, r_len);
  while (pL < pE) {
    if ((l = MINI_TOLOWER(*pL)) != (r = MINI_TOLOWER(*pR)))
      break;
    pL++;
    pR++;
  }
  return (pL == pE) ? (int)(l_len - r_len) : (l - r);
}
static int MINI_zip_reader_locate_file_binary_search(MINI_zip_archive *pZip, const char *pFilename) {
  MINI_zip_internal_state *pState = pZip->m_pState;
  const MINI_zip_array *pCentral_dir_offsets = &pState->m_central_dir_offsets;
  const MINI_zip_array *pCentral_dir = &pState->m_central_dir;
  MINI_uint32 *pIndices = &MINI_ZIP_ARRAY_ELEMENT(
      &pState->m_sorted_central_dir_offsets, MINI_uint32, 0);
  const int size = pZip->m_total_files;
  const MINI_uint filename_len = (MINI_uint)strlen(pFilename);
  int l = 0, h = size - 1;
  while (l <= h) {
    int m = (l + h) >> 1, file_index = pIndices[m], comp = MINI_zip_reader_filename_compare(pCentral_dir, pCentral_dir_offsets, file_index, pFilename, filename_len);
    if (!comp)
      return file_index;
    else if (comp < 0)
      l = m + 1;
    else
      h = m - 1;
  }
  return -1;
}
int MINI_zip_reader_locate_file(MINI_zip_archive *pZip, const char *pName, const char *pComment, MINI_uint flags) {
  MINI_uint file_index;
  size_t name_len, comment_len;
  if ((!pZip) || (!pZip->m_pState) || (!pName) ||
      (pZip->m_zip_mode != MINI_ZIP_MODE_READING))
    return -1;
  if (((flags & (MINI_ZIP_FLAG_IGNORE_PATH | MINI_ZIP_FLAG_CASE_SENSITIVE)) == 0) &&
      (!pComment) && (pZip->m_pState->m_sorted_central_dir_offsets.m_size))
    return MINI_zip_reader_locate_file_binary_search(pZip, pName);
  name_len = strlen(pName);
  if (name_len > 0xFFFF)
    return -1;
  comment_len = pComment ? strlen(pComment) : 0;
  if (comment_len > 0xFFFF)
    return -1;
  for (file_index = 0; file_index < pZip->m_total_files; file_index++) {
    const MINI_uint8 *pHeader = &MINI_ZIP_ARRAY_ELEMENT(
        &pZip->m_pState->m_central_dir, MINI_uint8, MINI_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir_offsets, MINI_uint32, file_index));
    MINI_uint filename_len = MINI_READ_LE16(pHeader + MINI_ZIP_CDH_FILENAME_LEN_OFS);
    const char *pFilename = (const char *)pHeader + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE;
    if (filename_len < name_len)
      continue;
    if (comment_len) {
      MINI_uint file_extra_len = MINI_READ_LE16(pHeader + MINI_ZIP_CDH_EXTRA_LEN_OFS), file_comment_len = MINI_READ_LE16(pHeader + MINI_ZIP_CDH_COMMENT_LEN_OFS);
      const char *pFile_comment = pFilename + filename_len + file_extra_len;
      if ((file_comment_len != comment_len) ||
          (!MINI_zip_reader_string_equal(pComment, pFile_comment, file_comment_len, flags)))
        continue;
    }
    if ((flags & MINI_ZIP_FLAG_IGNORE_PATH) && (filename_len)) {
      int ofs = filename_len - 1;
      do {
        if ((pFilename[ofs] == '/') || (pFilename[ofs] == '\\') ||
            (pFilename[ofs] == ':'))
          break;
      } while (--ofs >= 0);
      ofs++;
      pFilename += ofs;
      filename_len -= ofs;
    }
    if ((filename_len == name_len) &&
        (MINI_zip_reader_string_equal(pName, pFilename, filename_len, flags)))
      return file_index;
  }
  return -1;
}
MINI_bool MINI_zip_reader_extract_to_mem_no_alloc(MINI_zip_archive *pZip, MINI_uint file_index, void *pBuf, size_t buf_size, MINI_uint flags, void *pUser_read_buf, size_t user_read_buf_size) {
  int status = TINFL_STATUS_DONE;
  MINI_uint64 needed_size, cur_file_ofs, comp_remaining, out_buf_ofs = 0, read_buf_size, read_buf_ofs = 0, read_buf_avail;
  MINI_zip_archive_file_stat file_stat;
  void *pRead_buf;
  MINI_uint32
      local_header_u32[(MINI_ZIP_LOCAL_DIR_HEADER_SIZE + sizeof(MINI_uint32) - 1) /
                       sizeof(MINI_uint32)];
  MINI_uint8 *pLocal_header = (MINI_uint8 *)local_header_u32;
  tinfl_decompressor inflator;
  if ((buf_size) && (!pBuf))
    return MINI_FALSE;
  if (!MINI_zip_reader_file_stat(pZip, file_index, &file_stat))
    return MINI_FALSE;
  if (!file_stat.m_comp_size)
    return MINI_TRUE;
  if (MINI_zip_reader_is_file_a_directory(pZip, file_index))
    return MINI_TRUE;
  if (file_stat.m_bit_flag & (1 | 32))
    return MINI_FALSE;
  if ((!(flags & MINI_ZIP_FLAG_COMPRESSED_DATA)) && (file_stat.m_method != 0) &&
      (file_stat.m_method != MINI_DEFLATED))
    return MINI_FALSE;
  needed_size = (flags & MINI_ZIP_FLAG_COMPRESSED_DATA) ? file_stat.m_comp_size
                                                      : file_stat.m_uncomp_size;
  if (buf_size < needed_size)
    return MINI_FALSE;
  cur_file_ofs = file_stat.m_local_header_ofs;
  if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pLocal_header, MINI_ZIP_LOCAL_DIR_HEADER_SIZE) != MINI_ZIP_LOCAL_DIR_HEADER_SIZE)
    return MINI_FALSE;
  if (MINI_READ_LE32(pLocal_header) != MINI_ZIP_LOCAL_DIR_HEADER_SIG)
    return MINI_FALSE;
  cur_file_ofs += MINI_ZIP_LOCAL_DIR_HEADER_SIZE +
                  MINI_READ_LE16(pLocal_header + MINI_ZIP_LDH_FILENAME_LEN_OFS) +
                  MINI_READ_LE16(pLocal_header + MINI_ZIP_LDH_EXTRA_LEN_OFS);
  if ((cur_file_ofs + file_stat.m_comp_size) > pZip->m_archive_size)
    return MINI_FALSE;
  if ((flags & MINI_ZIP_FLAG_COMPRESSED_DATA) || (!file_stat.m_method)) {
    if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pBuf, (size_t)needed_size) != needed_size)
      return MINI_FALSE;
    return ((flags & MINI_ZIP_FLAG_COMPRESSED_DATA) != 0) ||
           (MINI_crc32(MINI_CRC32_INIT, (const MINI_uint8 *)pBuf, (size_t)file_stat.m_uncomp_size) == file_stat.m_crc32);
  }
  tinfl_init(&inflator);
  if (pZip->m_pState->m_pMem) {
    pRead_buf = (MINI_uint8 *)pZip->m_pState->m_pMem + cur_file_ofs;
    read_buf_size = read_buf_avail = file_stat.m_comp_size;
    comp_remaining = 0;
  } else if (pUser_read_buf) {
    if (!user_read_buf_size)
      return MINI_FALSE;
    pRead_buf = (MINI_uint8 *)pUser_read_buf;
    read_buf_size = user_read_buf_size;
    read_buf_avail = 0;
    comp_remaining = file_stat.m_comp_size;
  } else {
    read_buf_size = MINI_MIN(file_stat.m_comp_size, MINI_ZIP_MAX_IO_BUF_SIZE);
#ifdef _MSC_VER
    if (((0, sizeof(size_t) == sizeof(MINI_uint32))) &&
        (read_buf_size > 0x7FFFFFFF))
#else
    if (((sizeof(size_t) == sizeof(MINI_uint32))) && (read_buf_size > 0x7FFFFFFF))
#endif
      return MINI_FALSE;
    if (NULL == (pRead_buf = pZip->m_pAlloc(pZip->m_pAlloc_opaque, 1, (size_t)read_buf_size)))
      return MINI_FALSE;
    read_buf_avail = 0;
    comp_remaining = file_stat.m_comp_size;
  }
  do {
    size_t in_buf_size, out_buf_size = (size_t)(file_stat.m_uncomp_size - out_buf_ofs);
    if ((!read_buf_avail) && (!pZip->m_pState->m_pMem)) {
      read_buf_avail = MINI_MIN(read_buf_size, comp_remaining);
      if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pRead_buf, (size_t)read_buf_avail) != read_buf_avail) {
        status = TINFL_STATUS_FAILED;
        break;
      }
      cur_file_ofs += read_buf_avail;
      comp_remaining -= read_buf_avail;
      read_buf_ofs = 0;
    }
    in_buf_size = (size_t)read_buf_avail;
    status = tinfl_decompress(
        &inflator, (MINI_uint8 *)pRead_buf + read_buf_ofs, &in_buf_size, (MINI_uint8 *)pBuf, (MINI_uint8 *)pBuf + out_buf_ofs, &out_buf_size, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF |
            (comp_remaining ? TINFL_FLAG_HAS_MORE_INPUT : 0));
    read_buf_avail -= in_buf_size;
    read_buf_ofs += in_buf_size;
    out_buf_ofs += out_buf_size;
  } while (status == TINFL_STATUS_NEEDS_MORE_INPUT);
  if (status == TINFL_STATUS_DONE) {
    if ((out_buf_ofs != file_stat.m_uncomp_size) ||
        (MINI_crc32(MINI_CRC32_INIT, (const MINI_uint8 *)pBuf, (size_t)file_stat.m_uncomp_size) != file_stat.m_crc32))
      status = TINFL_STATUS_FAILED;
  }
  if ((!pZip->m_pState->m_pMem) && (!pUser_read_buf))
    pZip->m_pFree(pZip->m_pAlloc_opaque, pRead_buf);
  return status == TINFL_STATUS_DONE;
}
MINI_bool MINI_zip_reader_extract_file_to_mem_no_alloc(
    MINI_zip_archive *pZip, const char *pFilename, void *pBuf, size_t buf_size, MINI_uint flags, void *pUser_read_buf, size_t user_read_buf_size) {
  int file_index = MINI_zip_reader_locate_file(pZip, pFilename, NULL, flags);
  if (file_index < 0)
    return MINI_FALSE;
  return MINI_zip_reader_extract_to_mem_no_alloc(pZip, file_index, pBuf, buf_size, flags, pUser_read_buf, user_read_buf_size);
}
MINI_bool MINI_zip_reader_extract_to_mem(MINI_zip_archive *pZip, MINI_uint file_index, void *pBuf, size_t buf_size, MINI_uint flags) {
  return MINI_zip_reader_extract_to_mem_no_alloc(pZip, file_index, pBuf, buf_size, flags, NULL, 0);
}
MINI_bool MINI_zip_reader_extract_file_to_mem(MINI_zip_archive *pZip, const char *pFilename, void *pBuf, size_t buf_size, MINI_uint flags) {
  return MINI_zip_reader_extract_file_to_mem_no_alloc(pZip, pFilename, pBuf, buf_size, flags, NULL, 0);
}
void *MINI_zip_reader_extract_to_heap(MINI_zip_archive *pZip, MINI_uint file_index, size_t *pSize, MINI_uint flags) {
  MINI_uint64 comp_size, uncomp_size, alloc_size;
  const MINI_uint8 *p = MINI_zip_reader_get_cdh(pZip, file_index);
  void *pBuf;
  if (pSize)
    *pSize = 0;
  if (!p)
    return NULL;
  comp_size = MINI_READ_LE32(p + MINI_ZIP_CDH_COMPRESSED_SIZE_OFS);
  uncomp_size = MINI_READ_LE32(p + MINI_ZIP_CDH_DECOMPRESSED_SIZE_OFS);
  alloc_size = (flags & MINI_ZIP_FLAG_COMPRESSED_DATA) ? comp_size : uncomp_size;
#ifdef _MSC_VER
  if (((0, sizeof(size_t) == sizeof(MINI_uint32))) && (alloc_size > 0x7FFFFFFF))
#else
  if (((sizeof(size_t) == sizeof(MINI_uint32))) && (alloc_size > 0x7FFFFFFF))
#endif
    return NULL;
  if (NULL == (pBuf = pZip->m_pAlloc(pZip->m_pAlloc_opaque, 1, (size_t)alloc_size)))
    return NULL;
  if (!MINI_zip_reader_extract_to_mem(pZip, file_index, pBuf, (size_t)alloc_size, flags)) {
    pZip->m_pFree(pZip->m_pAlloc_opaque, pBuf);
    return NULL;
  }
  if (pSize)
    *pSize = (size_t)alloc_size;
  return pBuf;
}
void *MINI_zip_reader_extract_file_to_heap(MINI_zip_archive *pZip, const char *pFilename, size_t *pSize, MINI_uint flags) {
  int file_index = MINI_zip_reader_locate_file(pZip, pFilename, NULL, flags);
  if (file_index < 0) {
    if (pSize)
      *pSize = 0;
    return MINI_FALSE;
  }
  return MINI_zip_reader_extract_to_heap(pZip, file_index, pSize, flags);
}
MINI_bool MINI_zip_reader_extract_to_callback(MINI_zip_archive *pZip, MINI_uint file_index, MINI_file_write_func pCallback, void *pOpaque, MINI_uint flags) {
  int status = TINFL_STATUS_DONE;
  MINI_uint file_crc32 = MINI_CRC32_INIT;
  MINI_uint64 read_buf_size, read_buf_ofs = 0, read_buf_avail, comp_remaining, out_buf_ofs = 0, cur_file_ofs;
  MINI_zip_archive_file_stat file_stat;
  void *pRead_buf = NULL;
  void *pWrite_buf = NULL;
  MINI_uint32
      local_header_u32[(MINI_ZIP_LOCAL_DIR_HEADER_SIZE + sizeof(MINI_uint32) - 1) /
                       sizeof(MINI_uint32)];
  MINI_uint8 *pLocal_header = (MINI_uint8 *)local_header_u32;
  if (!MINI_zip_reader_file_stat(pZip, file_index, &file_stat))
    return MINI_FALSE;
  if (!file_stat.m_comp_size)
    return MINI_TRUE;
  if (MINI_zip_reader_is_file_a_directory(pZip, file_index))
    return MINI_TRUE;
  if (file_stat.m_bit_flag & (1 | 32))
    return MINI_FALSE;
  if ((!(flags & MINI_ZIP_FLAG_COMPRESSED_DATA)) && (file_stat.m_method != 0) &&
      (file_stat.m_method != MINI_DEFLATED))
    return MINI_FALSE;
  cur_file_ofs = file_stat.m_local_header_ofs;
  if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pLocal_header, MINI_ZIP_LOCAL_DIR_HEADER_SIZE) != MINI_ZIP_LOCAL_DIR_HEADER_SIZE)
    return MINI_FALSE;
  if (MINI_READ_LE32(pLocal_header) != MINI_ZIP_LOCAL_DIR_HEADER_SIG)
    return MINI_FALSE;
  cur_file_ofs += MINI_ZIP_LOCAL_DIR_HEADER_SIZE +
                  MINI_READ_LE16(pLocal_header + MINI_ZIP_LDH_FILENAME_LEN_OFS) +
                  MINI_READ_LE16(pLocal_header + MINI_ZIP_LDH_EXTRA_LEN_OFS);
  if ((cur_file_ofs + file_stat.m_comp_size) > pZip->m_archive_size)
    return MINI_FALSE;
  if (pZip->m_pState->m_pMem) {
    pRead_buf = (MINI_uint8 *)pZip->m_pState->m_pMem + cur_file_ofs;
    read_buf_size = read_buf_avail = file_stat.m_comp_size;
    comp_remaining = 0;
  } else {
    read_buf_size = MINI_MIN(file_stat.m_comp_size, MINI_ZIP_MAX_IO_BUF_SIZE);
    if (NULL == (pRead_buf = pZip->m_pAlloc(pZip->m_pAlloc_opaque, 1, (size_t)read_buf_size)))
      return MINI_FALSE;
    read_buf_avail = 0;
    comp_remaining = file_stat.m_comp_size;
  }
  if ((flags & MINI_ZIP_FLAG_COMPRESSED_DATA) || (!file_stat.m_method)) {
    if (pZip->m_pState->m_pMem) {
#ifdef _MSC_VER
      if (((0, sizeof(size_t) == sizeof(MINI_uint32))) &&
          (file_stat.m_comp_size > 0xFFFFFFFF))
#else
      if (((sizeof(size_t) == sizeof(MINI_uint32))) &&
          (file_stat.m_comp_size > 0xFFFFFFFF))
#endif
        return MINI_FALSE;
      if (pCallback(pOpaque, out_buf_ofs, pRead_buf, (size_t)file_stat.m_comp_size) != file_stat.m_comp_size)
        status = TINFL_STATUS_FAILED;
      else if (!(flags & MINI_ZIP_FLAG_COMPRESSED_DATA))
        file_crc32 = (MINI_uint32)MINI_crc32(file_crc32, (const MINI_uint8 *)pRead_buf, (size_t)file_stat.m_comp_size);
      cur_file_ofs += file_stat.m_comp_size;
      out_buf_ofs += file_stat.m_comp_size;
      comp_remaining = 0;
    } else {
      while (comp_remaining) {
        read_buf_avail = MINI_MIN(read_buf_size, comp_remaining);
        if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pRead_buf, (size_t)read_buf_avail) != read_buf_avail) {
          status = TINFL_STATUS_FAILED;
          break;
        }
        if (!(flags & MINI_ZIP_FLAG_COMPRESSED_DATA))
          file_crc32 = (MINI_uint32)MINI_crc32(
              file_crc32, (const MINI_uint8 *)pRead_buf, (size_t)read_buf_avail);
        if (pCallback(pOpaque, out_buf_ofs, pRead_buf, (size_t)read_buf_avail) != read_buf_avail) {
          status = TINFL_STATUS_FAILED;
          break;
        }
        cur_file_ofs += read_buf_avail;
        out_buf_ofs += read_buf_avail;
        comp_remaining -= read_buf_avail;
      }
    }
  } else {
    tinfl_decompressor inflator;
    tinfl_init(&inflator);
    if (NULL == (pWrite_buf = pZip->m_pAlloc(pZip->m_pAlloc_opaque, 1, TINFL_LZ_DICT_SIZE)))
      status = TINFL_STATUS_FAILED;
    else {
      do {
        MINI_uint8 *pWrite_buf_cur = (MINI_uint8 *)pWrite_buf + (out_buf_ofs & (TINFL_LZ_DICT_SIZE - 1));
        size_t in_buf_size, out_buf_size = TINFL_LZ_DICT_SIZE - (out_buf_ofs & (TINFL_LZ_DICT_SIZE - 1));
        if ((!read_buf_avail) && (!pZip->m_pState->m_pMem)) {
          read_buf_avail = MINI_MIN(read_buf_size, comp_remaining);
          if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pRead_buf, (size_t)read_buf_avail) != read_buf_avail) {
            status = TINFL_STATUS_FAILED;
            break;
          }
          cur_file_ofs += read_buf_avail;
          comp_remaining -= read_buf_avail;
          read_buf_ofs = 0;
        }
        in_buf_size = (size_t)read_buf_avail;
        status = tinfl_decompress(
            &inflator, (const MINI_uint8 *)pRead_buf + read_buf_ofs, &in_buf_size, (MINI_uint8 *)pWrite_buf, pWrite_buf_cur, &out_buf_size, comp_remaining ? TINFL_FLAG_HAS_MORE_INPUT : 0);
        read_buf_avail -= in_buf_size;
        read_buf_ofs += in_buf_size;
        if (out_buf_size) {
          if (pCallback(pOpaque, out_buf_ofs, pWrite_buf_cur, out_buf_size) != out_buf_size) {
            status = TINFL_STATUS_FAILED;
            break;
          }
          file_crc32 = (MINI_uint32)MINI_crc32(file_crc32, pWrite_buf_cur, out_buf_size);
          if ((out_buf_ofs += out_buf_size) > file_stat.m_uncomp_size) {
            status = TINFL_STATUS_FAILED;
            break;
          }
        }
      } while ((status == TINFL_STATUS_NEEDS_MORE_INPUT) ||
               (status == TINFL_STATUS_HAS_MORE_OUTPUT));
    }
  }
  if ((status == TINFL_STATUS_DONE) &&
      (!(flags & MINI_ZIP_FLAG_COMPRESSED_DATA))) {
    if ((out_buf_ofs != file_stat.m_uncomp_size) ||
        (file_crc32 != file_stat.m_crc32))
      status = TINFL_STATUS_FAILED;
  }
  if (!pZip->m_pState->m_pMem)
    pZip->m_pFree(pZip->m_pAlloc_opaque, pRead_buf);
  if (pWrite_buf)
    pZip->m_pFree(pZip->m_pAlloc_opaque, pWrite_buf);
  return status == TINFL_STATUS_DONE;
}
MINI_bool MINI_zip_reader_extract_file_to_callback(MINI_zip_archive *pZip, const char *pFilename, MINI_file_write_func pCallback, void *pOpaque, MINI_uint flags) {
  int file_index = MINI_zip_reader_locate_file(pZip, pFilename, NULL, flags);
  if (file_index < 0)
    return MINI_FALSE;
  return MINI_zip_reader_extract_to_callback(pZip, file_index, pCallback, pOpaque, flags);
}
#ifndef MINI_NO_STDIO
static size_t MINI_zip_file_write_callback(void *pOpaque, MINI_uint64 ofs, const void *pBuf, size_t n) {
  (void)ofs;
  return MINI_FWRITE(pBuf, 1, n, (MINI_FILE *)pOpaque);
}
MINI_bool MINI_zip_reader_extract_to_file(MINI_zip_archive *pZip, MINI_uint file_index, const char *pDst_filename, MINI_uint flags) {
  MINI_bool status;
  MINI_zip_archive_file_stat file_stat;
  MINI_FILE *pFile;
  if (!MINI_zip_reader_file_stat(pZip, file_index, &file_stat))
    return MINI_FALSE;
  pFile = MINI_FOPEN(pDst_filename, "wb");
  if (!pFile)
    return MINI_FALSE;
  status = MINI_zip_reader_extract_to_callback(
      pZip, file_index, MINI_zip_file_write_callback, pFile, flags);
  if (MINI_FCLOSE(pFile) == EOF)
    return MINI_FALSE;
#ifndef MINI_NO_TIME
  if (status)
    MINI_zip_set_file_times(pDst_filename, file_stat.m_time, file_stat.m_time);
#endif
  return status;
}
#endif
MINI_bool MINI_zip_reader_end(MINI_zip_archive *pZip) {
  if ((!pZip) || (!pZip->m_pState) || (!pZip->m_pAlloc) || (!pZip->m_pFree) ||
      (pZip->m_zip_mode != MINI_ZIP_MODE_READING))
    return MINI_FALSE;
  if (pZip->m_pState) {
    MINI_zip_internal_state *pState = pZip->m_pState;
    pZip->m_pState = NULL;
    MINI_zip_array_clear(pZip, &pState->m_central_dir);
    MINI_zip_array_clear(pZip, &pState->m_central_dir_offsets);
    MINI_zip_array_clear(pZip, &pState->m_sorted_central_dir_offsets);
#ifndef MINI_NO_STDIO
    if (pState->m_pFile) {
      MINI_FCLOSE(pState->m_pFile);
      pState->m_pFile = NULL;
    }
#endif
    pZip->m_pFree(pZip->m_pAlloc_opaque, pState);
  }
  pZip->m_zip_mode = MINI_ZIP_MODE_INVALID;
  return MINI_TRUE;
}
#ifndef MINI_NO_STDIO
MINI_bool MINI_zip_reader_extract_file_to_file(MINI_zip_archive *pZip, const char *pArchive_filename, const char *pDst_filename, MINI_uint flags) {
  int file_index = MINI_zip_reader_locate_file(pZip, pArchive_filename, NULL, flags);
  if (file_index < 0)
    return MINI_FALSE;
  return MINI_zip_reader_extract_to_file(pZip, file_index, pDst_filename, flags);
}
#endif
#ifndef MINI_NO_ARCHIVE_WRITING_APIS
static void MINI_write_le16(MINI_uint8 *p, MINI_uint16 v) {
  p[0] = (MINI_uint8)v;
  p[1] = (MINI_uint8)(v >> 8);
}
static void MINI_write_le32(MINI_uint8 *p, MINI_uint32 v) {
  p[0] = (MINI_uint8)v;
  p[1] = (MINI_uint8)(v >> 8);
  p[2] = (MINI_uint8)(v >> 16);
  p[3] = (MINI_uint8)(v >> 24);
}
#define MINI_WRITE_LE16(p, v) MINI_write_le16((MINI_uint8 *)(p), (MINI_uint16)(v))
#define MINI_WRITE_LE32(p, v) MINI_write_le32((MINI_uint8 *)(p), (MINI_uint32)(v))
MINI_bool MINI_zip_writer_init(MINI_zip_archive *pZip, MINI_uint64 existing_size) {
  if ((!pZip) || (pZip->m_pState) || (!pZip->m_pWrite) ||
      (pZip->m_zip_mode != MINI_ZIP_MODE_INVALID))
    return MINI_FALSE;
  if (pZip->m_file_offset_alignment) {
    if (pZip->m_file_offset_alignment & (pZip->m_file_offset_alignment - 1))
      return MINI_FALSE;
  }
  if (!pZip->m_pAlloc)
    pZip->m_pAlloc = def_alloc_func;
  if (!pZip->m_pFree)
    pZip->m_pFree = def_free_func;
  if (!pZip->m_pRealloc)
    pZip->m_pRealloc = def_realloc_func;
  pZip->m_zip_mode = MINI_ZIP_MODE_WRITING;
  pZip->m_archive_size = existing_size;
  pZip->m_central_directory_file_ofs = 0;
  pZip->m_total_files = 0;
  if (NULL == (pZip->m_pState = (MINI_zip_internal_state *)pZip->m_pAlloc(
                   pZip->m_pAlloc_opaque, 1, sizeof(MINI_zip_internal_state))))
    return MINI_FALSE;
  memset(pZip->m_pState, 0, sizeof(MINI_zip_internal_state));
  MINI_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir, sizeof(MINI_uint8));
  MINI_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir_offsets, sizeof(MINI_uint32));
  MINI_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_sorted_central_dir_offsets, sizeof(MINI_uint32));
  return MINI_TRUE;
}
static size_t MINI_zip_heap_write_func(void *pOpaque, MINI_uint64 file_ofs, const void *pBuf, size_t n) {
  MINI_zip_archive *pZip = (MINI_zip_archive *)pOpaque;
  MINI_zip_internal_state *pState = pZip->m_pState;
  MINI_uint64 new_size = MINI_MAX(file_ofs + n, pState->m_mem_size);
#ifdef _MSC_VER
  if ((!n) ||
      ((0, sizeof(size_t) == sizeof(MINI_uint32)) && (new_size > 0x7FFFFFFF)))
#else
  if ((!n) ||
      ((sizeof(size_t) == sizeof(MINI_uint32)) && (new_size > 0x7FFFFFFF)))
#endif
    return 0;
  if (new_size > pState->m_mem_capacity) {
    void *pNew_block;
    size_t new_capacity = MINI_MAX(64, pState->m_mem_capacity);
    while (new_capacity < new_size)
      new_capacity *= 2;
    if (NULL == (pNew_block = pZip->m_pRealloc(
                     pZip->m_pAlloc_opaque, pState->m_pMem, 1, new_capacity)))
      return 0;
    pState->m_pMem = pNew_block;
    pState->m_mem_capacity = new_capacity;
  }
  memcpy((MINI_uint8 *)pState->m_pMem + file_ofs, pBuf, n);
  pState->m_mem_size = (size_t)new_size;
  return n;
}
MINI_bool MINI_zip_writer_init_heap(MINI_zip_archive *pZip, size_t size_to_reserve_at_beginning, size_t initial_allocation_size) {
  pZip->m_pWrite = MINI_zip_heap_write_func;
  pZip->m_pIO_opaque = pZip;
  if (!MINI_zip_writer_init(pZip, size_to_reserve_at_beginning))
    return MINI_FALSE;
  if (0 != (initial_allocation_size = MINI_MAX(initial_allocation_size, size_to_reserve_at_beginning))) {
    if (NULL == (pZip->m_pState->m_pMem = pZip->m_pAlloc(
                     pZip->m_pAlloc_opaque, 1, initial_allocation_size))) {
      MINI_zip_writer_end(pZip);
      return MINI_FALSE;
    }
    pZip->m_pState->m_mem_capacity = initial_allocation_size;
  }
  return MINI_TRUE;
}
#ifndef MINI_NO_STDIO
static size_t MINI_zip_file_write_func(void *pOpaque, MINI_uint64 file_ofs, const void *pBuf, size_t n) {
  MINI_zip_archive *pZip = (MINI_zip_archive *)pOpaque;
  MINI_int64 cur_ofs = MINI_FTELL64(pZip->m_pState->m_pFile);
  if (((MINI_int64)file_ofs < 0) ||
      (((cur_ofs != (MINI_int64)file_ofs)) &&
       (MINI_FSEEK64(pZip->m_pState->m_pFile, (MINI_int64)file_ofs, SEEK_SET))))
    return 0;
  return MINI_FWRITE(pBuf, 1, n, pZip->m_pState->m_pFile);
}
MINI_bool MINI_zip_writer_init_file(MINI_zip_archive *pZip, const char *pFilename, MINI_uint64 size_to_reserve_at_beginning) {
  MINI_FILE *pFile;
  pZip->m_pWrite = MINI_zip_file_write_func;
  pZip->m_pIO_opaque = pZip;
  if (!MINI_zip_writer_init(pZip, size_to_reserve_at_beginning))
    return MINI_FALSE;
  if (NULL == (pFile = MINI_FOPEN(pFilename, "wb"))) {
    MINI_zip_writer_end(pZip);
    return MINI_FALSE;
  }
  pZip->m_pState->m_pFile = pFile;
  if (size_to_reserve_at_beginning) {
    MINI_uint64 cur_ofs = 0;
    char buf[4096];
    MINI_CLEAR_OBJ(buf);
    do {
      size_t n = (size_t)MINI_MIN(sizeof(buf), size_to_reserve_at_beginning);
      if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_ofs, buf, n) != n) {
        MINI_zip_writer_end(pZip);
        return MINI_FALSE;
      }
      cur_ofs += n;
      size_to_reserve_at_beginning -= n;
    } while (size_to_reserve_at_beginning);
  }
  return MINI_TRUE;
}
#endif
MINI_bool MINI_zip_writer_init_from_reader(MINI_zip_archive *pZip, const char *pFilename) {
  MINI_zip_internal_state *pState;
  if ((!pZip) || (!pZip->m_pState) || (pZip->m_zip_mode != MINI_ZIP_MODE_READING))
    return MINI_FALSE;
  if ((pZip->m_total_files == 0xFFFF) ||
      ((pZip->m_archive_size + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE +
        MINI_ZIP_LOCAL_DIR_HEADER_SIZE) > 0xFFFFFFFF))
    return MINI_FALSE;
  pState = pZip->m_pState;
  if (pState->m_pFile) {
#ifdef MINI_NO_STDIO
    pFilename;
    return MINI_FALSE;
#else
    if (pZip->m_pIO_opaque != pZip)
      return MINI_FALSE;
    if (!pFilename)
      return MINI_FALSE;
    pZip->m_pWrite = MINI_zip_file_write_func;
    if (NULL == (pState->m_pFile = MINI_FREOPEN(pFilename, "r+b", pState->m_pFile))) {
      MINI_zip_reader_end(pZip);
      return MINI_FALSE;
    }
#endif
  } else if (pState->m_pMem) {
    if (pZip->m_pIO_opaque != pZip)
      return MINI_FALSE;
    pState->m_mem_capacity = pState->m_mem_size;
    pZip->m_pWrite = MINI_zip_heap_write_func;
  } else if (!pZip->m_pWrite)
    return MINI_FALSE;
  pZip->m_archive_size = pZip->m_central_directory_file_ofs;
  pZip->m_zip_mode = MINI_ZIP_MODE_WRITING;
  pZip->m_central_directory_file_ofs = 0;
  return MINI_TRUE;
}
MINI_bool MINI_zip_writer_add_mem(MINI_zip_archive *pZip, const char *pArchive_name, const void *pBuf, size_t buf_size, MINI_uint level_and_flags) {
  return MINI_zip_writer_add_mem_ex(pZip, pArchive_name, pBuf, buf_size, NULL, 0, level_and_flags, 0, 0);
}
typedef struct {
  MINI_zip_archive *m_pZip;
  MINI_uint64 m_cur_archive_file_ofs;
  MINI_uint64 m_comp_size;
} MINI_zip_writer_add_state;
static MINI_bool MINI_zip_writer_add_put_buf_callback(const void *pBuf, int len, void *pUser) {
  MINI_zip_writer_add_state *pState = (MINI_zip_writer_add_state *)pUser;
  if ((int)pState->m_pZip->m_pWrite(pState->m_pZip->m_pIO_opaque, pState->m_cur_archive_file_ofs, pBuf, len) != len)
    return MINI_FALSE;
  pState->m_cur_archive_file_ofs += len;
  pState->m_comp_size += len;
  return MINI_TRUE;
}
static MINI_bool MINI_zip_writer_create_local_dir_header(
    MINI_zip_archive *pZip, MINI_uint8 *pDst, MINI_uint16 filename_size, MINI_uint16 extra_size, MINI_uint64 uncomp_size, MINI_uint64 comp_size, MINI_uint32 uncomp_crc32, MINI_uint16 method, MINI_uint16 bit_flags, MINI_uint16 dos_time, MINI_uint16 dos_date) {
  (void)pZip;
  memset(pDst, 0, MINI_ZIP_LOCAL_DIR_HEADER_SIZE);
  MINI_WRITE_LE32(pDst + MINI_ZIP_LDH_SIG_OFS, MINI_ZIP_LOCAL_DIR_HEADER_SIG);
  MINI_WRITE_LE16(pDst + MINI_ZIP_LDH_VERSION_NEEDED_OFS, method ? 20 : 0);
  MINI_WRITE_LE16(pDst + MINI_ZIP_LDH_BIT_FLAG_OFS, bit_flags);
  MINI_WRITE_LE16(pDst + MINI_ZIP_LDH_METHOD_OFS, method);
  MINI_WRITE_LE16(pDst + MINI_ZIP_LDH_FILE_TIME_OFS, dos_time);
  MINI_WRITE_LE16(pDst + MINI_ZIP_LDH_FILE_DATE_OFS, dos_date);
  MINI_WRITE_LE32(pDst + MINI_ZIP_LDH_CRC32_OFS, uncomp_crc32);
  MINI_WRITE_LE32(pDst + MINI_ZIP_LDH_COMPRESSED_SIZE_OFS, comp_size);
  MINI_WRITE_LE32(pDst + MINI_ZIP_LDH_DECOMPRESSED_SIZE_OFS, uncomp_size);
  MINI_WRITE_LE16(pDst + MINI_ZIP_LDH_FILENAME_LEN_OFS, filename_size);
  MINI_WRITE_LE16(pDst + MINI_ZIP_LDH_EXTRA_LEN_OFS, extra_size);
  return MINI_TRUE;
}
static MINI_bool MINI_zip_writer_create_central_dir_header(
    MINI_zip_archive *pZip, MINI_uint8 *pDst, MINI_uint16 filename_size, MINI_uint16 extra_size, MINI_uint16 comment_size, MINI_uint64 uncomp_size, MINI_uint64 comp_size, MINI_uint32 uncomp_crc32, MINI_uint16 method, MINI_uint16 bit_flags, MINI_uint16 dos_time, MINI_uint16 dos_date, MINI_uint64 local_header_ofs, MINI_uint32 ext_attributes) {
  (void)pZip;
  memset(pDst, 0, MINI_ZIP_CENTRAL_DIR_HEADER_SIZE);
  MINI_WRITE_LE32(pDst + MINI_ZIP_CDH_SIG_OFS, MINI_ZIP_CENTRAL_DIR_HEADER_SIG);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_VERSION_NEEDED_OFS, method ? 20 : 0);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_BIT_FLAG_OFS, bit_flags);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_METHOD_OFS, method);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_FILE_TIME_OFS, dos_time);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_FILE_DATE_OFS, dos_date);
  MINI_WRITE_LE32(pDst + MINI_ZIP_CDH_CRC32_OFS, uncomp_crc32);
  MINI_WRITE_LE32(pDst + MINI_ZIP_CDH_COMPRESSED_SIZE_OFS, comp_size);
  MINI_WRITE_LE32(pDst + MINI_ZIP_CDH_DECOMPRESSED_SIZE_OFS, uncomp_size);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_FILENAME_LEN_OFS, filename_size);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_EXTRA_LEN_OFS, extra_size);
  MINI_WRITE_LE16(pDst + MINI_ZIP_CDH_COMMENT_LEN_OFS, comment_size);
  MINI_WRITE_LE32(pDst + MINI_ZIP_CDH_EXTERNAL_ATTR_OFS, ext_attributes);
  MINI_WRITE_LE32(pDst + MINI_ZIP_CDH_LOCAL_HEADER_OFS, local_header_ofs);
  return MINI_TRUE;
}
static MINI_bool MINI_zip_writer_add_to_central_dir(
    MINI_zip_archive *pZip, const char *pFilename, MINI_uint16 filename_size, const void *pExtra, MINI_uint16 extra_size, const void *pComment, MINI_uint16 comment_size, MINI_uint64 uncomp_size, MINI_uint64 comp_size, MINI_uint32 uncomp_crc32, MINI_uint16 method, MINI_uint16 bit_flags, MINI_uint16 dos_time, MINI_uint16 dos_date, MINI_uint64 local_header_ofs, MINI_uint32 ext_attributes) {
  MINI_zip_internal_state *pState = pZip->m_pState;
  MINI_uint32 central_dir_ofs = (MINI_uint32)pState->m_central_dir.m_size;
  size_t orig_central_dir_size = pState->m_central_dir.m_size;
  MINI_uint8 central_dir_header[MINI_ZIP_CENTRAL_DIR_HEADER_SIZE];
  if ((local_header_ofs > 0xFFFFFFFF) ||
      (((MINI_uint64)pState->m_central_dir.m_size +
        MINI_ZIP_CENTRAL_DIR_HEADER_SIZE + filename_size + extra_size +
        comment_size) > 0xFFFFFFFF))
    return MINI_FALSE;
  if (!MINI_zip_writer_create_central_dir_header(
          pZip, central_dir_header, filename_size, extra_size, comment_size, uncomp_size, comp_size, uncomp_crc32, method, bit_flags, dos_time, dos_date, local_header_ofs, ext_attributes))
    return MINI_FALSE;
  if ((!MINI_zip_array_push_back(pZip, &pState->m_central_dir, central_dir_header, MINI_ZIP_CENTRAL_DIR_HEADER_SIZE)) ||
      (!MINI_zip_array_push_back(pZip, &pState->m_central_dir, pFilename, filename_size)) ||
      (!MINI_zip_array_push_back(pZip, &pState->m_central_dir, pExtra, extra_size)) ||
      (!MINI_zip_array_push_back(pZip, &pState->m_central_dir, pComment, comment_size)) ||
      (!MINI_zip_array_push_back(pZip, &pState->m_central_dir_offsets, &central_dir_ofs, 1))) {
    MINI_zip_array_resize(pZip, &pState->m_central_dir, orig_central_dir_size, MINI_FALSE);
    return MINI_FALSE;
  }
  return MINI_TRUE;
}
static MINI_bool MINI_zip_writer_validate_archive_name(const char *pArchive_name) {
  if (*pArchive_name == '/')
    return MINI_FALSE;
  while (*pArchive_name) {
    if ((*pArchive_name == '\\') || (*pArchive_name == ':'))
      return MINI_FALSE;
    pArchive_name++;
  }
  return MINI_TRUE;
}
static MINI_uint
MINI_zip_writer_compute_padding_needed_for_file_alignment(MINI_zip_archive *pZip) {
  MINI_uint32 n;
  if (!pZip->m_file_offset_alignment)
    return 0;
  n = (MINI_uint32)(pZip->m_archive_size & (pZip->m_file_offset_alignment - 1));
  return (pZip->m_file_offset_alignment - n) &
         (pZip->m_file_offset_alignment - 1);
}
static MINI_bool MINI_zip_writer_write_zeros(MINI_zip_archive *pZip, MINI_uint64 cur_file_ofs, MINI_uint32 n) {
  char buf[4096];
  memset(buf, 0, MINI_MIN(sizeof(buf), n));
  while (n) {
    MINI_uint32 s = MINI_MIN(sizeof(buf), n);
    if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_file_ofs, buf, s) != s)
      return MINI_FALSE;
    cur_file_ofs += s;
    n -= s;
  }
  return MINI_TRUE;
}
MINI_bool MINI_zip_writer_add_mem_ex(MINI_zip_archive *pZip, const char *pArchive_name, const void *pBuf, size_t buf_size, const void *pComment, MINI_uint16 comment_size, MINI_uint level_and_flags, MINI_uint64 uncomp_size, MINI_uint32 uncomp_crc32) {
  MINI_uint16 method = 0, dos_time = 0, dos_date = 0;
  MINI_uint level, ext_attributes = 0, num_alignment_padding_bytes;
  MINI_uint64 local_dir_header_ofs = pZip->m_archive_size, cur_archive_file_ofs = pZip->m_archive_size, comp_size = 0;
  size_t archive_name_size;
  MINI_uint8 local_dir_header[MINI_ZIP_LOCAL_DIR_HEADER_SIZE];
  tdefl_compressor *pComp = NULL;
  MINI_bool store_data_uncompressed;
  MINI_zip_internal_state *pState;
  if ((int)level_and_flags < 0)
    level_and_flags = MINI_DEFAULT_LEVEL;
  level = level_and_flags & 0xF;
  store_data_uncompressed = ((!level) || (level_and_flags & MINI_ZIP_FLAG_COMPRESSED_DATA));
  if ((!pZip) || (!pZip->m_pState) ||
      (pZip->m_zip_mode != MINI_ZIP_MODE_WRITING) || ((buf_size) && (!pBuf)) ||
      (!pArchive_name) || ((comment_size) && (!pComment)) ||
      (pZip->m_total_files == 0xFFFF) || (level > MINI_UBER_COMPRESSION))
    return MINI_FALSE;
  pState = pZip->m_pState;
  if ((!(level_and_flags & MINI_ZIP_FLAG_COMPRESSED_DATA)) && (uncomp_size))
    return MINI_FALSE;
  if ((buf_size > 0xFFFFFFFF) || (uncomp_size > 0xFFFFFFFF))
    return MINI_FALSE;
  if (!MINI_zip_writer_validate_archive_name(pArchive_name))
    return MINI_FALSE;
#ifndef MINI_NO_TIME
  {
    time_t cur_time;
    time(&cur_time);
    MINI_zip_time_to_dos_time(cur_time, &dos_time, &dos_date);
  }
#endif
  archive_name_size = strlen(pArchive_name);
  if (archive_name_size > 0xFFFF)
    return MINI_FALSE;
  num_alignment_padding_bytes = MINI_zip_writer_compute_padding_needed_for_file_alignment(pZip);
  if ((pZip->m_total_files == 0xFFFF) ||
      ((pZip->m_archive_size + num_alignment_padding_bytes +
        MINI_ZIP_LOCAL_DIR_HEADER_SIZE + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE +
        comment_size + archive_name_size) > 0xFFFFFFFF))
    return MINI_FALSE;
  if ((archive_name_size) && (pArchive_name[archive_name_size - 1] == '/')) {
    ext_attributes |= 0x10;
    if ((buf_size) || (uncomp_size))
      return MINI_FALSE;
  }
  if ((!MINI_zip_array_ensure_room(pZip, &pState->m_central_dir, MINI_ZIP_CENTRAL_DIR_HEADER_SIZE +
                                     archive_name_size + comment_size)) ||
      (!MINI_zip_array_ensure_room(pZip, &pState->m_central_dir_offsets, 1)))
    return MINI_FALSE;
  if ((!store_data_uncompressed) && (buf_size)) {
    if (NULL == (pComp = (tdefl_compressor *)pZip->m_pAlloc(
                     pZip->m_pAlloc_opaque, 1, sizeof(tdefl_compressor))))
      return MINI_FALSE;
  }
  if (!MINI_zip_writer_write_zeros(pZip, cur_archive_file_ofs, num_alignment_padding_bytes +
                                     sizeof(local_dir_header))) {
    pZip->m_pFree(pZip->m_pAlloc_opaque, pComp);
    return MINI_FALSE;
  }
  local_dir_header_ofs += num_alignment_padding_bytes;
  if (pZip->m_file_offset_alignment) {
    MINI_ASSERT((local_dir_header_ofs & (pZip->m_file_offset_alignment - 1)) == 0);
  }
  cur_archive_file_ofs += num_alignment_padding_bytes + sizeof(local_dir_header);
  MINI_CLEAR_OBJ(local_dir_header);
  if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_archive_file_ofs, pArchive_name, archive_name_size) != archive_name_size) {
    pZip->m_pFree(pZip->m_pAlloc_opaque, pComp);
    return MINI_FALSE;
  }
  cur_archive_file_ofs += archive_name_size;
  if (!(level_and_flags & MINI_ZIP_FLAG_COMPRESSED_DATA)) {
    uncomp_crc32 = (MINI_uint32)MINI_crc32(MINI_CRC32_INIT, (const MINI_uint8 *)pBuf, buf_size);
    uncomp_size = buf_size;
    if (uncomp_size <= 3) {
      level = 0;
      store_data_uncompressed = MINI_TRUE;
    }
  }
  if (store_data_uncompressed) {
    if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_archive_file_ofs, pBuf, buf_size) != buf_size) {
      pZip->m_pFree(pZip->m_pAlloc_opaque, pComp);
      return MINI_FALSE;
    }
    cur_archive_file_ofs += buf_size;
    comp_size = buf_size;
    if (level_and_flags & MINI_ZIP_FLAG_COMPRESSED_DATA)
      method = MINI_DEFLATED;
  } else if (buf_size) {
    MINI_zip_writer_add_state state;
    state.m_pZip = pZip;
    state.m_cur_archive_file_ofs = cur_archive_file_ofs;
    state.m_comp_size = 0;
    if ((tdefl_init(pComp, MINI_zip_writer_add_put_buf_callback, &state, tdefl_create_comp_flags_from_zip_params(
                        level, -15, MINI_DEFAULT_STRATEGY)) != TDEFL_STATUS_OKAY) ||
        (tdefl_compress_buffer(pComp, pBuf, buf_size, TDEFL_FINISH) != TDEFL_STATUS_DONE)) {
      pZip->m_pFree(pZip->m_pAlloc_opaque, pComp);
      return MINI_FALSE;
    }
    comp_size = state.m_comp_size;
    cur_archive_file_ofs = state.m_cur_archive_file_ofs;
    method = MINI_DEFLATED;
  }
  pZip->m_pFree(pZip->m_pAlloc_opaque, pComp);
  pComp = NULL;
  if ((comp_size > 0xFFFFFFFF) || (cur_archive_file_ofs > 0xFFFFFFFF))
    return MINI_FALSE;
  if (!MINI_zip_writer_create_local_dir_header(
          pZip, local_dir_header, (MINI_uint16)archive_name_size, 0, uncomp_size, comp_size, uncomp_crc32, method, 0, dos_time, dos_date))
    return MINI_FALSE;
  if (pZip->m_pWrite(pZip->m_pIO_opaque, local_dir_header_ofs, local_dir_header, sizeof(local_dir_header)) != sizeof(local_dir_header))
    return MINI_FALSE;
  if (!MINI_zip_writer_add_to_central_dir(
          pZip, pArchive_name, (MINI_uint16)archive_name_size, NULL, 0, pComment, comment_size, uncomp_size, comp_size, uncomp_crc32, method, 0, dos_time, dos_date, local_dir_header_ofs, ext_attributes))
    return MINI_FALSE;
  pZip->m_total_files++;
  pZip->m_archive_size = cur_archive_file_ofs;
  return MINI_TRUE;
}
#ifndef MINI_NO_STDIO
MINI_bool MINI_zip_writer_add_file(MINI_zip_archive *pZip, const char *pArchive_name, const char *pSrc_filename, const void *pComment, MINI_uint16 comment_size, MINI_uint level_and_flags) {
  MINI_uint uncomp_crc32 = MINI_CRC32_INIT, level, num_alignment_padding_bytes;
  MINI_uint16 method = 0, dos_time = 0, dos_date = 0, ext_attributes = 0;
  MINI_uint64 local_dir_header_ofs = pZip->m_archive_size, cur_archive_file_ofs = pZip->m_archive_size, uncomp_size = 0, comp_size = 0;
  size_t archive_name_size;
  MINI_uint8 local_dir_header[MINI_ZIP_LOCAL_DIR_HEADER_SIZE];
  MINI_FILE *pSrc_file = NULL;
  if ((int)level_and_flags < 0)
    level_and_flags = MINI_DEFAULT_LEVEL;
  level = level_and_flags & 0xF;
  if ((!pZip) || (!pZip->m_pState) ||
      (pZip->m_zip_mode != MINI_ZIP_MODE_WRITING) || (!pArchive_name) ||
      ((comment_size) && (!pComment)) || (level > MINI_UBER_COMPRESSION))
    return MINI_FALSE;
  if (level_and_flags & MINI_ZIP_FLAG_COMPRESSED_DATA)
    return MINI_FALSE;
  if (!MINI_zip_writer_validate_archive_name(pArchive_name))
    return MINI_FALSE;
  archive_name_size = strlen(pArchive_name);
  if (archive_name_size > 0xFFFF)
    return MINI_FALSE;
  num_alignment_padding_bytes = MINI_zip_writer_compute_padding_needed_for_file_alignment(pZip);
  if ((pZip->m_total_files == 0xFFFF) ||
      ((pZip->m_archive_size + num_alignment_padding_bytes +
        MINI_ZIP_LOCAL_DIR_HEADER_SIZE + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE +
        comment_size + archive_name_size) > 0xFFFFFFFF))
    return MINI_FALSE;
  if (!MINI_zip_get_file_modified_time(pSrc_filename, &dos_time, &dos_date))
    return MINI_FALSE;
  pSrc_file = MINI_FOPEN(pSrc_filename, "rb");
  if (!pSrc_file)
    return MINI_FALSE;
  MINI_FSEEK64(pSrc_file, 0, SEEK_END);
  uncomp_size = MINI_FTELL64(pSrc_file);
  MINI_FSEEK64(pSrc_file, 0, SEEK_SET);
  if (uncomp_size > 0xFFFFFFFF) {
    MINI_FCLOSE(pSrc_file);
    return MINI_FALSE;
  }
  if (uncomp_size <= 3)
    level = 0;
  if (!MINI_zip_writer_write_zeros(pZip, cur_archive_file_ofs, num_alignment_padding_bytes +
                                     sizeof(local_dir_header))) {
    MINI_FCLOSE(pSrc_file);
    return MINI_FALSE;
  }
  local_dir_header_ofs += num_alignment_padding_bytes;
  if (pZip->m_file_offset_alignment) {
    MINI_ASSERT((local_dir_header_ofs & (pZip->m_file_offset_alignment - 1)) == 0);
  }
  cur_archive_file_ofs += num_alignment_padding_bytes + sizeof(local_dir_header);
  MINI_CLEAR_OBJ(local_dir_header);
  if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_archive_file_ofs, pArchive_name, archive_name_size) != archive_name_size) {
    MINI_FCLOSE(pSrc_file);
    return MINI_FALSE;
  }
  cur_archive_file_ofs += archive_name_size;
  if (uncomp_size) {
    MINI_uint64 uncomp_remaining = uncomp_size;
    void *pRead_buf = pZip->m_pAlloc(pZip->m_pAlloc_opaque, 1, MINI_ZIP_MAX_IO_BUF_SIZE);
    if (!pRead_buf) {
      MINI_FCLOSE(pSrc_file);
      return MINI_FALSE;
    }
    if (!level) {
      while (uncomp_remaining) {
        MINI_uint n = (MINI_uint)MINI_MIN(MINI_ZIP_MAX_IO_BUF_SIZE, uncomp_remaining);
        if ((MINI_FREAD(pRead_buf, 1, n, pSrc_file) != n) ||
            (pZip->m_pWrite(pZip->m_pIO_opaque, cur_archive_file_ofs, pRead_buf, n) != n)) {
          pZip->m_pFree(pZip->m_pAlloc_opaque, pRead_buf);
          MINI_FCLOSE(pSrc_file);
          return MINI_FALSE;
        }
        uncomp_crc32 = (MINI_uint32)MINI_crc32(uncomp_crc32, (const MINI_uint8 *)pRead_buf, n);
        uncomp_remaining -= n;
        cur_archive_file_ofs += n;
      }
      comp_size = uncomp_size;
    } else {
      MINI_bool result = MINI_FALSE;
      MINI_zip_writer_add_state state;
      tdefl_compressor *pComp = (tdefl_compressor *)pZip->m_pAlloc(
          pZip->m_pAlloc_opaque, 1, sizeof(tdefl_compressor));
      if (!pComp) {
        pZip->m_pFree(pZip->m_pAlloc_opaque, pRead_buf);
        MINI_FCLOSE(pSrc_file);
        return MINI_FALSE;
      }
      state.m_pZip = pZip;
      state.m_cur_archive_file_ofs = cur_archive_file_ofs;
      state.m_comp_size = 0;
      if (tdefl_init(pComp, MINI_zip_writer_add_put_buf_callback, &state, tdefl_create_comp_flags_from_zip_params(
                         level, -15, MINI_DEFAULT_STRATEGY)) != TDEFL_STATUS_OKAY) {
        pZip->m_pFree(pZip->m_pAlloc_opaque, pComp);
        pZip->m_pFree(pZip->m_pAlloc_opaque, pRead_buf);
        MINI_FCLOSE(pSrc_file);
        return MINI_FALSE;
      }
      for (;;) {
        size_t in_buf_size = (MINI_uint32)MINI_MIN(uncomp_remaining, MINI_ZIP_MAX_IO_BUF_SIZE);
        tdefl_status status;
        if (MINI_FREAD(pRead_buf, 1, in_buf_size, pSrc_file) != in_buf_size)
          break;
        uncomp_crc32 = (MINI_uint32)MINI_crc32(
            uncomp_crc32, (const MINI_uint8 *)pRead_buf, in_buf_size);
        uncomp_remaining -= in_buf_size;
        status = tdefl_compress_buffer(pComp, pRead_buf, in_buf_size, uncomp_remaining ? TDEFL_NO_FLUSH
                                                        : TDEFL_FINISH);
        if (status == TDEFL_STATUS_DONE) {
          result = MINI_TRUE;
          break;
        } else if (status != TDEFL_STATUS_OKAY)
          break;
      }
      pZip->m_pFree(pZip->m_pAlloc_opaque, pComp);
      if (!result) {
        pZip->m_pFree(pZip->m_pAlloc_opaque, pRead_buf);
        MINI_FCLOSE(pSrc_file);
        return MINI_FALSE;
      }
      comp_size = state.m_comp_size;
      cur_archive_file_ofs = state.m_cur_archive_file_ofs;
      method = MINI_DEFLATED;
    }
    pZip->m_pFree(pZip->m_pAlloc_opaque, pRead_buf);
  }
  MINI_FCLOSE(pSrc_file);
  pSrc_file = NULL;
  if ((comp_size > 0xFFFFFFFF) || (cur_archive_file_ofs > 0xFFFFFFFF))
    return MINI_FALSE;
  if (!MINI_zip_writer_create_local_dir_header(
          pZip, local_dir_header, (MINI_uint16)archive_name_size, 0, uncomp_size, comp_size, uncomp_crc32, method, 0, dos_time, dos_date))
    return MINI_FALSE;
  if (pZip->m_pWrite(pZip->m_pIO_opaque, local_dir_header_ofs, local_dir_header, sizeof(local_dir_header)) != sizeof(local_dir_header))
    return MINI_FALSE;
  if (!MINI_zip_writer_add_to_central_dir(
          pZip, pArchive_name, (MINI_uint16)archive_name_size, NULL, 0, pComment, comment_size, uncomp_size, comp_size, uncomp_crc32, method, 0, dos_time, dos_date, local_dir_header_ofs, ext_attributes))
    return MINI_FALSE;
  pZip->m_total_files++;
  pZip->m_archive_size = cur_archive_file_ofs;
  return MINI_TRUE;
}
#endif
MINI_bool MINI_zip_writer_add_from_zip_reader(MINI_zip_archive *pZip, MINI_zip_archive *pSource_zip, MINI_uint file_index) {
  MINI_uint n, bit_flags, num_alignment_padding_bytes;
  MINI_uint64 comp_bytes_remaining, local_dir_header_ofs;
  MINI_uint64 cur_src_file_ofs, cur_dst_file_ofs;
  MINI_uint32
      local_header_u32[(MINI_ZIP_LOCAL_DIR_HEADER_SIZE + sizeof(MINI_uint32) - 1) /
                       sizeof(MINI_uint32)];
  MINI_uint8 *pLocal_header = (MINI_uint8 *)local_header_u32;
  MINI_uint8 central_header[MINI_ZIP_CENTRAL_DIR_HEADER_SIZE];
  size_t orig_central_dir_size;
  MINI_zip_internal_state *pState;
  void *pBuf;
  const MINI_uint8 *pSrc_central_header;
  if ((!pZip) || (!pZip->m_pState) || (pZip->m_zip_mode != MINI_ZIP_MODE_WRITING))
    return MINI_FALSE;
  if (NULL == (pSrc_central_header = MINI_zip_reader_get_cdh(pSource_zip, file_index)))
    return MINI_FALSE;
  pState = pZip->m_pState;
  num_alignment_padding_bytes = MINI_zip_writer_compute_padding_needed_for_file_alignment(pZip);
  if ((pZip->m_total_files == 0xFFFF) ||
      ((pZip->m_archive_size + num_alignment_padding_bytes +
        MINI_ZIP_LOCAL_DIR_HEADER_SIZE + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE) >
       0xFFFFFFFF))
    return MINI_FALSE;
  cur_src_file_ofs = MINI_READ_LE32(pSrc_central_header + MINI_ZIP_CDH_LOCAL_HEADER_OFS);
  cur_dst_file_ofs = pZip->m_archive_size;
  if (pSource_zip->m_pRead(pSource_zip->m_pIO_opaque, cur_src_file_ofs, pLocal_header, MINI_ZIP_LOCAL_DIR_HEADER_SIZE) != MINI_ZIP_LOCAL_DIR_HEADER_SIZE)
    return MINI_FALSE;
  if (MINI_READ_LE32(pLocal_header) != MINI_ZIP_LOCAL_DIR_HEADER_SIG)
    return MINI_FALSE;
  cur_src_file_ofs += MINI_ZIP_LOCAL_DIR_HEADER_SIZE;
  if (!MINI_zip_writer_write_zeros(pZip, cur_dst_file_ofs, num_alignment_padding_bytes))
    return MINI_FALSE;
  cur_dst_file_ofs += num_alignment_padding_bytes;
  local_dir_header_ofs = cur_dst_file_ofs;
  if (pZip->m_file_offset_alignment) {
    MINI_ASSERT((local_dir_header_ofs & (pZip->m_file_offset_alignment - 1)) == 0);
  }
  if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_dst_file_ofs, pLocal_header, MINI_ZIP_LOCAL_DIR_HEADER_SIZE) != MINI_ZIP_LOCAL_DIR_HEADER_SIZE)
    return MINI_FALSE;
  cur_dst_file_ofs += MINI_ZIP_LOCAL_DIR_HEADER_SIZE;
  n = MINI_READ_LE16(pLocal_header + MINI_ZIP_LDH_FILENAME_LEN_OFS) +
      MINI_READ_LE16(pLocal_header + MINI_ZIP_LDH_EXTRA_LEN_OFS);
  comp_bytes_remaining = n + MINI_READ_LE32(pSrc_central_header + MINI_ZIP_CDH_COMPRESSED_SIZE_OFS);
  if (NULL == (pBuf = pZip->m_pAlloc(pZip->m_pAlloc_opaque, 1, (size_t)MINI_MAX(sizeof(MINI_uint32) * 4, MINI_MIN(MINI_ZIP_MAX_IO_BUF_SIZE, comp_bytes_remaining)))))
    return MINI_FALSE;
  while (comp_bytes_remaining) {
    n = (MINI_uint)MINI_MIN(MINI_ZIP_MAX_IO_BUF_SIZE, comp_bytes_remaining);
    if (pSource_zip->m_pRead(pSource_zip->m_pIO_opaque, cur_src_file_ofs, pBuf, n) != n) {
      pZip->m_pFree(pZip->m_pAlloc_opaque, pBuf);
      return MINI_FALSE;
    }
    cur_src_file_ofs += n;
    if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_dst_file_ofs, pBuf, n) != n) {
      pZip->m_pFree(pZip->m_pAlloc_opaque, pBuf);
      return MINI_FALSE;
    }
    cur_dst_file_ofs += n;
    comp_bytes_remaining -= n;
  }
  bit_flags = MINI_READ_LE16(pLocal_header + MINI_ZIP_LDH_BIT_FLAG_OFS);
  if (bit_flags & 8) {
    if (pSource_zip->m_pRead(pSource_zip->m_pIO_opaque, cur_src_file_ofs, pBuf, sizeof(MINI_uint32) * 4) != sizeof(MINI_uint32) * 4) {
      pZip->m_pFree(pZip->m_pAlloc_opaque, pBuf);
      return MINI_FALSE;
    }
    n = sizeof(MINI_uint32) * ((MINI_READ_LE32(pBuf) == 0x08074b50) ? 4 : 3);
    if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_dst_file_ofs, pBuf, n) != n) {
      pZip->m_pFree(pZip->m_pAlloc_opaque, pBuf);
      return MINI_FALSE;
    }
    cur_src_file_ofs += n;
    cur_dst_file_ofs += n;
  }
  pZip->m_pFree(pZip->m_pAlloc_opaque, pBuf);
  if (cur_dst_file_ofs > 0xFFFFFFFF)
    return MINI_FALSE;
  orig_central_dir_size = pState->m_central_dir.m_size;
  memcpy(central_header, pSrc_central_header, MINI_ZIP_CENTRAL_DIR_HEADER_SIZE);
  MINI_WRITE_LE32(central_header + MINI_ZIP_CDH_LOCAL_HEADER_OFS, local_dir_header_ofs);
  if (!MINI_zip_array_push_back(pZip, &pState->m_central_dir, central_header, MINI_ZIP_CENTRAL_DIR_HEADER_SIZE))
    return MINI_FALSE;
  n = MINI_READ_LE16(pSrc_central_header + MINI_ZIP_CDH_FILENAME_LEN_OFS) +
      MINI_READ_LE16(pSrc_central_header + MINI_ZIP_CDH_EXTRA_LEN_OFS) +
      MINI_READ_LE16(pSrc_central_header + MINI_ZIP_CDH_COMMENT_LEN_OFS);
  if (!MINI_zip_array_push_back(
          pZip, &pState->m_central_dir, pSrc_central_header + MINI_ZIP_CENTRAL_DIR_HEADER_SIZE, n)) {
    MINI_zip_array_resize(pZip, &pState->m_central_dir, orig_central_dir_size, MINI_FALSE);
    return MINI_FALSE;
  }
  if (pState->m_central_dir.m_size > 0xFFFFFFFF)
    return MINI_FALSE;
  n = (MINI_uint32)orig_central_dir_size;
  if (!MINI_zip_array_push_back(pZip, &pState->m_central_dir_offsets, &n, 1)) {
    MINI_zip_array_resize(pZip, &pState->m_central_dir, orig_central_dir_size, MINI_FALSE);
    return MINI_FALSE;
  }
  pZip->m_total_files++;
  pZip->m_archive_size = cur_dst_file_ofs;
  return MINI_TRUE;
}
MINI_bool MINI_zip_writer_finalize_archive(MINI_zip_archive *pZip) {
  MINI_zip_internal_state *pState;
  MINI_uint64 central_dir_ofs, central_dir_size;
  MINI_uint8 hdr[MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE];
  if ((!pZip) || (!pZip->m_pState) || (pZip->m_zip_mode != MINI_ZIP_MODE_WRITING))
    return MINI_FALSE;
  pState = pZip->m_pState;
  if ((pZip->m_total_files > 0xFFFF) ||
      ((pZip->m_archive_size + pState->m_central_dir.m_size +
        MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE) > 0xFFFFFFFF))
    return MINI_FALSE;
  central_dir_ofs = 0;
  central_dir_size = 0;
  if (pZip->m_total_files) {
    central_dir_ofs = pZip->m_archive_size;
    central_dir_size = pState->m_central_dir.m_size;
    pZip->m_central_directory_file_ofs = central_dir_ofs;
    if (pZip->m_pWrite(pZip->m_pIO_opaque, central_dir_ofs, pState->m_central_dir.m_p, (size_t)central_dir_size) != central_dir_size)
      return MINI_FALSE;
    pZip->m_archive_size += central_dir_size;
  }
  MINI_CLEAR_OBJ(hdr);
  MINI_WRITE_LE32(hdr + MINI_ZIP_ECDH_SIG_OFS, MINI_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG);
  MINI_WRITE_LE16(hdr + MINI_ZIP_ECDH_CDIR_NUM_ENTRIES_ON_DISK_OFS, pZip->m_total_files);
  MINI_WRITE_LE16(hdr + MINI_ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS, pZip->m_total_files);
  MINI_WRITE_LE32(hdr + MINI_ZIP_ECDH_CDIR_SIZE_OFS, central_dir_size);
  MINI_WRITE_LE32(hdr + MINI_ZIP_ECDH_CDIR_OFS_OFS, central_dir_ofs);
  if (pZip->m_pWrite(pZip->m_pIO_opaque, pZip->m_archive_size, hdr, sizeof(hdr)) != sizeof(hdr))
    return MINI_FALSE;
#ifndef MINI_NO_STDIO
  if ((pState->m_pFile) && (MINI_FFLUSH(pState->m_pFile) == EOF))
    return MINI_FALSE;
#endif
  pZip->m_archive_size += sizeof(hdr);
  pZip->m_zip_mode = MINI_ZIP_MODE_WRITING_HAS_BEEN_FINALIZED;
  return MINI_TRUE;
}
MINI_bool MINI_zip_writer_finalize_heap_archive(MINI_zip_archive *pZip, void **pBuf, size_t *pSize) {
  if ((!pZip) || (!pZip->m_pState) || (!pBuf) || (!pSize))
    return MINI_FALSE;
  if (pZip->m_pWrite != MINI_zip_heap_write_func)
    return MINI_FALSE;
  if (!MINI_zip_writer_finalize_archive(pZip))
    return MINI_FALSE;
  *pBuf = pZip->m_pState->m_pMem;
  *pSize = pZip->m_pState->m_mem_size;
  pZip->m_pState->m_pMem = NULL;
  pZip->m_pState->m_mem_size = pZip->m_pState->m_mem_capacity = 0;
  return MINI_TRUE;
}
MINI_bool MINI_zip_writer_end(MINI_zip_archive *pZip) {
  MINI_zip_internal_state *pState;
  MINI_bool status = MINI_TRUE;
  if ((!pZip) || (!pZip->m_pState) || (!pZip->m_pAlloc) || (!pZip->m_pFree) ||
      ((pZip->m_zip_mode != MINI_ZIP_MODE_WRITING) &&
       (pZip->m_zip_mode != MINI_ZIP_MODE_WRITING_HAS_BEEN_FINALIZED)))
    return MINI_FALSE;
  pState = pZip->m_pState;
  pZip->m_pState = NULL;
  MINI_zip_array_clear(pZip, &pState->m_central_dir);
  MINI_zip_array_clear(pZip, &pState->m_central_dir_offsets);
  MINI_zip_array_clear(pZip, &pState->m_sorted_central_dir_offsets);
#ifndef MINI_NO_STDIO
  if (pState->m_pFile) {
    MINI_FCLOSE(pState->m_pFile);
    pState->m_pFile = NULL;
  }
#endif
  if ((pZip->m_pWrite == MINI_zip_heap_write_func) && (pState->m_pMem)) {
    pZip->m_pFree(pZip->m_pAlloc_opaque, pState->m_pMem);
    pState->m_pMem = NULL;
  }
  pZip->m_pFree(pZip->m_pAlloc_opaque, pState);
  pZip->m_zip_mode = MINI_ZIP_MODE_INVALID;
  return status;
}
#ifndef MINI_NO_STDIO
MINI_bool MINI_zip_add_mem_to_archive_file_in_place(
    const char *pZip_filename, const char *pArchive_name, const void *pBuf, size_t buf_size, const void *pComment, MINI_uint16 comment_size, MINI_uint level_and_flags) {
  MINI_bool status, created_new_archive = MINI_FALSE;
  MINI_zip_archive zip_archive;
  struct MINI_FILE_STAT_STRUCT file_stat;
  MINI_CLEAR_OBJ(zip_archive);
  if ((int)level_and_flags < 0)
    level_and_flags = MINI_DEFAULT_LEVEL;
  if ((!pZip_filename) || (!pArchive_name) || ((buf_size) && (!pBuf)) ||
      ((comment_size) && (!pComment)) ||
      ((level_and_flags & 0xF) > MINI_UBER_COMPRESSION))
    return MINI_FALSE;
  if (!MINI_zip_writer_validate_archive_name(pArchive_name))
    return MINI_FALSE;
  if (MINI_FILE_STAT(pZip_filename, &file_stat) != 0) {
    if (!MINI_zip_writer_init_file(&zip_archive, pZip_filename, 0))
      return MINI_FALSE;
    created_new_archive = MINI_TRUE;
  } else {
    if (!MINI_zip_reader_init_file(&zip_archive, pZip_filename, level_and_flags |
                                     MINI_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY))
      return MINI_FALSE;
    if (!MINI_zip_writer_init_from_reader(&zip_archive, pZip_filename)) {
      MINI_zip_reader_end(&zip_archive);
      return MINI_FALSE;
    }
  }
  status = MINI_zip_writer_add_mem_ex(&zip_archive, pArchive_name, pBuf, buf_size, pComment, comment_size, level_and_flags, 0, 0);
  if (!MINI_zip_writer_finalize_archive(&zip_archive))
    status = MINI_FALSE;
  if (!MINI_zip_writer_end(&zip_archive))
    status = MINI_FALSE;
  if ((!status) && (created_new_archive)) {
    int ignoredStatus = MINI_DELETE_FILE(pZip_filename);
    (void)ignoredStatus;
  }
  return status;
}
void *MINI_zip_extract_archive_file_to_heap(const char *pZip_filename, const char *pArchive_name, size_t *pSize, MINI_uint flags) {
  int file_index;
  MINI_zip_archive zip_archive;
  void *p = NULL;
  if (pSize)
    *pSize = 0;
  if ((!pZip_filename) || (!pArchive_name))
    return NULL;
  MINI_CLEAR_OBJ(zip_archive);
  if (!MINI_zip_reader_init_file(&zip_archive, pZip_filename, flags |
                                   MINI_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY))
    return NULL;
  if ((file_index = MINI_zip_reader_locate_file(&zip_archive, pArchive_name, NULL, flags)) >= 0)
    p = MINI_zip_reader_extract_to_heap(&zip_archive, file_index, pSize, flags);
  MINI_zip_reader_end(&zip_archive);
  return p;
}
#endif
#endif
#endif
#ifdef __cplusplus
}
#endif
#endif
#include <limits.h>
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint;
#define my_min(a, b) (((a) < (b)) ? (a) : (b))
#define BUF_SIZE (1024 * 1024)
static uint8 s_inbuf[BUF_SIZE];
static uint8 s_outbuf[BUF_SIZE];
int main(int argc, char *argv[]) {
  const char *mode;
  FILE *inputFile, *outputFile;
  uint infile_size;
  int level = MINI_UBER_COMPRESSION;
  z_stream stream;
  int p = 1;
  const char *sourceFileName;
  const char *outputFileName;
  long file_loc;
  if (argc < 4) {
    printf("mini (June 4th 2020).\n");
    printf("Usage: mini [options] [mode:c or d] inputFile outputFile\n");
    printf("\nModes:\n");
    printf("c - Compresses file inputFile to a stream in file outputFile\n");
    printf("d - Decompress stream in file inputFile to file outputFile\n");
    printf("\nOptions:\n");
    printf("-l[0-10] - Compression level, higher values are slower.\n");
    printf("\nThanks to Rich Geldreich, Rich Geldreich, Alex Evans, Paul "
           "Holden, Thorsten Scheuermann, Matt Pritchard, Sean Barrett, Bruce "
           "Dawson, and Janez Zemva.\n");
    return EXIT_FAILURE;
  }
  while ((p < argc) && (argv[p][0] == '-')) {
    switch (argv[p][1]) {
    case 'l': {
      level = atoi(&argv[1][2]);
      if ((level < 0) || (level > 10)) {
        printf("Invalid level!\n");
        return EXIT_FAILURE;
      }
      break;
    }
    default: {
      printf("Invalid option: %s\n", argv[p]);
      return EXIT_FAILURE;
    }
    }
    p++;
  }
  if ((argc - p) < 3) {
    printf("Must specify mode, input filename, and output filename after "
           "options!\n");
    return EXIT_FAILURE;
  } else if ((argc - p) > 3) {
    printf("Too many filenames!\n");
    return EXIT_FAILURE;
  }
  mode = argv[p++];
  if (!strchr("cCdD", mode[0])) {
    printf("Invalid mode!\n");
    return EXIT_FAILURE;
  }
  sourceFileName = argv[p++];
  outputFileName = argv[p++];
  printf("Mode: %c, Level: %u\nInput File: \"%s\"\nOutput File: \"%s\"\n", mode[0], level, sourceFileName, outputFileName);
  inputFile = fopen(sourceFileName, "rb");
  if (!inputFile) {
    printf("Failed opening input file!\n");
    return EXIT_FAILURE;
  }
  fseek(inputFile, 0, SEEK_END);
  file_loc = ftell(inputFile);
  fseek(inputFile, 0, SEEK_SET);
  if ((file_loc < 0) || (file_loc > INT_MAX)) {
    printf("File is too large to be processed by mini.\n");
    return EXIT_FAILURE;
  }
  infile_size = (uint)file_loc;
  outputFile = fopen(outputFileName, "wb");
  if (!outputFile) {
    printf("Failed opening output file!\n");
    return EXIT_FAILURE;
  }
  printf("Input file size: %u\n", infile_size);
  memset(&stream, 0, sizeof(stream));
  stream.next_in = s_inbuf;
  stream.avail_in = 0;
  stream.next_out = s_outbuf;
  stream.avail_out = BUF_SIZE;
  if ((mode[0] == 'c') || (mode[0] == 'C')) {
    uint infile_remaining = infile_size;
    if (deflateInit(&stream, level) != Z_OK) {
      printf("deflateInit() failed!\n");
      return EXIT_FAILURE;
    }
    for (;;) {
      int status;
      if (!stream.avail_in) {
        uint n = my_min(BUF_SIZE, infile_remaining);
        if (fread(s_inbuf, 1, n, inputFile) != n) {
          printf("Failed reading from input file!\n");
          return EXIT_FAILURE;
        }
        stream.next_in = s_inbuf;
        stream.avail_in = n;
        infile_remaining -= n;
      }
      status = deflate(&stream, infile_remaining ? Z_NO_FLUSH : Z_FINISH);
      if ((status == Z_STREAM_END) || (!stream.avail_out)) {
        uint n = BUF_SIZE - stream.avail_out;
        if (fwrite(s_outbuf, 1, n, outputFile) != n) {
          printf("Failed writing to output file!\n");
          return EXIT_FAILURE;
        }
        stream.next_out = s_outbuf;
        stream.avail_out = BUF_SIZE;
      }
      if (status == Z_STREAM_END)
        break;
      else if (status != Z_OK) {
        printf("deflate() failed with status %i!\n", status);
        return EXIT_FAILURE;
      }
    }
    if (deflateEnd(&stream) != Z_OK) {
      printf("deflateEnd() failed!\n");
      return EXIT_FAILURE;
    }
  } else if ((mode[0] == 'd') || (mode[0] == 'D')) {
    uint infile_remaining = infile_size;
    if (inflateInit(&stream)) {
      printf("inflateInit() failed!\n");
      return EXIT_FAILURE;
    }
    for (;;) {
      int status;
      if (!stream.avail_in) {
        uint n = my_min(BUF_SIZE, infile_remaining);
        if (fread(s_inbuf, 1, n, inputFile) != n) {
          printf("Failed reading from input file!\n");
          return EXIT_FAILURE;
        }
        stream.next_in = s_inbuf;
        stream.avail_in = n;
        infile_remaining -= n;
      }
      status = inflate(&stream, Z_SYNC_FLUSH);
      if ((status == Z_STREAM_END) || (!stream.avail_out)) {
        uint n = BUF_SIZE - stream.avail_out;
        if (fwrite(s_outbuf, 1, n, outputFile) != n) {
          printf("Failed writing to output file!\n");
          return EXIT_FAILURE;
        }
        stream.next_out = s_outbuf;
        stream.avail_out = BUF_SIZE;
      }
      if (status == Z_STREAM_END)
        break;
      else if (status != Z_OK) {
        printf("inflate() failed with status %i!\n", status);
        return EXIT_FAILURE;
      }
    }
    if (inflateEnd(&stream) != Z_OK) {
      printf("inflateEnd() failed!\n");
      return EXIT_FAILURE;
    }
  } else {
    printf("Invalid mode!\n");
    return EXIT_FAILURE;
  }
  fclose(inputFile);
  if (EOF == fclose(outputFile)) {
    printf("Failed writing to output file!\n");
    return EXIT_FAILURE;
  }
  printf("Total input bytes: %u\n", (MINI_uint32)stream.total_in);
  printf("Total output bytes: %u\n", (MINI_uint32)stream.total_out);
  printf("Done.\n");
  return EXIT_SUCCESS;
}
