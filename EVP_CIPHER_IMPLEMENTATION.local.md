# EVP Cipher Implementation for Net::SSLeay

> **NOTE:** This file is for local documentation only. Do not check in.

## Overview

Implemented **Option 3 (Hybrid approach)** - both low-level EVP cipher functions and high-level helper functions for symmetric encryption/decryption, including AEAD (authenticated encryption).

## Files Modified

| File | Changes |
|------|---------|
| `typemap` | Added `EVP_CIPHER_CTX *` type mapping |
| `SSLeay.xs` | Added all EVP cipher functions (see below) |
| `lib/Net/SSLeay.pm` | Added Perl convenience functions |
| `lib/Net/SSLeay.pod` | Full documentation for all new functions |
| `t/local/66_evp_cipher.t` | Test suite (47 tests, all passing) |
| `MANIFEST` | Added new test file |

## Functions Added

### Low-Level Functions (OpenSSL 1.0.0+) - in SSLeay.xs

**Context Management:**
- `EVP_CIPHER_CTX_new()` - Create new cipher context
- `EVP_CIPHER_CTX_free($ctx)` - Free cipher context
- `EVP_CIPHER_CTX_reset($ctx)` - Reset context (1.1.0+ only)
- `EVP_CIPHER_CTX_set_key_length($ctx, $keylen)`
- `EVP_CIPHER_CTX_set_padding($ctx, $pad)`

**Cipher Info:**
- `EVP_CIPHER_key_length($cipher)`
- `EVP_CIPHER_iv_length($cipher)`
- `EVP_CIPHER_block_size($cipher)`
- `EVP_CIPHER_CTX_key_length($ctx)`
- `EVP_CIPHER_CTX_iv_length($ctx)`
- `EVP_CIPHER_CTX_block_size($ctx)`

**Encryption:**
- `EVP_EncryptInit($ctx, $cipher, $key, $iv)`
- `EVP_EncryptInit_ex($ctx, $cipher, $engine, $key, $iv)`
- `EVP_EncryptUpdate($ctx, $plaintext)` → returns ciphertext
- `EVP_EncryptFinal($ctx)` → returns final block
- `EVP_EncryptFinal_ex($ctx)` → returns final block

**Decryption:**
- `EVP_DecryptInit($ctx, $cipher, $key, $iv)`
- `EVP_DecryptInit_ex($ctx, $cipher, $engine, $key, $iv)`
- `EVP_DecryptUpdate($ctx, $ciphertext)` → returns plaintext
- `EVP_DecryptFinal($ctx)` → returns final block
- `EVP_DecryptFinal_ex($ctx)` → returns final block

**Advanced:**
- `EVP_CIPHER_CTX_ctrl($ctx, $type, $arg, $ptr)` - For GCM tag handling etc.

### XS Helper Functions (P_ prefix)

- `P_EVP_Cipher($cipher, $key, $iv, $data, $enc)` - One-shot encrypt/decrypt (CBC, CTR, etc.)
- `P_EVP_Cipher_AEAD_encrypt($cipher, $key, $iv, $plaintext, $aad)` - Returns ($ciphertext, $tag)
- `P_EVP_Cipher_AEAD_decrypt($cipher, $key, $iv, $ciphertext, $tag, $aad)` - Verifies tag, dies on tamper

### Perl Convenience Functions (in SSLeay.pm)

- `encrypt_with_prepended_iv($cipher, $key, $plaintext)` - Auto-generates IV, prepends to output
- `decrypt_with_prepended_iv($cipher, $key, $data)` - Extracts IV from data
- `encrypt_aead_with_prepended_iv($cipher, $key, $plaintext, $aad)` - Returns: IV || ciphertext || tag
- `decrypt_aead_with_prepended_iv($cipher, $key, $data, $aad)` - Extracts IV and tag, verifies

### OpenSSL 1.1.0+ Functions

- `OpenSSL_add_all_ciphers()` - Register all cipher algorithms
- `P_EVP_CIPHER_list_all()` - List available ciphers (returns arrayref)

## Usage Examples

### High-Level API (Simple)

```perl
use Net::SSLeay qw(RAND_bytes);

# Generate random key and IV
my $key = '';
my $iv = '';
Net::SSLeay::RAND_bytes($key, 32);  # 256-bit key for AES-256
Net::SSLeay::RAND_bytes($iv, 16);   # 128-bit IV for CBC

my $plaintext = "Secret message";

# Encrypt (enc=1)
my $ciphertext = Net::SSLeay::P_EVP_Cipher('aes-256-cbc', $key, $iv, $plaintext, 1);

# Decrypt (enc=0)
my $decrypted = Net::SSLeay::P_EVP_Cipher('aes-256-cbc', $key, $iv, $ciphertext, 0);
```

### Low-Level API (Streaming/Advanced)

```perl
my $ctx = Net::SSLeay::EVP_CIPHER_CTX_new();
my $cipher = Net::SSLeay::EVP_get_cipherbyname('aes-256-cbc');

# Encrypt
Net::SSLeay::EVP_EncryptInit_ex($ctx, $cipher, undef, $key, $iv);
my $ciphertext = Net::SSLeay::EVP_EncryptUpdate($ctx, $chunk1);
$ciphertext .= Net::SSLeay::EVP_EncryptUpdate($ctx, $chunk2);
$ciphertext .= Net::SSLeay::EVP_EncryptFinal_ex($ctx);

# Reset for decryption (OpenSSL 1.1.0+)
Net::SSLeay::EVP_CIPHER_CTX_reset($ctx);

# Decrypt
Net::SSLeay::EVP_DecryptInit_ex($ctx, $cipher, undef, $key, $iv);
my $plaintext = Net::SSLeay::EVP_DecryptUpdate($ctx, $ciphertext);
$plaintext .= Net::SSLeay::EVP_DecryptFinal_ex($ctx);

Net::SSLeay::EVP_CIPHER_CTX_free($ctx);
```

### Convenience Functions (Simplest - Auto IV)

```perl
use Net::SSLeay qw(RAND_bytes encrypt_with_prepended_iv decrypt_with_prepended_iv);

my $key = '';
Net::SSLeay::RAND_bytes($key, 32);

# CBC - no need to manage IV manually
my $encrypted = Net::SSLeay::encrypt_with_prepended_iv('aes-256-cbc', $key, $plaintext);
my $decrypted = Net::SSLeay::decrypt_with_prepended_iv('aes-256-cbc', $key, $encrypted);
```

### AEAD/GCM (Authenticated Encryption)

```perl
use Net::SSLeay qw(RAND_bytes encrypt_aead_with_prepended_iv decrypt_aead_with_prepended_iv);

my $key = '';
Net::SSLeay::RAND_bytes($key, 32);

my $aad = "Metadata - authenticated but not encrypted";

# GCM provides both encryption AND integrity verification
my $encrypted = Net::SSLeay::encrypt_aead_with_prepended_iv('aes-256-gcm', $key, $plaintext, $aad);
my $decrypted = Net::SSLeay::decrypt_aead_with_prepended_iv('aes-256-gcm', $key, $encrypted, $aad);
# Dies if data has been tampered with!
```

### List Available Ciphers

```perl
Net::SSLeay::OpenSSL_add_all_ciphers();
my $ciphers = Net::SSLeay::P_EVP_CIPHER_list_all();
print "Available ciphers: @$ciphers\n";
```

## Supported Cipher Names

Common cipher names for `EVP_get_cipherbyname()` and `P_EVP_Cipher()`:

**Standard modes (use with encrypt_with_prepended_iv):**
- `aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc`
- `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`
- `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`
- `aes-128-ofb`, `aes-192-ofb`, `aes-256-ofb`
- `des-cbc`, `des-ecb`, `des-ede3-cbc`
- `camellia-128-cbc`, `camellia-256-cbc`

**AEAD modes (use with encrypt_aead_with_prepended_iv):**
- `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`
- `chacha20-poly1305`

Use `P_EVP_CIPHER_list_all()` to get the full list for your OpenSSL version.

## Version Compatibility

| Function | Minimum OpenSSL |
|----------|-----------------|
| EVP_CIPHER_CTX_new/free | 1.0.0 |
| EVP_Encrypt*/EVP_Decrypt* | 1.0.0 |
| P_EVP_Cipher | 1.0.0 |
| P_EVP_Cipher_AEAD_encrypt/decrypt | 1.0.0 |
| encrypt_with_prepended_iv | 1.0.0 |
| encrypt_aead_with_prepended_iv | 1.0.0 |
| EVP_CIPHER_CTX_reset | 1.1.0 |
| OpenSSL_add_all_ciphers | 1.1.0 |
| P_EVP_CIPHER_list_all | 1.1.0 |

## Testing

```bash
cd /home/bjerre/opensource/Net-SSLeay
perl Makefile.PL
make
prove -Iblib/lib -Iblib/arch t/local/66_evp_cipher.t
```

All 58 tests pass on OpenSSL 3.0.2.

## What is AEAD?

**AEAD = Authenticated Encryption with Associated Data**

| Mode | Encrypted | Authenticated | Tamper Detection |
|------|-----------|---------------|------------------|
| **CBC** | ✅ Yes | ❌ No | ❌ None |
| **GCM** (AEAD) | ✅ Yes | ✅ Yes | ✅ Tag verification |

With CBC, an attacker can flip bits in ciphertext without detection.
With GCM, any tampering causes decryption to fail with an authentication error.

## File-Based Functions

For working with encrypted files, convenience functions are provided:

### String ↔ File

```perl
# Encrypt plaintext to file (CBC)
Net::SSLeay::encrypt_to_file_with_prepended_iv('aes-256-cbc', $key, $plaintext, '/path/file.enc');
my $plaintext = Net::SSLeay::decrypt_file_with_prepended_iv('aes-256-cbc', $key, '/path/file.enc');

# AEAD mode (GCM)
Net::SSLeay::encrypt_aead_to_file_with_prepended_iv('aes-256-gcm', $key, $plaintext, '/path/file.enc', $aad);
my $plaintext = Net::SSLeay::decrypt_aead_file_with_prepended_iv('aes-256-gcm', $key, '/path/file.enc', $aad);
```

### File → File (Streaming)

For large files, use streaming file-to-file functions (64KB chunks):

```perl
# CBC mode streaming
Net::SSLeay::encrypt_file_to_file_with_prepended_iv('aes-256-cbc', $key, 'input.bin', 'output.enc');
Net::SSLeay::decrypt_file_to_file_with_prepended_iv('aes-256-cbc', $key, 'output.enc', 'decrypted.bin');

# GCM mode (note: AEAD decrypt loads entire file for tag verification)
Net::SSLeay::encrypt_aead_file_to_file_with_prepended_iv('aes-256-gcm', $key, 'input.bin', 'output.enc', $aad);
Net::SSLeay::decrypt_aead_file_to_file_with_prepended_iv('aes-256-gcm', $key, 'output.enc', 'decrypted.bin', $aad);
```

## TODO / Future Enhancements

- [x] ~~Add GCM-specific helpers~~ DONE: P_EVP_Cipher_AEAD_encrypt/decrypt
- [x] ~~Add convenience functions with auto-IV~~ DONE: encrypt_with_prepended_iv, etc.
- [x] ~~Add file-based convenience functions~~ DONE: encrypt_to_file, decrypt_file, file-to-file
- [ ] Add helper for reading IV from file (like the Epic EVP.xs has)
- [ ] Consider adding EVP_CipherInit/Update/Final for unified encrypt/decrypt
- [ ] Export EVP_CTRL_* constants for EVP_CIPHER_CTX_ctrl

