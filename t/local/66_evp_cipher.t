#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Net::SSLeay;

# Initialize OpenSSL
Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::OpenSSL_add_all_algorithms();

plan tests => 58;

# Test EVP_get_cipherbyname
{
    my $cipher = Net::SSLeay::EVP_get_cipherbyname('aes-256-cbc');
    ok( $cipher, 'EVP_get_cipherbyname returns a cipher for aes-256-cbc' );

    my $no_cipher = Net::SSLeay::EVP_get_cipherbyname('no-such-cipher');
    ok( !$no_cipher, 'EVP_get_cipherbyname returns undef for unknown cipher' );
}

# Test EVP_CIPHER_* functions
SKIP: {
    skip 'EVP_CIPHER_CTX_new requires OpenSSL 1.0.0+', 25
      if Net::SSLeay::SSLeay() < 0x10000000;

    my $cipher = Net::SSLeay::EVP_get_cipherbyname('aes-256-cbc');
    ok( $cipher, 'Got aes-256-cbc cipher' );

    # Test cipher info functions
    my $key_len = Net::SSLeay::EVP_CIPHER_key_length($cipher);
    is( $key_len, 32, 'AES-256 key length is 32 bytes' );

    my $iv_len = Net::SSLeay::EVP_CIPHER_iv_length($cipher);
    is( $iv_len, 16, 'AES-CBC IV length is 16 bytes' );

    my $block_size = Net::SSLeay::EVP_CIPHER_block_size($cipher);
    is( $block_size, 16, 'AES block size is 16 bytes' );

    # Test context creation
    my $ctx = Net::SSLeay::EVP_CIPHER_CTX_new();
    ok( $ctx, 'EVP_CIPHER_CTX_new returns a context' );

    # Test context info functions after init
    my $key = 'A' x 32;    # 256-bit key
    my $iv  = 'B' x 16;    # 128-bit IV

    my $init_ok = Net::SSLeay::EVP_EncryptInit( $ctx, $cipher, $key, $iv );
    ok( $init_ok, 'EVP_EncryptInit succeeds' );

    my $ctx_key_len = Net::SSLeay::EVP_CIPHER_CTX_key_length($ctx);
    is( $ctx_key_len, 32, 'Context key length is 32' );

    my $ctx_iv_len = Net::SSLeay::EVP_CIPHER_CTX_iv_length($ctx);
    is( $ctx_iv_len, 16, 'Context IV length is 16' );

    my $ctx_block_size = Net::SSLeay::EVP_CIPHER_CTX_block_size($ctx);
    is( $ctx_block_size, 16, 'Context block size is 16' );

    Net::SSLeay::EVP_CIPHER_CTX_free($ctx);
    pass('EVP_CIPHER_CTX_free completed');

    # Test low-level encrypt/decrypt
    {
        my $ctx2 = Net::SSLeay::EVP_CIPHER_CTX_new();
        my $plaintext =
          "Hello, World! This is a test message for AES encryption.";

        # Encrypt
        Net::SSLeay::EVP_EncryptInit_ex( $ctx2, $cipher, undef, $key, $iv );
        my $ciphertext = Net::SSLeay::EVP_EncryptUpdate( $ctx2, $plaintext );
        ok( defined $ciphertext, 'EVP_EncryptUpdate returns ciphertext' );
        my $final = Net::SSLeay::EVP_EncryptFinal_ex($ctx2);
        ok( defined $final, 'EVP_EncryptFinal_ex returns final block' );
        $ciphertext .= $final;

        ok( length($ciphertext) > 0, 'Ciphertext has content' );
        isnt( $ciphertext, $plaintext, 'Ciphertext differs from plaintext' );

        # Test context reset if available (OpenSSL 1.1.0+)
      SKIP: {
            skip 'EVP_CIPHER_CTX_reset requires OpenSSL 1.1.0+', 1
              if Net::SSLeay::SSLeay() < 0x10100000;

            my $reset_ok = Net::SSLeay::EVP_CIPHER_CTX_reset($ctx2);
            ok( $reset_ok, 'EVP_CIPHER_CTX_reset succeeds' );
        }

        # Decrypt
        Net::SSLeay::EVP_DecryptInit_ex( $ctx2, $cipher, undef, $key, $iv );
        my $decrypted = Net::SSLeay::EVP_DecryptUpdate( $ctx2, $ciphertext );
        ok( defined $decrypted, 'EVP_DecryptUpdate returns plaintext' );
        my $dec_final = Net::SSLeay::EVP_DecryptFinal_ex($ctx2);
        ok( defined $dec_final, 'EVP_DecryptFinal_ex returns final block' );
        $decrypted .= $dec_final;

        is( $decrypted, $plaintext, 'Decrypted text matches original' );

        Net::SSLeay::EVP_CIPHER_CTX_free($ctx2);
    }

    # Test high-level P_EVP_Cipher helper
    {
        my $plaintext = "High-level API test with P_EVP_Cipher function!";

        # Encrypt using helper
        my $ciphertext =
          Net::SSLeay::P_EVP_Cipher( 'aes-256-cbc', $key, $iv, $plaintext, 1 );
        ok( defined $ciphertext, 'P_EVP_Cipher encrypt returns ciphertext' );
        ok( length($ciphertext) > 0, 'Helper ciphertext has content' );
        isnt( $ciphertext, $plaintext,
            'Helper ciphertext differs from plaintext' );

        # Decrypt using helper
        my $decrypted =
          Net::SSLeay::P_EVP_Cipher( 'aes-256-cbc', $key, $iv, $ciphertext, 0 );
        ok( defined $decrypted, 'P_EVP_Cipher decrypt returns plaintext' );
        is( $decrypted, $plaintext, 'Helper decrypted text matches original' );
    }

    # Test error handling for wrong key length
    {
        my $short_key = 'X' x 16;    # Too short for AES-256
        eval {
            Net::SSLeay::P_EVP_Cipher( 'aes-256-cbc', $short_key, $iv, 'test',
                1 );
        };
        like(
            $@,
            qr/Key length mismatch/,
            'P_EVP_Cipher dies on wrong key length'
        );
    }

    # Test error handling for unknown cipher
    {
        eval {
            Net::SSLeay::P_EVP_Cipher( 'no-such-cipher', $key, $iv, 'test', 1 );
        };
        like( $@, qr/Unknown cipher/, 'P_EVP_Cipher dies on unknown cipher' );
    }
}

# Test P_EVP_CIPHER_list_all if available
SKIP: {
    skip 'P_EVP_CIPHER_list_all requires OpenSSL 1.1.0+', 0
      if Net::SSLeay::SSLeay() < 0x10100000;

    # Only test if the function exists
    if ( Net::SSLeay->can('P_EVP_CIPHER_list_all') ) {
        my $ciphers = Net::SSLeay::P_EVP_CIPHER_list_all();
        ok( ref($ciphers) eq 'ARRAY',
            'P_EVP_CIPHER_list_all returns an array ref' );
        ok( @$ciphers > 0, 'Cipher list is not empty' );

        # Check that common ciphers are present
        my %cipher_set = map { $_ => 1 } @$ciphers;
        ok( $cipher_set{'aes-256-cbc'} || $cipher_set{'AES-256-CBC'},
            'aes-256-cbc is in cipher list' );
    }
}

# Test AEAD functions (GCM)
SKIP: {
    skip 'AEAD functions require OpenSSL 1.0.0+', 9
      if Net::SSLeay::SSLeay() < 0x10000000;

    my $key       = 'K' x 32;    # 256-bit key
    my $iv        = 'I' x 12;    # 12-byte IV for GCM
    my $plaintext = "AEAD test message - authenticated and encrypted!";
    my $aad       = "Additional authenticated data - not encrypted";

    # Test P_EVP_Cipher_AEAD_encrypt
    my ( $ciphertext, $tag ) =
      Net::SSLeay::P_EVP_Cipher_AEAD_encrypt( 'aes-256-gcm', $key, $iv,
        $plaintext, $aad );
    ok( defined $ciphertext, 'AEAD encrypt returns ciphertext' );
    ok( defined $tag,        'AEAD encrypt returns tag' );
    is( length($tag), 16, 'AEAD tag is 16 bytes' );
    isnt( $ciphertext, $plaintext, 'AEAD ciphertext differs from plaintext' );

    # Test P_EVP_Cipher_AEAD_decrypt
    my $decrypted =
      Net::SSLeay::P_EVP_Cipher_AEAD_decrypt( 'aes-256-gcm', $key, $iv,
        $ciphertext, $tag, $aad );
    ok( defined $decrypted, 'AEAD decrypt returns plaintext' );
    is( $decrypted, $plaintext, 'AEAD decrypted matches original' );

    # Test AEAD without AAD
    my ( $ct2, $tag2 ) =
      Net::SSLeay::P_EVP_Cipher_AEAD_encrypt( 'aes-256-gcm', $key, $iv,
        $plaintext );
    my $dec2 = Net::SSLeay::P_EVP_Cipher_AEAD_decrypt( 'aes-256-gcm',
        $key, $iv, $ct2, $tag2 );
    is( $dec2, $plaintext, 'AEAD without AAD works' );

    # Test authentication failure (tampered data)
    my $tampered = $ciphertext;
    substr( $tampered, 0, 1 ) ^= "\xff";    # Flip bits
    eval {
        Net::SSLeay::P_EVP_Cipher_AEAD_decrypt( 'aes-256-gcm', $key, $iv,
            $tampered, $tag, $aad );
    };
    like( $@, qr/authentication failed|tampered/,
        'AEAD detects tampered data' );

    # Test authentication failure (wrong AAD)
    eval {
        Net::SSLeay::P_EVP_Cipher_AEAD_decrypt( 'aes-256-gcm', $key, $iv,
            $ciphertext, $tag, "wrong aad" );
    };
    like( $@, qr/authentication failed|tampered/, 'AEAD detects wrong AAD' );
}

# Test Perl convenience functions
SKIP: {
    skip 'Convenience functions require OpenSSL 1.0.0+', 9
      if Net::SSLeay::SSLeay() < 0x10000000;

    my $key = '';
    Net::SSLeay::RAND_bytes( $key, 32 );
    my $plaintext = "Testing convenience functions with random key!";

    # Test encrypt_with_prepended_iv / decrypt_with_prepended_iv (CBC)
    {
        my $encrypted =
          Net::SSLeay::encrypt_with_prepended_iv( 'aes-256-cbc', $key,
            $plaintext );
        ok( defined $encrypted, 'encrypt_with_prepended_iv returns data' );
        ok( length($encrypted) > length($plaintext),
            'Encrypted has IV + padding' );

        my $decrypted =
          Net::SSLeay::decrypt_with_prepended_iv( 'aes-256-cbc', $key,
            $encrypted );
        is( $decrypted, $plaintext,
            'decrypt_with_prepended_iv recovers plaintext' );
    }

    # Test with CTR mode (no padding)
    {
        my $encrypted =
          Net::SSLeay::encrypt_with_prepended_iv( 'aes-256-ctr', $key,
            $plaintext );
        ok( defined $encrypted, 'CTR encrypt_with_prepended_iv works' );

        my $decrypted =
          Net::SSLeay::decrypt_with_prepended_iv( 'aes-256-ctr', $key,
            $encrypted );
        is( $decrypted, $plaintext, 'CTR mode roundtrip works' );
    }

    # Test AEAD convenience functions (GCM)
    {
        my $aad = "Header info";
        my $encrypted =
          Net::SSLeay::encrypt_aead_with_prepended_iv( 'aes-256-gcm', $key,
            $plaintext, $aad );
        ok( defined $encrypted, 'encrypt_aead_with_prepended_iv returns data' );

        # Should be: 12 (IV) + len(ciphertext) + 16 (tag)
        ok( length($encrypted) >= 12 + length($plaintext) + 16,
            'AEAD encrypted has IV + data + tag' );

        my $decrypted =
          Net::SSLeay::decrypt_aead_with_prepended_iv( 'aes-256-gcm', $key,
            $encrypted, $aad );
        is( $decrypted, $plaintext, 'AEAD convenience roundtrip works' );
    }
}

# Test file-based convenience functions
SKIP: {
    skip 'File functions require OpenSSL 1.0.0+', 12
      if Net::SSLeay::SSLeay() < 0x10000000;

    use File::Temp qw(tempfile);

    my $key = '';
    Net::SSLeay::RAND_bytes( $key, 32 );
    my $plaintext = "File-based encryption test data with some content!";

    # Test encrypt_to_file / decrypt_file (CBC)
    {
        my ( $fh, $tmpfile ) = tempfile( UNLINK => 1 );
        close $fh;

        my $bytes =
          Net::SSLeay::encrypt_to_file_with_prepended_iv( 'aes-256-cbc', $key,
            $plaintext, $tmpfile );
        ok( $bytes > 0, 'encrypt_to_file_with_prepended_iv writes bytes' );
        ok(
            -s $tmpfile > length($plaintext),
            'Encrypted file has IV + padding'
        );

        my $decrypted =
          Net::SSLeay::decrypt_file_with_prepended_iv( 'aes-256-cbc', $key,
            $tmpfile );
        is( $decrypted, $plaintext,
            'decrypt_file_with_prepended_iv recovers plaintext' );
    }

    # Test AEAD file functions (GCM)
    {
        my ( $fh, $tmpfile ) = tempfile( UNLINK => 1 );
        close $fh;

        my $aad = "File metadata";
        my $bytes =
          Net::SSLeay::encrypt_aead_to_file_with_prepended_iv( 'aes-256-gcm',
            $key, $plaintext, $tmpfile, $aad );
        ok( $bytes > 0, 'encrypt_aead_to_file writes bytes' );

        my $decrypted =
          Net::SSLeay::decrypt_aead_file_with_prepended_iv( 'aes-256-gcm',
            $key, $tmpfile, $aad );
        is( $decrypted, $plaintext, 'AEAD file roundtrip works' );
    }

    # Test file-to-file streaming (CBC)
    {
        my ( $fh_in, $infile ) = tempfile( UNLINK => 1 );
        print $fh_in $plaintext;
        close $fh_in;

        my ( $fh_out, $outfile ) = tempfile( UNLINK => 1 );
        close $fh_out;

        my ( $fh_dec, $decfile ) = tempfile( UNLINK => 1 );
        close $fh_dec;

        Net::SSLeay::encrypt_file_to_file_with_prepended_iv( 'aes-256-cbc',
            $key, $infile, $outfile );
        ok( -s $outfile > 0, 'encrypt_file_to_file creates output' );

        Net::SSLeay::decrypt_file_to_file_with_prepended_iv( 'aes-256-cbc',
            $key, $outfile, $decfile );
        ok( -s $decfile > 0, 'decrypt_file_to_file creates output' );

        open my $fh, '<:raw', $decfile;
        local $/;
        my $result = <$fh>;
        close $fh;
        is( $result, $plaintext, 'file-to-file streaming roundtrip works' );
    }

    # Test AEAD file-to-file (GCM)
    {
        my ( $fh_in, $infile ) = tempfile( UNLINK => 1 );
        print $fh_in $plaintext;
        close $fh_in;

        my ( $fh_out, $outfile ) = tempfile( UNLINK => 1 );
        close $fh_out;

        my ( $fh_dec, $decfile ) = tempfile( UNLINK => 1 );
        close $fh_dec;

        my $aad = "Streaming AAD";
        Net::SSLeay::encrypt_aead_file_to_file_with_prepended_iv( 'aes-256-gcm',
            $key, $infile, $outfile, $aad );
        ok( -s $outfile > 0, 'AEAD encrypt_file_to_file creates output' );

        Net::SSLeay::decrypt_aead_file_to_file_with_prepended_iv( 'aes-256-gcm',
            $key, $outfile, $decfile, $aad );
        ok( -s $decfile > 0, 'AEAD decrypt_file_to_file creates output' );

        open my $fh, '<:raw', $decfile;
        local $/;
        my $result = <$fh>;
        close $fh;
        is( $result, $plaintext, 'AEAD file-to-file roundtrip works' );
    }
}
