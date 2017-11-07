# include
include_directories(src)
include_directories(src/ccan)
include_directories(src/secp256k1)
include_directories(src/secp256k1/src)
include_directories (${CMAKE_BINARY_DIR})

add_definitions(-DHAVE_CONFIG_H)
add_definitions(-DWALLY_CORE_BUILD)
add_definitions(-DWALLY_EXPORTS)

# source files
set(WALLY_SOURCE_FILES
        src/bip39.c
        src/base58.c
        src/pbkdf2.c
        src/wordlist.c
        src/bip32.c
        src/internal.c
        src/hex.c
        src/aes.c
        # src/ccan/ccan/crypto/sha256/sha256.c
        src/ccan/ccan/crypto/sha512/sha512.c
        # src/ccan/ccan/crypto/ripemd160/ripemd160.c
        src/ccan/ccan/tap/tap.c
        # src/ccan/ccan/str/hex/hex.c
        src/bip38.c
        src/scrypt.c
        src/secp256k1/src/secp256k1.c
        src/sign.c
        src/hmac.c
        src/mnemonic.c
        )

# static lib
add_library( wally
             STATIC
             ${WALLY_SOURCE_FILES}
             )
