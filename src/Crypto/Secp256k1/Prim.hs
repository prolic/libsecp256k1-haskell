{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# OPTIONS_GHC -Wno-dodgy-foreign-imports #-}

-- |
-- Module      : Crypto.Secp256k1.Prim
-- License     : UNLICENSE
-- Maintainer  : Keagan McClelland <keagan.mcclelland@gmail.com>
-- Stability   : experimental
-- Portability : POSIX
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
module Crypto.Secp256k1.Prim where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BU
import Foreign (Bits (..), FunPtr, Ptr, castPtr)
import Foreign.C (
    CInt (..),
    CSize (..),
    CString,
    CUChar,
    CUInt (..),
 )
import GHC.TypeNats (Nat)
import System.IO.Unsafe (unsafePerformIO)


-- | Return type of C Lib functions
type Ret = CInt


type ContextFlags = CUInt
type CompressionFlags = CUInt
type PubkeyFlags = CUInt


-- * Flags


-- ** Flag Types


-- $flagTypes All flags' lower 8 bits indicate what they're for. Do not use directly.


-- | Mask to isolate the type of flags
flagsTypeMask :: CUInt
flagsTypeMask = (1 `shiftL` 8) - 1
{-# DEPRECATED flagsTypeMask "Do not use Flag Types directly" #-}


-- | This bit indicates that the flags are to be used to initialize context
flagsTypeContext :: ContextFlags
flagsTypeContext = 1 `shiftL` 0
{-# DEPRECATED flagsTypeContext "Do not use Flag Types directly" #-}


-- | This bit indicates that the flags are to be used to assess compression
flagsTypeCompression :: CompressionFlags
flagsTypeCompression = 1 `shiftL` 1
{-# DEPRECATED flagsTypeCompression "Do not use Flag Types directly" #-}


-- ** Flag Operations


-- $flagOperations
-- The higher bits contain the actual data. Do not use directly. */


-- | This bit indicates that the context should be initialized for verification
flagsBitContextVerify :: ContextFlags
flagsBitContextVerify = 1 `shiftL` 8
{-# DEPRECATED flagsBitContextVerify "Do not use Flag Operations directly" #-}


-- | This bit indicates that the context should be initialized for signing
flagsBitContextSign :: ContextFlags
flagsBitContextSign = 1 `shiftL` 9
{-# DEPRECATED flagsBitContextSign "Do not use Flag Operations directly" #-}


-- | This bit indicates that the context should be initialized for declassification
flagsBitContextDeclassify :: ContextFlags
flagsBitContextDeclassify = 1 `shiftL` 10
{-# DEPRECATED flagsBitContextDeclassify "Do not use Flag Operations directly" #-}


-- | This bit indicates that things should be serialized in a compressed format
flagsBitCompression :: CompressionFlags
flagsBitCompression = 1 `shiftL` 8
{-# DEPRECATED flagsBitCompression "Do not use Flag Operations directly" #-}


-- ** Composite Flags


-- *** Context Initialization Flags


-- $ciFlags
-- Flags to pass to 'contextCreate', 'contextPreallocatedSize', and 'contextPreallocatedCreate'.


-- | Initialize context for verification
flagsContextVerify :: ContextFlags
flagsContextVerify = flagsTypeContext .|. flagsBitContextVerify


-- | Initialize context for signing
flagsContextSign :: ContextFlags
flagsContextSign = flagsTypeContext .|. flagsBitContextSign


-- | Initialize context for declassifying
flagsContextDeclassify :: ContextFlags
flagsContextDeclassify = flagsTypeContext .|. flagsBitContextDeclassify


-- | Initialize context for primitive operations
flagsContextNone :: ContextFlags
flagsContextNone = flagsTypeContext


-- *** Pubkey Serialization Flags


-- $psFlags
-- Flags to pass to 'ecPubkeySerialize'.


-- | Serialize EC keys compressed
flagsEcCompressed :: CompressionFlags
flagsEcCompressed = flagsTypeCompression .|. flagsBitCompression


-- | Serialize EC keys uncompressed
flagsEcUncompressed :: CompressionFlags
flagsEcUncompressed = flagsTypeCompression


-- *** Pubkey Tags


-- $pkTags
-- Prefix byte used to tag various encoded curvepoints for specific purposes


-- | Pubkey is even
flagsTagPubkeyEven :: PubkeyFlags
flagsTagPubkeyEven = 0x02


-- | Pubkey is odd
flagsTagPubkeyOdd :: PubkeyFlags
flagsTagPubkeyOdd = 0x03


-- | Pubkey is uncompressed
flagsTagPubkeyUncompressed :: PubkeyFlags
flagsTagPubkeyUncompressed = 0x04


-- | Pubkey is even and uncompressed
flagsTagPubkeyHybridEven :: PubkeyFlags
flagsTagPubkeyHybridEven = flagsTagPubkeyEven .|. flagsTagPubkeyUncompressed


-- | Pubkey is odd and uncompressed
flagsTagPubkeyHybridOdd :: PubkeyFlags
flagsTagPubkeyHybridOdd = flagsTagPubkeyOdd .|. flagsTagPubkeyUncompressed


-- * Context Operations


-- | Opaque data structure that holds context information (precomputed tables etc.).
--
--  The purpose of context structures is to cache large precomputed data tables
--  that are expensive to construct, and also to maintain the randomization data
--  for blinding.
--
--  Do not create a new context object for each operation, as construction is
--  far slower than all other API calls (~100 times slower than an ECDSA
--  verification).
--
--  A constructed context can safely be used from multiple threads
--  simultaneously, but API calls that take a non-const pointer to a context
--  need exclusive access to it. In particular this is the case for
--  'contextDestroy', 'contextPreallocatedDestroy',
--  and 'contextRandomize'.
--
--  Regarding randomization, either do it once at creation time (in which case
--  you do not need any locking for the other calls), or use a read-write lock.
type Ctx = Ptr LCtx


-- | Updates the context randomization to protect against side-channel leakage.
--
-- While secp256k1 code is written to be constant-time no matter what secret
-- values are, it's possible that a future compiler may output code which isn't,
-- and also that the CPU may not emit the same radio frequencies or draw the same
-- amount power for all values.
--
-- This function provides a seed which is combined into the blinding value: that
-- blinding value is added before each multiplication (and removed afterwards) so
-- that it does not affect function results, but shields against attacks which
-- rely on any input-dependent behaviour.
--
-- This function has currently an effect only on contexts initialized for signing
-- because randomization is currently used only for signing. However, this is not
-- guaranteed and may change in the future. It is safe to call this function on
-- contexts not initialized for signing; then it will have no effect and return 1.
--
-- You should call this after 'contextCreate' or
-- 'contextClone' (and 'contextPreallocatedCreate' or
-- 'contextClone', resp.), and you may call this repeatedly afterwards.
foreign import capi safe "secp256k1.h secp256k1_context_randomize"
    contextRandomize ::
        -- | __Mutated__: pointer to a context object (cannot be NULL)
        Ctx ->
        -- | __Input__: pointer to a 32-byte random seed (NULL resets to initial state)
        Ptr Seed32 ->
        -- | __Returns__: 1 if randomization successfully updated or nothing to randomize OR 0 if there was an error
        IO Ret


-- ** Allocating


-- | Copy a secp256k1 context object (into dynamically allocated memory).
--
--  This function uses malloc to allocate memory. It is guaranteed that malloc is
--  called at most once for every call of this function. If you need to avoid dynamic
--  memory allocation entirely, see the functions in the [Preallocated](#g:preallocated) section.
foreign import capi safe "secp256k1.h secp256k1_context_clone"
    contextClone ::
        -- | __Input:__ an existing context to copy (cannot be NULL)
        Ctx ->
        -- | __Returns:__ a newly created context object.
        IO Ctx


-- | Create a secp256k1 context object (in dynamically allocated memory).
--
--  This function uses malloc to allocate memory. It is guaranteed that malloc is
--  called at most once for every call of this function. If you need to avoid dynamic
--  memory allocation entirely, see the functions in secp256k1_preallocated.h.
--
--  See also 'contextRandomize'.
foreign import capi safe "secp256k1.h secp256k1_context_create"
    contextCreate ::
        -- | __Input:__ which parts of the context to initialize.
        ContextFlags ->
        -- | __Returns:__ a newly created context object.
        IO Ctx


-- | Destroy a secp256k1 context object (created in dynamically allocated memory).
--
--  The context pointer may not be used afterwards.
--
--  The context to destroy must have been created using 'contextCreate'
--  or 'contextClone'. If the context has instead been created using
--  'contextPreallocatedCreate' or 'contextPreallocatedClone', the
--  behaviour is undefined. In that case, 'contextPreallocatedDestroy' must
--  be used instead.
foreign import capi safe "secp256k1.h secp256k1_context_destroy"
    contextDestroy ::
        -- | an existing context to destroy, constructed using 'contextCreate' or 'contextClone'
        Ctx ->
        IO ()


-- ** Preallocated #preallocated#


-- $preallocated
-- Functions in this secion are intended for settings in which it
-- is not possible or desirable to rely on dynamic memory allocation. It provides
-- functions for creating, cloning, and destroying secp256k1 context objects in a
-- contiguous fixed-size block of memory provided by the caller.
--
-- Context objects created by functions in this section can be used like contexts
-- objects created by functions in secp256k1.h, i.e., they can be passed to any
-- API function that expects a context object (see secp256k1.h for details). The
-- only exception is that context objects created by functions in this module
-- must be destroyed using 'contextPreallocatedDestroy' (in this
-- section) instead of 'contextDestroy'
--
-- It is guaranteed that functions in this module will not call malloc or its
-- friends realloc, calloc, and free.


-- | A simple secp256k1 context object with no precomputed tables. These are useful for
--  type serialization/parsing functions which require a context object to maintain
--  API consistency, but currently do not require expensive precomputations or dynamic
--  allocations.
foreign import ccall unsafe "secp256k1.h secp256k1_context_no_precomp"
    contextNoPrecomp :: Ctx


-- | Copy a secp256k1 context object into caller-provided memory.
--
--  The caller must provide a pointer to a rewritable contiguous block of memory
--  of size at least 'contextPreallocatedSize' (flags) bytes, suitably
--  aligned to hold an object of any type.
--
--  The block of memory is exclusively owned by the created context object during
--  the lifetime of this context object, see the description of
--  'contextPreallocatedCreate' for details.
foreign import capi safe "secp256k1_preallocated.h secp256k1_context_preallocated_clone"
    contextPreallocatedClone ::
        -- | __Mutated:__ an existing context to copy (cannot be NULL)
        Ctx ->
        -- | __Input:__ a pointer to a rewritable contiguous block of memory of size at least
        -- 'contextPreallocatedSize' (flags) bytes, as detailed above (cannot be NULL)
        Ptr (Bytes n) ->
        -- | __Returns:__ a newly created context object.
        IO Ctx


-- | Determine the memory size of a secp256k1 context object to be copied into
--  caller-provided memory.
foreign import capi safe "secp256k1_preallocated.h secp256k1_context_preallocated_clone_size"
    contextPreallocatedCloneSize ::
        -- | __Input:__ an existing context to copy (cannot be NULL)
        Ctx ->
        -- | __Returns:__ the required size of the caller-provided memory block.
        IO CSize


-- | Create a secp256k1 context object in caller-provided memory.
--
--  The caller must provide a pointer to a rewritable contiguous block of memory
--  of size at least 'contextPreallocatedSize' (flags) bytes, suitably
--  aligned to hold an object of any type.
--
--  The block of memory is exclusively owned by the created context object during
--  the lifetime of this context object, which begins with the call to this
--  function and ends when a call to 'contextPreallocatedDestroy'
--  (which destroys the context object again) returns. During the lifetime of the
--  context object, the caller is obligated not to access this block of memory,
--  i.e., the caller may not read or write the memory, e.g., by copying the memory
--  contents to a different location or trying to create a second context object
--  in the memory. In simpler words, the prealloc pointer (or any pointer derived
--  from it) should not be used during the lifetime of the context object.
--
--  See also 'contextRandomize'
--  and 'contextPreallocatedDestroy'.
foreign import capi safe "secp256k1_preallocated.h secp256k1_context_preallocated_create"
    contextPreallocatedCreate ::
        -- | __Mutated:__ a pointer to a rewritable contiguous block of memory of
        -- size at least 'contextPreallocatedSize' (flags)
        -- bytes, as detailed above (cannot be NULL)
        Ptr (Bytes n) ->
        -- | __Input:__ which parts of the context to initialize.
        CUInt ->
        -- | __Returns:__ a newly created context object.
        IO Ctx


-- | Destroy a secp256k1 context object that has been created in
--  caller-provided memory.
--
--  The context pointer may not be used afterwards.
--
--  The context to destroy must have been created using
--  'contextPreallocatedCreate' or 'contextPreallocatedClone'.
--  If the context has instead been created using 'contextCreate' or
--  'contextClone', the behaviour is undefined. In that case,
--  'contextDestroy' must be used instead.
--
--  If required, it is the responsibility of the caller to deallocate the block
--  of memory properly after this function returns, e.g., by calling free on the
--  preallocated pointer given to 'contextPreallocatedCreate' or
--  'contextPreallocatedClone'.
foreign import capi safe "secp256k1_preallocated.h secp256k1_context_preallocated_destroy"
    contextPreallocatedDestroy ::
        -- | an existing context to destroy, constructed using 'contextPreallocatedCreate' or
        -- 'contextPreallocatedClone' (cannot be NULL)
        Ctx ->
        IO ()


-- | Determine the memory size of a secp256k1 context object to be created in
--  caller-provided memory.
--
--  The purpose of this function is to determine how much memory must be provided
--  to 'contextPreallocatedCreate'.
foreign import capi safe "secp256k1_preallocated.h secp256k1_context_preallocated_size"
    contextPreallocatedSize ::
        -- | __Input:__ which parts of the context to initialize.
        CUInt ->
        -- | __Returns:__ the required size of the caller-provided memory block
        IO CSize


-- ** Callbacks


-- | Set a callback function to be called when an internal consistency check
--  fails. The default is crashing.
--
--  This can only trigger in case of a hardware failure, miscompilation,
--  memory corruption, serious bug in the library, or other error would can
--  otherwise result in undefined behaviour. It will not trigger due to mere
--  incorrect usage of the API (see 'contextSetIllegalCallback'
--  for that). After this callback returns, anything may happen, including
--  crashing.
--
--  See also 'contextSetIllegalCallback'.
foreign import capi safe "secp256k1.h secp256k1_context_set_error_callback"
    contextSetErrorCallback ::
        -- | an existing context object (cannot be NULL)
        Ctx ->
        -- | __Input:__ a pointer to a function to call when an internal error occurs,
        -- taking a message and an opaque pointer (NULL restores the
        -- default handler, see contextSetIllegalCallback
        -- for details).
        FunPtr (CString -> Ptr a -> IO ()) ->
        -- | __Input:__ the opaque pointer to pass to fun above.
        Ptr a ->
        IO ()


-- | Set a callback function to be called when an illegal argument is passed to
--  an API call. It will only trigger for violations that are mentioned
--  explicitly in the header.
--
--  The philosophy is that these shouldn't be dealt with through a
--  specific return value, as calling code should not have branches to deal with
--  the case that this code itself is broken.
--
--  On the other hand, during debug stage, one would want to be informed about
--  such mistakes, and the default (crashing) may be inadvisable.
--  When this callback is triggered, the API function called is guaranteed not
--  to cause a crash, though its return value and output arguments are
--  undefined.
--
--  When this function has not been called (or called with fn==NULL), then the
--  default handler will be used. The library provides a default handler which
--  writes the message to stderr and calls abort. This default handler can be
--  replaced at link time if the preprocessor macro
--  USE_EXTERNAL_DEFAULT_CALLBACKS is defined, which is the case if the build
--  has been configured with @--enable-external-default-callbacks@. Then the
--  following two symbols must be provided to link against:
--
--   - @void secp256k1_default_illegal_callback_fn(const char* message, void* data);@
--   - @void secp256k1_default_error_callback_fn(const char* message, void* data);@
--
--  The library can call these default handlers even before a proper callback data
--  pointer could have been set using 'contextSetIllegalCallback' or
--  'contextSetErrorCallback', e.g., when the creation of a context
--  fails. In this case, the corresponding default handler will be called with
--  the data pointer argument set to NULL.
--
--  See also 'contextSetErrorCallback'.
foreign import capi safe "secp256k1.h secp256k1_context_set_illegal_callback"
    contextSetIllegalCallback ::
        -- | an existing context object (cannot be NULL)
        Ctx ->
        -- | __Input:__ a pointer to a function to call when an illegal argument is passed to the API, taking a message
        -- and an opaque pointer.  (NULL restores the default handler.)
        FunPtr (CString -> Ptr a -> IO ()) ->
        -- | __Input:__ the opaque pointer to pass to fun above.
        Ptr a ->
        IO ()


-- * ECDH Operations


-- | Compute an EC Diffie-Hellman secret in constant time
foreign import capi safe "secp256k1.h secp256k1_ecdh"
    ecdh ::
        -- | pointer to a context object (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to an array to be filled by hashfp
        Ptr (Bytes n) ->
        -- | __Input:__ a pointer to a 'Pubkey64' containing an initialized public key
        Ptr Pubkey64 ->
        -- | __Input:__ a 32-byte scalar with which to multiply the point
        Ptr Seckey32 ->
        -- | __Input:__ pointer to a hash function. If NULL, 'ecdhHashFunctionSha256' is used
        -- (in which case, 32 bytes will be written to output)
        FunPtr (EcdhHashFun a) ->
        -- | __Input:__ arbitrary data pointer that is passed through to hashfp
        Ptr a ->
        -- | __Returns:__ 1 if exponentiation was successful, 0 if scalar was invalid (zero or overflow)
        -- or hashfp returned 0
        IO Ret


-- | A default ECDH hash function (currently equal to 'ecdhHashFunctionSha256').
-- Populates the output parameter with 32 bytes.
foreign import capi safe "secp256k1_ecdh.h value secp256k1_ecdh_hash_function_default"
    ecdhHashFunctionDefault :: FunPtr (EcdhHashFun a)


-- | An implementation of SHA256 hash function that applies to compressed public key.
-- Populates the output parameter with 32 bytes.
foreign import capi safe "secp256k1_ecdh.h value secp256k1_ecdh_hash_function_sha256"
    ecdhHashFunctionSha256 :: FunPtr (EcdhHashFun a)


-- * ECDSA


-- | A default safe nonce generation function (currently equal to 'nonceFunctionRfc6979').
foreign import capi safe "secp256k1.h value secp256k1_nonce_function_default"
    nonceFunctionDefault :: FunPtr (NonceFun a)


-- | An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
-- If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
-- extra entropy.
foreign import capi safe "secp256k1.h value secp256k1_nonce_function_rfc6979"
    nonceFunctionRfc6979 :: FunPtr (NonceFun a)


-- ** Recoverable


-- | Recover an ECDSA public key from a signature.
foreign import capi safe "secp256k1_recovery.h secp256k1_ecdsa_recover"
    ecdsaRecover ::
        -- | pointer to a context object, initialized for verification (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to the recovered public key (cannot be NULL)
        Ptr Pubkey64 ->
        -- | __Input:__ pointer to initialized signature that supports pubkey recovery (cannot be NULL)
        Ptr RecSig65 ->
        -- | __Input:__ the 32-byte message hash assumed to be signed (cannot be NULL)
        Ptr Msg32 ->
        -- | __Returns:__ 1: public key successfully recovered (which guarantees a correct signature).
        -- 0: otherwise.
        IO Ret


-- | Convert a recoverable signature into a normal signature.
foreign import capi safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_convert"
    ecdsaRecoverableSignatureConvert ::
        -- | a secp256k1 context object
        Ctx ->
        -- | __Output:__ pointer to a normal signature (cannot be NULL).
        Ptr Sig64 ->
        -- | __Input:__ a pointer to a recoverable signature (cannot be NULL).
        Ptr RecSig65 ->
        -- | __Returns:__ 1
        IO Ret


-- | Parse a compact ECDSA signature (64 bytes + recovery id).
foreign import capi safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_parse_compact"
    ecdsaRecoverableSignatureParseCompact ::
        -- | a secp256k1 context object
        Ctx ->
        -- | __Output:__ a pointer to a signature object
        Ptr RecSig65 ->
        -- | __Input:__ a pointer to a 64-byte compact signature
        Ptr (Bytes 64) ->
        -- | __Input:__ the recovery id (0, 1, 2 or 3)
        CInt ->
        -- | __Returns:__ 1 when the signature could be parsed, 0 otherwise
        IO Ret


-- | Serialize an ECDSA signature in compact format (64 bytes + recovery id).
foreign import capi safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_serialize_compact"
    ecdsaRecoverableSignatureSerializeCompact ::
        -- | a secp256k1 context object
        Ctx ->
        -- | __Output:__ a pointer to a 64-byte array of the compact signature (cannot be NULL)
        Ptr (Bytes 64) ->
        -- | __Output:__ a pointer to an integer to hold the recovery id (can be NULL).
        Ptr CInt ->
        -- | __Input:__ a pointer to an initialized signature object (cannot be NULL)
        Ptr RecSig65 ->
        -- | __Returns:__ 1
        IO Ret


-- | Create a recoverable ECDSA signature.
foreign import capi safe "secp256k1_recovery.h secp256k1_ecdsa_sign_recoverable"
    ecdsaSignRecoverable ::
        -- | pointer to a context object, initialized for signing (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to an array where the signature will be placed (cannot be NULL)
        Ptr RecSig65 ->
        -- | __Input:__ the 32-byte message hash being signed (cannot be NULL)
        Ptr Msg32 ->
        -- | __Input:__ pointer to a 32-byte secret key (cannot be NULL)
        Ptr Seckey32 ->
        -- | __Input:__ pointer to a nonce generation function. If NULL, 'nonceFunctionDefault' is used
        FunPtr (NonceFun a) ->
        -- | __Input:__ pointer to arbitrary data used by the nonce generation function (can be NULL)
        Ptr a ->
        -- | __Returns:__ 1: signature created
        -- 0: the nonce generation function failed, or the secret key was invalid.
        IO Ret


-- ** Non-Recoverable


-- | Create an ECDSA signature.
--
-- The created signature is always in lower-S form. See
-- 'ecdsaSignatureNormalize' for more details.
foreign import capi safe "secp256k1.h secp256k1_ecdsa_sign"
    ecdsaSign ::
        -- | pointer to a context object, initialized for signing (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to an array where the signature will be placed (cannot be NULL)
        Ptr Sig64 ->
        -- | __Input:__ the 32-byte message hash being signed (cannot be NULL)
        Ptr Msg32 ->
        -- | __Input:__ pointer to a 32-byte secret key (cannot be NULL)
        Ptr Seckey32 ->
        -- | __Input:__ pointer to a nonce generation function. If NULL, 'nonceFunctionDefault' is used
        FunPtr (NonceFun a) ->
        -- | __Input:__ pointer to arbitrary data used by the nonce generation function (can be NULL)
        Ptr a ->
        -- | __Returns:__ 1: signature created
        -- 0: the nonce generation function failed, or the secret key was invalid.
        IO Ret


-- | Verify an ECDSA signature.
--
-- To avoid accepting malleable signatures, only ECDSA signatures in lower-S
-- form are accepted.
--
-- If you need to accept ECDSA signatures from sources that do not obey this
-- rule, apply 'ecdsaSignatureNormalize' to the signature prior to
-- validation, but be aware that doing so results in malleable signatures.
--
-- For details, see the comments for that function.
foreign import capi safe "secp256k1.h secp256k1_ecdsa_verify"
    ecdsaVerify ::
        -- | a secp256k1 context object, initialized for verification.
        Ctx ->
        -- | __Input:__ the signature being verified (cannot be NULL)
        Ptr Sig64 ->
        -- | __Input:__ the 32-byte message hash being verified (cannot be NULL).
        -- The verifier must make sure to apply a cryptographic
        -- hash function to the message by itself and not accept an
        -- msghash32 value directly. Otherwise, it would be easy to
        -- create a "valid" signature without knowledge of the
        -- secret key. See also
        -- https://bitcoin.stackexchange.com/a/81116/35586 for more
        -- background on this topic.
        Ptr Msg32 ->
        -- | __Input:__ pointer to an initialized public key to verify with (cannot be NULL)
        Ptr Pubkey64 ->
        -- | __Returns:__ 1 if correct signature, 0 if incorrect or unparseable signature
        IO Ret


-- | Convert a signature to a normalized lower-S form.
--
--  With ECDSA a third-party can forge a second distinct signature of the same
--  message, given a single initial signature, but without knowing the key. This
--  is done by negating the S value modulo the order of the curve, "flipping"
--  the sign of the random point R which is not included in the signature.
--
--  Forgery of the same message isn't universally problematic, but in systems
--  where message malleability or uniqueness of signatures is important this can
--  cause issues. This forgery can be blocked by all verifiers forcing signers
--  to use a normalized form.
--
--  The lower-S form reduces the size of signatures slightly on average when
--  variable length encodings (such as DER) are used and is cheap to verify,
--  making it a good choice. Security of always using lower-S is assured because
--  anyone can trivially modify a signature after the fact to enforce this
--  property anyway.
--
--  The lower S value is always between 0x1 and
--  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
--  inclusive.
--
--  No other forms of ECDSA malleability are known and none seem likely, but
--  there is no formal proof that ECDSA, even with this additional restriction,
--  is free of other malleability. Commonly used serialization schemes will also
--  accept various non-unique encodings, so care should be taken when this
--  property is required for an application.
--
--  The 'ecdsaSign' function will by default create signatures in the
--  lower-S form, and 'ecdsaVerify' will not accept others. In case
--  signatures come from a system that cannot enforce this property,
--  'ecdsaSignatureNormalize' must be called before verification.
foreign import capi safe "secp256k1.h secp256k1_ecdsa_signature_normalize"
    ecdsaSignatureNormalize ::
        -- | a secp256k1 context object
        Ctx ->
        -- | __Output:__ a pointer to a signature to fill with the normalized form,
        -- or copy if the input was already normalized. (can be NULL if
        -- you're only interested in whether the input was already
        -- normalized).
        Ptr Sig64 ->
        -- | __Input:__ a pointer to a signature to check/normalize (cannot be NULL,
        -- can be identical to sigout)
        Ptr Sig64 ->
        -- | __Returns:__ 1 if sigin was not normalized, 0 if it already was.
        IO Ret


-- *** Parsing / Serialization


-- | Parse an ECDSA signature in compact (64 bytes) format.
--
--  The signature must consist of a 32-byte big endian R value, followed by a
--  32-byte big endian S value. If R or S fall outside of [0..order-1], the
--  encoding is invalid. R and S with value 0 are allowed in the encoding.
--
--  After the call, sig will always be initialized. If parsing failed or R or
--  S are zero, the resulting sig value is guaranteed to fail validation for any
--  message and public key.
foreign import capi safe "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
    ecdsaSignatureParseCompact ::
        -- | __Input:__ a secp256k1 context object
        Ctx ->
        -- | __Output:__ a pointer to a signature object
        Ptr Sig64 ->
        -- | __Input:__ a pointer to the 64-byte array to parse
        Ptr (Bytes 64) ->
        -- | __Returns:__ 1 when the signature could be parsed, 0 otherwise.
        IO Ret


-- | Parse a DER ECDSA signature.
--
--  This function will accept any valid DER encoded signature, even if the
--  encoded numbers are out of range.
--
--  After the call, sig will always be initialized. If parsing failed or the
--  encoded numbers are out of range, signature validation with it is
--  guaranteed to fail for every message and public key.
foreign import capi safe "secp256k1.h secp256k1_ecdsa_signature_parse_der"
    ecdsaSignatureParseDer ::
        -- | __Input:__ a secp256k1 context object
        Ctx ->
        -- | __Output:__ a pointer to a signature object
        Ptr Sig64 ->
        -- | __Input:__ a pointer to the signature to be parsed
        Ptr (Bytes n) ->
        -- | __Input:__ the length of the array pointed to be input
        CSize ->
        -- | __Returns:__ 1 when the signature could be parsed, 0 otherwise.
        IO Ret


-- | Serialize an ECDSA signature in compact (64 byte) format.
--
--  See 'ecdsaSignatureParseCompact' for details about the encoding.
foreign import capi safe "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
    ecdsaSignatureSerializeCompact ::
        -- | __Input:__ a secp256k1 context object
        Ctx ->
        -- | __Output:__ a pointer to a 64-byte array to store the compact serialization
        Ptr (Bytes 64) ->
        -- | __Input:__ a pointer to an initialized signature object
        Ptr Sig64 ->
        -- | __Returns:__ 1
        IO Ret


-- | Serialize an ECDSA signature in DER format.
foreign import capi safe "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
    ecdsaSignatureSerializeDer ::
        -- | __Input:__ a secp256k1 context object
        Ctx ->
        -- | __Output:__ a pointer to an array to store the DER serialization
        Ptr (Bytes n) ->
        -- | __Mutates:__ a pointer to a length integer. Initially, this integer
        -- should be set to the length of output. After the call
        -- it will be set to the length of the serialization (even
        -- if 0 was returned).
        Ptr CSize ->
        -- | __Input:__ a pointer to an initialized signature object
        Ptr Sig64 ->
        -- | __Returns:__ 1 if enough space was available to serialize, 0 otherwise
        IO Ret


-- * Pubkey Operations


-- | Compare two public keys using lexicographic (of compressed serialization) order
foreign import capi safe "secp256k1.h secp256k1_ec_pubkey_cmp"
    ecPubkeyCmp ::
        -- | __Input:__ a secp256k1 context object.
        Ctx ->
        -- | __Input:__ first public key to compare
        Ptr Pubkey64 ->
        -- | __Input:__ second public key to compare
        Ptr Pubkey64 ->
        -- __Returns:__ <0 if the first public key is less than the second
        -- >0 if the first public key is greater than the second
        -- 0 if the two public keys are equal
        IO Ret


-- | Add a number of public keys together.
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_combine"
    ecPubkeyCombine ::
        -- | pointer to a context object
        Ctx ->
        -- | __Output:__ pointer to a public key object for placing the resulting public key (cannot be NULL)
        Ptr Pubkey64 ->
        -- | __Input:__ pointer to array of pointers to public keys (cannot be NULL)
        Ptr (Ptr Pubkey64) ->
        -- | __Input:__ the number of public keys to add together (must be at least 1)
        CInt ->
        -- | __Returns:__ 1: the sum of the public keys is valid.
        -- 0: the sum of the public keys is not valid.
        IO Ret


-- | Compute the public key for a secret key.
foreign import capi safe "secp256k1.h secp256k1_ec_pubkey_create"
    ecPubkeyCreate ::
        -- | pointer to a context object, initialized for signing (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to the created public key (cannot be NULL)
        Ptr Pubkey64 ->
        -- | __Input:__ pointer to a 32-byte secret key (cannot be NULL)
        Ptr Seckey32 ->
        -- | __Returns:__ 1: secret was valid, public key stores
        -- 0: secret was invalid, try again
        IO Ret


-- | Negates a public key in place.
foreign import capi safe "secp256k1.h secp256k1_ec_pubkey_negate"
    ecPubkeyNegate ::
        -- | pointer to a context object
        Ctx ->
        -- | __Mutates:__ pointer to the public key to be negated (cannot be NULL)
        Ptr Pubkey64 ->
        -- | __Returns:__ 1 always
        IO Ret


-- | Parse a variable-length public key into the pubkey object.
--
--  This function supports parsing compressed (33 bytes, header byte 0x02 or
--  0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes, header
--  byte 0x06 or 0x07) format public keys.
foreign import capi safe "secp256k1.h secp256k1_ec_pubkey_parse"
    ecPubkeyParse ::
        -- | a secp256k1 context object.
        Ctx ->
        -- | __Output:__ pointer to a pubkey object. If 1 is returned, it is set to a
        -- parsed version of input. If not, its value is undefined.
        Ptr Pubkey64 ->
        -- | __Input:__ pointer to a serialized public key
        Ptr (Bytes n) ->
        -- | __Input:__ length of the array pointed to by input
        CSize ->
        -- | __Returns:__ 1 if the public key was fully valid.
        -- 0 if the public key could not be parsed or is invalid.
        IO Ret


-- | Serialize a pubkey object into a serialized byte sequence.
foreign import capi safe "secp256k1.h secp256k1_ec_pubkey_serialize"
    ecPubkeySerialize ::
        -- | a secp256k1 context object.
        Ctx ->
        -- | __Output:__ a pointer to a 65-byte (if compressed==0) or 33-byte (if
        -- compressed==1) byte array to place the serialized key in.
        Ptr (Bytes n) ->
        -- | __Mutates:__ a pointer to an integer which is initially set to the
        -- size of output, and is overwritten with the written size.
        Ptr CSize ->
        -- | __Input:__ a pointer to a 'Pubkey64' containing an
        -- initialized public key.
        Ptr Pubkey64 ->
        -- | __Input:__ 'compressed' if serialization should be in
        -- compressed format, otherwise 'uncompressed'.
        CompressionFlags ->
        --  Returns: 1 always.
        IO Ret


-- | Tweak a public key by adding tweak times the generator to it.
foreign import capi unsafe "secp256k1.h secp256k1_ec_pubkey_tweak_add"
    ecPubkeyTweakAdd ::
        -- | pointer to a context object initialized for validation (cannot be NULL).
        Ctx ->
        -- | __Mutates:__ pointer to a public key object. pubkey will be set to an
        -- invalid value if this function returns 0 (cannot be NULL).
        Ptr Pubkey64 ->
        -- | __Input:__ pointer to a 32-byte tweak. If the tweak is invalid according to
        -- 'ecSeckeyVerify', this function returns 0. For
        -- uniformly random 32-byte arrays the chance of being invalid
        -- is negligible (around 1 in 2^128) (cannot be NULL).
        Ptr Tweak32 ->
        -- | __Returns:__ 0 if the arguments are invalid or the resulting public key would be
        -- invalid (only when the tweak is the negation of the corresponding
        -- secret key). 1 otherwise.
        IO Ret


-- | Tweak a public key by multiplying it by a tweak value.
foreign import capi safe "secp256k1.h secp256k1_ec_pubkey_tweak_mul"
    ecPubkeyTweakMul ::
        -- | pointer to a context object initialized for validation (cannot be NULL).
        Ctx ->
        -- | __Mutates:__ pointer to a public key object. pubkey will be set to an
        -- invalid value if this function returns 0 (cannot be NULL).
        Ptr Pubkey64 ->
        -- | __Input:__ pointer to a 32-byte tweak. If the tweak is invalid according to
        -- 'ecSeckeyVerify', this function returns 0. For
        -- uniformly random 32-byte arrays the chance of being invalid
        -- is negligible (around 1 in 2^128) (cannot be NULL).
        Ptr Tweak32 ->
        -- | __Returns:__ 0 if the arguments are invalid. 1 otherwise.
        IO Ret


-- | Negates a secret key in place.
foreign import capi safe "secp256k1.h secp256k1_ec_seckey_negate"
    ecSeckeyNegate ::
        -- | pointer to a context object
        Ctx ->
        -- | __Mutates:__ pointer to the 32-byte secret key to be negated. If the
        -- secret key is invalid according to
        -- ecSeckeyVerify, this function returns 0 and
        -- seckey will be set to some unspecified value. (cannot be
        -- NULL)
        Ptr Seckey32 ->
        -- | __Returns:__ 0 if the given secret key is invalid according to
        -- 'ecSeckeyVerify'. 1 otherwise
        IO Ret


-- | Tweak a secret key by adding tweak to it.
foreign import capi safe "secp256k1.h secp256k1_ec_seckey_tweak_add"
    ecSeckeyTweakAdd ::
        -- | pointer to a context object (cannot be NULL).
        Ctx ->
        -- | __Mutates:__ pointer to a 32-byte secret key. If the secret key is
        -- invalid according to 'ecSeckeyVerify', this
        -- function returns 0. seckey will be set to some unspecified
        -- value if this function returns 0. (cannot be NULL)
        Ptr Seckey32 ->
        -- | __Input:__ pointer to a 32-byte tweak. If the tweak is invalid according to
        -- ecSeckeyVerify, this function returns 0. For
        -- uniformly random 32-byte arrays the chance of being invalid
        -- is negligible (around 1 in 2^128) (cannot be NULL).
        Ptr Tweak32 ->
        -- | __Returns:__ 0 if the arguments are invalid or the resulting secret key would be
        -- invalid (only when the tweak is the negation of the secret key). 1
        -- otherwise.
        IO Ret


-- | Tweak a secret key by multiplying it by a tweak.
foreign import capi safe "secp256k1.h secp256k1_ec_seckey_tweak_mul"
    ecSeckeyTweakMul ::
        -- | pointer to a context object (cannot be NULL).
        Ctx ->
        -- __Mutates:__ pointer to a 32-byte secret key. If the secret key is
        -- invalid according to 'ecSeckeyVerify', this
        -- function returns 0. seckey will be set to some unspecified
        -- value if this function returns 0. (cannot be NULL)
        Ptr Seckey32 ->
        -- __Input:__ pointer to a 32-byte tweak. If the tweak is invalid according to
        -- 'ecSeckeyVerify', this function returns 0. For
        -- uniformly random 32-byte arrays the chance of being invalid
        -- is negligible (around 1 in 2^128) (cannot be NULL).
        Ptr Tweak32 ->
        -- __Returns:__ 0 if the arguments are invalid. 1 otherwise.
        IO Ret


-- | Verify an ECDSA secret key.
--
--  A secret key is valid if it is not 0 and less than the secp256k1 curve order
--  when interpreted as an integer (most significant byte first). The
--  probability of choosing a 32-byte string uniformly at random which is an
--  invalid secret key is negligible.
foreign import capi safe "secp256k1.h secp256k1_ec_seckey_verify"
    ecSecKeyVerify ::
        -- | pointer to a context object (cannot be NULL)
        Ctx ->
        -- | __Input:__ pointer to a 32-byte secret key (cannot be NULL)
        Ptr Seckey32 ->
        -- | __Returns:__ 1 if secret key is valid, 0 if secret key is invalid
        IO Ret


-- | Compute the keypair for a secret key.
foreign import capi safe "secp256k1_extrakeys.h secp256k1_keypair_create"
    keypairCreate ::
        -- | pointer to a context object, initialized for signing (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to the created keypair (cannot be NULL)
        Ptr Keypair96 ->
        -- | __Input:__ pointer to a 32-byte secret key (cannot be NULL)
        Ptr Seckey32 ->
        -- | __Returns:__ 1: secret was valid, keypair is ready to use
        -- 0: secret was invalid, try again with a different secret
        IO Ret


-- | Get the public key from a keypair.
foreign import capi safe "secp256k1_extrakeys.h secp256k1_keypair_pub"
    keypairPub ::
        -- | pointer to a context object (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to a pubkey object. If 1 is returned, it is set to
        -- the keypair public key. If not, it's set to an invalid value.
        -- (cannot be NULL)
        Ptr Pubkey64 ->
        -- | __Input:__ pointer to a keypair (cannot be NULL)
        Ptr Keypair96 ->
        -- | __Returns:__ 0 if the arguments are invalid. 1 otherwise.
        IO Ret


-- | Get the secret key from a keypair.
foreign import capi safe "secp256k1_extrakeys.h secp256k1_keypair_sec"
    keypairSec ::
        -- | pointer to a context object (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to a 32-byte buffer for the secret key (cannot be NULL)
        Ptr Seckey32 ->
        -- | __Input:__ pointer to a keypair (cannot be NULL)
        Ptr Keypair96 ->
        -- | __Returns:__ 0 if the arguments are invalid. 1 otherwise.
        IO Ret


-- | Get the x-only public key from a keypair.
--
--  This is the same as calling 'keypairPub' and then
--  'xonlyPubkeyFromPubkey'.
foreign import capi safe "secp256k1_extrakeys.h secp256k1_keypair_xonly_pub"
    keypairXonlyPub ::
        -- | pointer to a context object (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to an xonly_pubkey object. If 1 is returned, it is set
        -- to the keypair public key after converting it to an
        -- xonly_pubkey. If not, it's set to an invalid value (cannot be
        -- NULL).
        Ptr XonlyPubkey64 ->
        --    pk_parity: pointer to an integer that will be set to the pk_parity
        --               argument of 'xonlyPubkeyFromPubkey' (can be NULL).
        Ptr CInt ->
        --  In: keypair: pointer to a keypair (cannot be NULL)
        Ptr Keypair96 ->
        --  Returns: 0 if the arguments are invalid. 1 otherwise.
        IO Ret


-- | Tweak a keypair by adding tweak32 to the secret key and updating the public
--  key accordingly.
--
--  Calling this function and then 'keypairPub' results in the same
--  public key as calling 'keypairXonlyPub' and then
--  'xonlyPubkeyTweakAdd'.
foreign import capi safe "secp256k1_extrakeys.h secp256k1_keypair_xonly_tweak_add"
    keypairXonlyTweakAdd ::
        -- | pointer to a context object initialized for verification
        -- (cannot be NULL)
        Ctx ->
        -- | __Mutates:__ pointer to a keypair to apply the tweak to. Will be set to
        -- an invalid value if this function returns 0 (cannot be NULL).
        Ptr Keypair96 ->
        -- | __Input:__ pointer to a 32-byte tweak. If the tweak is invalid according
        -- to 'ecSeckeyVerify', this function returns 0. For uniformly random 32-byte
        -- arrays the chance of being invalid is negligible (around 1 in 2^128) (cannot be NULL).
        Ptr Tweak32 ->
        -- | __Returns:__ 0 if the arguments are invalid or the resulting keypair would be
        -- invalid (only when the tweak is the negation of the keypair's secret key). 1 otherwise.
        IO Ret


-- * Schnorr Operations


-- | An implementation of the nonce generation function as defined in Bitcoin
--  Improvement Proposal 340 "Schnorr Signatures for secp256k1"
--  (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
--
--  If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
--  auxiliary random data as defined in BIP-340. If the data pointer is NULL,
--  the nonce derivation procedure follows BIP-340 by setting the auxiliary
--  random data to zero. The algo argument must be non-NULL, otherwise the
--  function will fail and return 0. The hash will be tagged with algo.
--  Therefore, to create BIP-340 compliant signatures, algo must be set to
--  "BIP0340/nonce" and algolen to 13.
foreign import capi safe "secp256k1_schnorrsig.h value secp256k1_nonce_function_bip340"
    nonceFunctionBip340 :: FunPtr (NonceFunHardened a)


-- | Create a Schnorr signature.
--
--  Does _not_ strictly follow BIP-340 because it does not verify the resulting
--  signature. Instead, you can manually use 'schnorrsigVerify' and
--  abort if it fails.
--
--  This function only signs 32-byte messages. If you have messages of a
--  different size (or the same size but without a context-specific tag
--  prefix), it is recommended to create a 32-byte message hash with
--  'taggedSha256' and then sign the hash. Tagged hashing allows
--  providing an context-specific tag for domain separation. This prevents
--  signatures from being valid in multiple contexts by accident.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign"
    schnorrsigSign ::
        -- | pointer to a context object, initialized for signing (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to a 64-byte array to store the serialized signature (cannot be NULL)
        Ptr Sig64 ->
        -- | __Input:__ the 32-byte message being signed (cannot be NULL)
        Ptr Msg32 ->
        -- | __Input:__ pointer to an initialized keypair (cannot be NULL)
        Ptr Keypair96 ->
        -- | __Input:__ 32 bytes of fresh randomness. While recommended to provide
        -- this, it is only supplemental to security and can be NULL. See
        -- BIP-340 "Default Signing" for a full explanation of this
        -- argument and for guidance if randomness is expensive.
        Ptr (Bytes 32) ->
        -- | __Returns:__ 1 on success, 0 on failure.
        IO Ret


-- | Create a Schnorr signature with a more flexible API.
--
--  Same arguments as 'schnorrsigSign' except that it allows signing
--  variable length messages and accepts a pointer to an extraparams object that
--  allows customizing signing by passing additional arguments.
--
--  Creates the same signatures as schnorrsig_sign if msglen is 32 and the
--  extraparams.ndata is the same as aux_rand32.
foreign import capi unsafe "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign_custom"
    schnorrsigSignCustom ::
        -- | pointer to a context object, initialized for signing (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to a 64-byte array to store the serialized signature (cannot be NULL)
        Ptr Sig64 ->
        -- | __Input:__ the message being signed. Can only be NULL if msglen is 0.
        Ptr (Bytes n) ->
        -- | __Input:__ length of the message
        CSize ->
        -- | __Input:__ pointer to an initialized keypair (cannot be NULL)
        Ptr Keypair96 ->
        -- | __Input:__ pointer to a extraparams object (can be NULL)
        Ptr SchnorrExtra ->
        -- | __Returns:__ 1 on success, 0 on failure.
        IO Ret


-- | Verify a Schnorr signature.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_schnorrsig_verify"
    schnorrsigSignVerify ::
        -- | a secp256k1 context object, initialized for verification.
        Ctx ->
        -- | __Input:__ pointer to the 64-byte signature to verify (cannot be NULL)
        Ptr Sig64 ->
        -- | __Input:__ the message being verified. Can only be NULL if msglen is 0.
        Ptr (Bytes n) ->
        -- | __Input:__ length of the message
        CSize ->
        -- | __Input:__ pointer to an x-only public key to verify with (cannot be NULL)
        Ptr XonlyPubkey64 ->
        -- | __Returns:__ 1 on correct signature, 0 on incorrect signature
        IO Ret


-- | Compute a tagged hash as defined in BIP-340.
--
--  This is useful for creating a message hash and achieving domain separation
--  through an application-specific tag. This function returns
--  SHA256(SHA256(tag)||SHA256(tag)||msg). Therefore, tagged hash
--  implementations optimized for a specific tag can precompute the SHA256 state
--  after hashing the tag hashes.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_tagged_sha256"
    taggedSha256 ::
        -- | pointer to a context object
        Ctx ->
        -- | __Output:__ pointer to a 32-byte array to store the resulting hash
        Ptr (Bytes 32) ->
        -- | __Input:__ pointer to an array containing the tag
        Ptr (Bytes n) ->
        -- | __Input:__ length of the tag array
        CSize ->
        -- | __Input:__ pointer to an array containing the message
        Ptr (Bytes n) ->
        -- | __Input:__ length of the message array
        CSize ->
        -- | __Returns:__ 0 if the arguments are invalid and 1 otherwise.
        IO Ret


-- * XOnly Operations


-- | Compare two x-only public keys using lexicographic order
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_xonly_pubkey_cmp"
    xonlyPubkeyCmp ::
        -- | a secp256k1 context object.
        Ctx ->
        -- | __Input:__ first public key to compare
        Ptr XonlyPubkey64 ->
        -- | __Input:__ second public key to compare
        Ptr XonlyPubkey64 ->
        -- | __Returns:__ <0 if the first public key is less than the second
        -- >0 if the first public key is greater than the second
        -- 0 if the two public keys are equal
        IO Ret


-- | Converts a 'Pubkey64' into a 'XonlyPubkey64'.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_xonly_pubkey_from_pubkey"
    xonlyPubkeyFromPubkey ::
        -- | pointer to a context object (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to an x-only public key object for placing the
        -- converted public key (cannot be NULL)
        Ptr XonlyPubkey64 ->
        -- __Output:__ pointer to an integer that will be set to 1 if the point
        -- encoded by xonly_pubkey is the negation of the pubkey and
        -- set to 0 otherwise. (can be NULL)
        Ptr CInt ->
        -- | __Input:__ pubkey: pointer to a public key that is converted (cannot be NULL)
        Ptr Pubkey64 ->
        -- | __Returns:__ 1 if the public key was successfully converted
        -- 0 otherwise
        IO Ret


-- | Parse a 32-byte sequence into a 'XonlyPubkey64' object.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_xonly_pubkey_parse"
    xonlyPubkeyParse ::
        -- | a secp256k1 context object (cannot be NULL).
        Ctx ->
        -- | __Output:__ pointer to a pubkey object. If 1 is returned, it is set to a
        -- parsed version of input. If not, it's set to an invalid value.
        -- (cannot be NULL).
        Ptr XonlyPubkey64 ->
        -- | __Input:__ pointer to a serialized xonly_pubkey (cannot be NULL)
        Ptr (Bytes 32) ->
        -- | __Returns:__ 1 if the public key was fully valid.
        -- 0 if the public key could not be parsed or is invalid.
        IO Ret


-- | Serialize an 'XonlyPubkey64' object into a 32-byte sequence.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_xonly_pubkey_serialize"
    xonlyPubkeySerialize ::
        -- | a secp256k1 context object (cannot be NULL).
        Ctx ->
        -- | __Output:__ a pointer to a 32-byte array to place the serialized key in
        -- (cannot be NULL).
        Ptr (Bytes 32) ->
        -- | __Input:__ a pointer to a 'XonlyPubkey64' containing an
        -- initialized public key (cannot be NULL).
        Ptr XonlyPubkey64 ->
        -- | __Returns:__ 1 always.
        IO Ret


-- | Tweak an x-only public key by adding the generator multiplied with tweak32
--  to it.
--
--  Note that the resulting point can not in general be represented by an x-only
--  pubkey because it may have an odd Y coordinate. Instead, the output_pubkey
--  is a normal 'Pubkey64'.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_xonly_pubkey_tweak_add"
    xonlyPubkeyTweakAdd ::
        -- | pointer to a context object initialized for verification
        -- (cannot be NULL)
        Ctx ->
        -- | __Output:__ pointer to a public key to store the result. Will be set
        -- to an invalid value if this function returns 0 (cannot
        -- be NULL)
        Ptr Pubkey64 ->
        -- | __Input:__ internal_pubkey: pointer to an x-only pubkey to apply the tweak to.
        -- (cannot be NULL).
        Ptr XonlyPubkey64 ->
        -- | __Input:__ pointer to a 32-byte tweak. If the tweak is invalid
        -- according to 'ecSeckeyVerify', this function
        -- returns 0. For uniformly random 32-byte arrays the
        -- chance of being invalid is negligible (around 1 in
        -- 2^128) (cannot be NULL).
        Ptr Tweak32 ->
        -- | __Returns:__ 0 if the arguments are invalid or the resulting public key would be
        -- invalid (only when the tweak is the negation of the corresponding
        -- secret key). 1 otherwise.
        IO Ret


-- | Checks that a tweaked pubkey is the result of calling
-- 'xonlyPubkeyTweakAdd' with the pubkey and tweak.
--
--  The tweaked pubkey is represented by its 32-byte x-only serialization and
--  its pk_parity, which can both be obtained by converting the result of
--  tweak_add to a 'XonlyPubkey64'.
--
--  Note that this alone does _not_ verify that the tweaked pubkey is a
--  commitment. If the tweak is not chosen in a specific way, the tweaked pubkey
--  can easily be the result of a different internal_pubkey and tweak.
foreign import capi safe "secp256k1_schnorrsig.h secp256k1_xonly_pubkey_tweak_add_check"
    xonlyPubkeyTweakAddCheck ::
        -- | pointer to a context object initialized for verification
        -- (cannot be NULL)
        Ctx ->
        -- | __Input:__ pointer to a serialized xonly_pubkey (cannot be NULL)
        Ptr XonlyPubkey64 ->
        -- | __Input:__ the parity of the tweaked pubkey (whose serialization
        -- is passed in as tweaked_pubkey32). This must match the
        -- pk_parity value that is returned when calling
        -- 'xonlyPubkey' with the tweaked pubkey, or
        -- this function will fail.
        CInt ->
        -- | __Input__ pointer to an x-only public key object to apply the
        -- tweak to (cannot be NULL)
        Ptr XonlyPubkey64 ->
        -- | __Input:__ pointer to a 32-byte tweak (cannot be NULL)
        Ptr Tweak32 ->
        -- | __Returns:__ 0 if the arguments are invalid or the tweaked pubkey is not the
        -- result of tweaking the internal_pubkey with tweak32. 1 otherwise.
        IO Ret


-- * Scratch Space


-- | Create a secp256k1 scratch space object.
foreign import capi safe "secp256k1.h secp256k1_scratch_space_create"
    scratchSpaceCreate ::
        -- | an existing context object (cannot be NULL)
        Ctx ->
        -- | __Input:__ amount of memory to be available as scratch space. Some extra
        -- (<100 bytes) will be allocated for extra accounting.
        CSize ->
        -- | __Returns:__ a newly created scratch space.
        IO (Ptr Scratch)


-- | Destroy a secp256k1 scratch space.
--
--  The pointer may not be used afterwards.
foreign import capi safe "secp256k1.h secp256k1_scratch_space_destroy"
    scratchSpaceDestroy ::
        -- | a secp256k1 context object.
        Ctx ->
        -- | __Input:__ space to destroy
        Ptr Scratch ->
        IO ()


-- * Deprecated
{-# DEPRECATED ecPrivkeyNegate "use ecSeckeyNegate instead" #-}
foreign import capi safe "secp256k1.h secp256k1_ec_privkey_negate"
    ecPrivkeyNegate ::
        Ctx ->
        Ptr Tweak32 ->
        IO Ret


{-# DEPRECATED ecPrivkeyTweakAdd "use ecSeckeyTweakAdd instead" #-}
foreign import capi safe "secp256k1.h secp256k1_ec_privkey_tweak_add"
    ecPrivkeyTweakAdd ::
        Ctx ->
        Ptr Seckey32 ->
        Ptr Tweak32 ->
        IO Ret


{-# DEPRECATED ecPrivkeyTweakMul "use ecSeckeyTweakMul instead" #-}
foreign import capi safe "secp256k1.h secp256k1_ec_privkey_tweak_mul"
    ecPrivkeyTweakMul ::
        Ctx ->
        Ptr Seckey32 ->
        Ptr Tweak32 ->
        IO Ret


-- * Pointer Types
data LCtx
data Pubkey64
data XonlyPubkey64
data Keypair96
data Msg32
data RecSig65
data Sig64
data Seed32
data Seckey32
data Tweak32
data SchnorrExtra
data Scratch
data Bytes (n :: Nat)


-- * Function Pointer Types


-- | A pointer to a function to deterministically generate a nonce.
-- Except for test cases, this function should compute some cryptographic hash of
-- the message, the algorithm, the key and the attempt.
type NonceFun a =
    -- | __Output:__ pointer to a 32-byte array to be filled by the function.
    Ptr CUChar ->
    -- | __Input:__ the 32-byte message hash being verified (will not be NULL)
    Ptr CUChar ->
    -- | __Input:__ pointer to a 32-byte secret key (will not be NULL)
    Ptr CUChar ->
    -- | __Input:__ pointer to a 16-byte array describing the signature
    -- algorithm (will be NULL for ECDSA for compatibility).
    Ptr CUChar ->
    -- | __Input:__ Arbitrary data pointer that is passed through.
    Ptr a ->
    -- | __Input:__ how many iterations we have tried to find a nonce.
    -- This will almost always be 0, but different attempt values
    -- are required to result in a different nonce.
    CInt ->
    -- | __Returns:__ 1 if a nonce was successfully generated. 0 will cause signing to fail.
    IO CInt


-- | A pointer to a function to deterministically generate a nonce.
--
--  Same as 'NonceFun' with the exception of accepting an
--  additional pubkey argument and not requiring an attempt argument. The pubkey
--  argument can protect signature schemes with key-prefixed challenge hash
--  inputs against reusing the nonce when signing with the wrong precomputed
--  pubkey.
--
--
--  Except for test cases, this function should compute some cryptographic hash of
--  the message, the key, the pubkey, the algorithm description, and data.
type NonceFunHardened a =
    -- | __Output:__ pointer to a 32-byte array to be filled by the function
    Ptr CUChar ->
    -- | __Input:__ the message being verified. Is NULL if and only if msglen is 0.
    Ptr CUChar ->
    -- | __Input:__ the length of the message
    CSize ->
    -- | __Input:__ pointer to a 32-byte secret key (will not be NULL)
    Ptr CUChar ->
    -- | __Input:__ the 32-byte serialized xonly pubkey corresponding to key32 (will not be NULL)
    Ptr CUChar ->
    -- | __Input:__ pointer to an array describing the signature algorithm (will not be NULL)
    Ptr CUChar ->
    -- | __Input:__ the length of the algo array
    CSize ->
    -- | __Input:__ arbitrary data pointer that is passed through
    Ptr a ->
    -- | __Returns:__ 1 if a nonce was successfully generated. 0 will cause signing to return an error.
    IO CInt


-- | A pointer to a function that hashes an EC point to obtain an ECDH secret
type EcdhHashFun a =
    -- | __Output:__ pointer to an array to be filled by the function
    Ptr CUChar ->
    -- | __Input:__ pointer to a 32-byte x coordinate
    Ptr CUChar ->
    -- | __Input:__ pointer to a 32-byte y coordinate
    Ptr CUChar ->
    -- | __Input:__ arbitrary data pointer that is passed through
    Ptr a ->
    -- | __Returns:__ 1 if the point was successfully hashed.
    -- 0 will cause 'ecdh' to fail and return 0.
    -- Other return values are not allowed, and the behaviour of
    -- 'ecdh' is undefined for other return values.
    IO CInt
