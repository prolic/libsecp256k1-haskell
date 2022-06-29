{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}

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
import Foreign (FunPtr, Ptr, castPtr)
import Foreign.C (
    CInt (..),
    CSize (..),
    CString,
    CUChar,
    CUInt (..),
 )
import GHC.TypeNats (Nat)
import System.IO.Unsafe (unsafePerformIO)


data LCtx
data Pubkey64
data XonlyPubkey64
data Keypair96
data Msg32
data RecSig65
data Sig64
data Compact64
data Seed32
data Seckey32
data Tweak32
data SchnorrExtra
data Scratch
data Bytes (n :: Nat)


type CtxFlags = CUInt
type SerFlags = CUInt
type Ret = CInt


type NonceFun a =
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr a ->
    CInt ->
    IO CInt


type NonceFunHardened a =
    Ptr CUChar ->
    Ptr CUChar ->
    CSize ->
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr CUChar ->
    CSize ->
    Ptr a ->
    IO CInt


type EcdhHashFun a =
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr a ->
    IO CInt


type Ctx = Ptr LCtx


verify :: CtxFlags
verify = 0x0101


sign :: CtxFlags
sign = 0x0201


signVerify :: CtxFlags
signVerify = 0x0301


compressed :: SerFlags
compressed = 0x0102


uncompressed :: SerFlags
uncompressed = 0x0002


isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n


unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
    BU.unsafeUseAsCStringLen bs $ \(b, l) ->
        f (castPtr b, fromIntegral l)


useByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useByteString bs f =
    BS.useAsCStringLen bs $ \(b, l) ->
        f (castPtr b, fromIntegral l)


unsafePackByteString :: (Ptr a, CSize) -> IO ByteString
unsafePackByteString (b, l) =
    BU.unsafePackMallocCStringLen (castPtr b, fromIntegral l)


packByteString :: (Ptr a, CSize) -> IO ByteString
packByteString (b, l) =
    BS.packCStringLen (castPtr b, fromIntegral l)


ctx :: Ctx
ctx = unsafePerformIO $ contextCreate signVerify
{-# NOINLINE ctx #-}


-- secp256k1_context_clone
foreign import ccall safe "secp256k1.h secp256k1_context_clone"
    contextClone :: Ctx -> IO Ctx


-- secp256k1_context_create
foreign import ccall safe "secp256k1.h secp256k1_context_create"
    contextCreate :: CtxFlags -> IO Ctx


-- secp256k1_context_destroy
foreign import ccall safe "secp256k1.h &secp256k1_context_destroy"
    contextDestroy :: FunPtr (Ctx -> IO ())


-- secp256k1_context_no_precomp
foreign import ccall safe "secp256k1.h secp256k1_context_no_precomp"
    contextNoPrecomp :: Ctx


-- secp256k1_context_preallocated_clone
foreign import ccall safe "secp256k1.h secp256k1_context_preallocated_clone"
    contextPreallocatedClone :: Ctx -> Ptr (Bytes n) -> IO Ctx


-- secp256k1_context_preallocated_clone_size
foreign import ccall safe "secp256k1.h secp256k1_context_preallocated_clone_size"
    contextPreallocatedCloneSize :: Ctx -> IO CSize


-- secp256k1_context_preallocated_create
foreign import ccall safe "secp256k1.h secp256k1_context_preallocated_create"
    contextPreallocatedCreate :: Ptr (Bytes n) -> CUInt -> IO Ctx


-- secp256k1_context_preallocated_destroy
foreign import ccall safe "secp256k1.h secp256k1_context_preallocated_destroy"
    contextPreallocatedDestroy :: Ctx -> IO ()


-- secp256k1_context_preallocated_size
foreign import ccall safe "secp256k1.h secp256k1_context_preallocated_size"
    contextPreallocatedSize :: CUInt -> IO CSize


-- secp256k1_context_randomize
foreign import ccall safe "secp256k1.h secp256k1_context_randomize"
    contextRandomize :: Ctx -> Ptr Seed32 -> IO Ret


-- secp256k1_context_set_error_callback
foreign import ccall safe "secp256k1.h secp256k1_context_set_error_callback"
    setErrorCallback ::
        Ctx ->
        -- | message, data
        FunPtr (CString -> Ptr a -> IO ()) ->
        -- | data
        Ptr a ->
        IO ()


-- secp256k1_context_set_illegal_callback
foreign import ccall safe "secp256k1.h secp256k1_context_set_illegal_callback"
    setIllegalCallback ::
        Ctx ->
        -- | message, data
        FunPtr (CString -> Ptr a -> IO ()) ->
        -- | data
        Ptr a ->
        IO ()


-- secp256k1_ecdh
foreign import ccall safe "secp256k1.h secp256k1_ecdh"
    ecdh :: Ctx -> Ptr (Bytes n) -> Ptr Pubkey64 -> Ptr Seckey32 -> FunPtr (EcdhHashFun a) -> Ptr a -> IO Ret


-- secp256k1_ecdh_hash_function_default
foreign import ccall safe "secp256k1.h &secp256k1_ecdh_hash_function_default"
    ecdhHashFunctionDefault :: FunPtr (EcdhHashFun a)


-- secp256k1_ecdh_hash_function_sha256
foreign import ccall safe "secp256k1.h &secp256k1_ecdh_hash_sha256"
    ecdhHashSha256 :: FunPtr (EcdhHashFun a)


-- secp256k1_ecdsa_recover
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_recover"
    ecdsaRecover :: Ctx -> Ptr Pubkey64 -> Ptr RecSig65 -> Ptr Msg32 -> IO Ret


-- secp256k1_ecdsa_recoverable_signature_convert
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_recoverable_signature_convert"
    ecdsaRecoverableSignatureConvert :: Ctx -> Ptr Sig64 -> Ptr RecSig65 -> IO Ret


-- secp256k1_ecdsa_recoverable_signature_parse_compact
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_recoverable_signature_parse_compact"
    ecdsaRecoverableSignatureParseCompact :: Ctx -> Ptr RecSig65 -> Ptr (Bytes 64) -> CInt -> IO Ret


-- secp256k1_ecdsa_recoverable_signature_serialize_compact
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_recoverable_signature_serialize_compact"
    ecdsaRecoverableSignatureSerializeCompact :: Ctx -> Ptr (Bytes 64) -> Ptr CInt -> Ptr RecSig65 -> IO Ret


-- secp256k1_ecdsa_sign
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_sign"
    ecdsaSign ::
        Ctx ->
        Ptr Sig64 ->
        Ptr Msg32 ->
        Ptr Seckey32 ->
        FunPtr (NonceFun a) ->
        -- | nonce data
        Ptr a ->
        IO Ret


-- secp256k1_ecdsa_signature_normalize
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_normalize"
    ecdsaSignatureNormalize ::
        Ctx ->
        -- | output
        Ptr Sig64 ->
        -- | input
        Ptr Sig64 ->
        IO Ret


-- secp256k1_ecdsa_signature_parse_compact
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
    ecdsaSignatureParseCompact ::
        Ctx ->
        Ptr Sig64 ->
        Ptr Compact64 ->
        IO Ret


-- secp256k1_ecdsa_signature_parse_der
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_der"
    ecdsaSignatureParseDer ::
        Ctx ->
        Ptr Sig64 ->
        -- | encoded DER signature
        Ptr (Bytes n) ->
        -- | size of encoded signature
        CSize ->
        IO Ret


-- secp256k1_ecdsa_signature_serialize_compact
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
    ecdsaSignatureSerializeCompact ::
        Ctx ->
        Ptr Compact64 ->
        Ptr Sig64 ->
        IO Ret


-- secp256k1_ecdsa_signature_serialize_der
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
    ecdsaSignatureSerializeDer ::
        Ctx ->
        -- | array for encoded signature, must be large enough
        Ptr (Bytes n) ->
        -- | size of encoded signature, will be updated
        Ptr CSize ->
        Ptr Sig64 ->
        IO Ret


-- secp256k1_ecdsa_sign_recoverable
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_sign_recoverable"
    ecdsaSignRecoverable ::
        Ctx -> Ptr RecSig65 -> Ptr Msg32 -> Ptr Seckey32 -> FunPtr (NonceFun a) -> Ptr a -> IO Ret


-- secp256k1_ecdsa_verify
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_verify"
    ecdsaVerify ::
        Ctx ->
        Ptr Sig64 ->
        Ptr Msg32 ->
        Ptr Pubkey64 ->
        IO Ret


-- secp256k1_ec_privkey_negate
{-# DEPRECATED ecPrivkeyNegate "use ecSeckeyNegate instead" #-}
foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_negate"
    ecPrivkeyNegate ::
        Ctx ->
        Ptr Tweak32 ->
        IO Ret


-- secp256k1_ec_privkey_tweak_add
{-# DEPRECATED ecPrivkeyTweakAdd "use ecSeckeyTweakAdd instead" #-}
foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_tweak_add"
    ecPrivkeyTweakAdd ::
        Ctx ->
        Ptr Seckey32 ->
        Ptr Tweak32 ->
        IO Ret


-- secp256k1_ec_privkey_tweak_mul
{-# DEPRECATED ecPrivkeyTweakMul "use ecSeckeyTweakMul instead" #-}
foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_tweak_mul"
    ecPrivkeyTweakMul ::
        Ctx ->
        Ptr Seckey32 ->
        Ptr Tweak32 ->
        IO Ret


-- secp256k1_ec_pubkey_cmp
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_cmp"
    ecPubkeyCmp ::
        Ctx ->
        Ptr Pubkey64 ->
        Ptr Pubkey64


-- secp256k1_ec_pubkey_combine
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_combine"
    ecPubKeyCombine ::
        Ctx ->
        -- | pointer to public key storage
        Ptr Pubkey64 ->
        -- | pointer to array of public keys
        Ptr (Ptr Pubkey64) ->
        -- | number of public keys
        CInt ->
        IO Ret


-- secp256k1_ec_pubkey_create
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_create"
    ecPubKeyCreate ::
        Ctx ->
        Ptr Pubkey64 ->
        Ptr Seckey32 ->
        IO Ret


-- secp256k1_ec_pubkey_negate
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_negate"
    ecPubkeyNegate :: Ctx -> Ptr Pubkey64 -> IO Ret


-- secp256k1_ec_pubkey_parse
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_parse"
    ecPubkeyParse ::
        Ctx ->
        Ptr Pubkey64 ->
        -- | encoded public key array
        Ptr (Bytes n) ->
        -- | size of encoded public key array
        CSize ->
        IO Ret


-- secp256k1_ec_pubkey_serialize
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_serialize"
    ecPubKeySerialize ::
        Ctx ->
        -- | array for encoded public key, must be large enough
        Ptr (Bytes n) ->
        -- | size of encoded public key, will be updated
        Ptr CSize ->
        Ptr Pubkey64 ->
        SerFlags ->
        IO Ret


-- secp256k1_ec_pubkey_tweak_add
foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_tweak_add"
    ecPubKeyTweakAdd ::
        Ctx ->
        Ptr Pubkey64 ->
        Ptr Tweak32 ->
        IO Ret


-- secp256k1_ec_pubkey_tweak_mul
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_tweak_mul"
    ecPubKeyTweakMul ::
        Ctx ->
        Ptr Pubkey64 ->
        Ptr Tweak32 ->
        IO Ret


-- secp256k1_ec_seckey_negate
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_negate"
    ecSeckeyNegate :: Ctx -> Ptr Seckey32 -> IO Ret


-- secp256k1_ec_seckey_tweak_add
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_tweak_add"
    ecSeckeyTweakAdd :: Ctx -> Ptr Seckey32 -> Ptr Tweak32 -> IO Ret


-- secp256k1_ec_seckey_tweak_mul
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_tweak_mul"
    ecSeckeyTweakMul :: Ctx -> Ptr Seckey32 -> Ptr Tweak32 -> IO Ret


-- secp256k1_ec_seckey_verify
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_verify"
    ecSecKeyVerify ::
        Ctx ->
        Ptr Seckey32 ->
        IO Ret


-- secp256k1_keypair_create
foreign import ccall safe "secp256k1.h secp256k1_keypair_create"
    keypairCreate :: Ctx -> Ptr Keypair96 -> Ptr Seckey32 -> IO Ret


-- secp256k1_keypair_pub
foreign import ccall safe "secp256k1.h secp256k1_keypair_pub"
    keypairPub :: Ctx -> Ptr Pubkey64 -> Ptr Keypair96 -> IO Ret


-- secp256k1_keypair_sec
foreign import ccall safe "secp256k1.h secp256k1_keypair_sec"
    keypairSec :: Ctx -> Ptr Seckey32 -> Ptr Keypair96 -> IO Ret


-- secp256k1_keypair_xonly_pub
foreign import ccall safe "secp256k1.h secp256k1_keypair_xonly_pub"
    keypairXonlyPub :: Ctx -> Ptr XonlyPubkey64 -> Ptr CInt -> Ptr Keypair96 -> IO Ret


-- secp256k1_keypair_xonly_tweak_add
foreign import ccall safe "secp256k1.h secp256k1_keypair_xonly_tweak_add"
    keypairXonlyTweakAdd :: Ctx -> Ptr Keypair96 -> Ptr Tweak32 -> IO Ret


-- secp256k1_nonce_function_bip340
foreign import ccall safe "secp256k1.h &secp256k1_nonce_function_bip340"
    nonceFunctionBip340 :: FunPtr (NonceFunHardened a)


-- secp256k1_nonce_function_default
foreign import ccall safe "secp256k1.h &secp256k1_nonce_function_default"
    nonceFunctionDefault :: FunPtr (NonceFun a)


-- secp256k1_nonce_function_rfc6979
foreign import ccall safe "secp256k1.h &secp256k1_nonce_function_rfc6979"
    nonceFunctionRfc6979 :: FunPtr (NonceFun a)


-- secp256k1_schnorrsig_sign
foreign import ccall safe "secp256k1.h secp256k1_schnorrsig_sign"
    schnorrsigSign :: Ctx -> Ptr Sig64 -> Ptr Msg32 -> Ptr Keypair96 -> Ptr (Bytes 32) -> IO Ret


-- secp256k1_schnorrsig_sign_custom
foreign import ccall safe "secp256k1.h secp256k1_schnorrsig_sign_custom"
    schnorrsigSignCustom :: Ctx -> Ptr Sig64 -> Ptr (Bytes n) -> CSize -> Ptr Keypair96 -> Ptr SchnorrExtra -> IO Ret


-- secp256k1_schnorrsig_verify
foreign import ccall safe "secp256k1.h secp256k1_schnorrsig_verify"
    schnorrSigSignVerify :: Ctx -> Ptr Sig64 -> Ptr (Bytes n) -> CSize -> Ptr XonlyPubkey64 -> IO Ret


-- secp256k1_scratch_space_create
foreign import ccall safe "secp256k1.h secp256k1_scratch_space_create"
    scratchSpaceCreate :: Ctx -> CSize -> IO (Ptr Scratch)


-- secp256k1_scratch_space_destroy
foreign import ccall safe "secp256k1.h secp256k1_scratch_space_destroy"
    scratchSpaceDestroy :: Ctx -> Ptr Scratch -> IO ()


-- secp256k1_tagged_sha256
foreign import ccall safe "secp256k1.h secp256k1_tagged_sha256"
    taggedSha256 :: Ctx -> Ptr (Bytes 32) -> Ptr (Bytes n) -> CSize -> Ptr (Bytes n) -> CSize -> IO Ret


-- secp256k1_xonly_pubkey_cmp
foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_cmp"
    xonlyPubkeyCmp :: Ctx -> Ptr XonlyPubkey64 -> Ptr XonlyPubkey64 -> IO Ret


-- secp256k1_xonly_pubkey_from_pubkey
foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_from_pubkey"
    xonlyPubkeyFromPubkey :: Ctx -> Ptr XonlyPubkey64 -> Ptr CInt -> Ptr Pubkey64 -> IO Ret


-- secp256k1_xonly_pubkey_parse
foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_parse"
    xonlyPubkeyParse :: Ctx -> Ptr XonlyPubkey64 -> Ptr (Bytes 32) -> IO Ret


-- secp256k1_xonly_pubkey_serialize
foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_serialize"
    xonlyPubkeySerialize :: Ctx -> Ptr (Bytes 32) -> Ptr XonlyPubkey64 -> IO Ret


-- secp256k1_xonly_pubkey_tweak_add
foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_tweak_add"
    xonlyPubkeyTweakAdd :: Ctx -> Ptr Pubkey64 -> Ptr XonlyPubkey64 -> Ptr Tweak32 -> IO Ret


-- secp256k1_xonly_pubkey_tweak_add_check
foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_tweak_add_check"
    xonlyPubkeyTweakAddCheck :: Ctx -> Ptr (Bytes 32) -> CInt -> Ptr XonlyPubkey64 -> Ptr Tweak32 -> IO Ret
