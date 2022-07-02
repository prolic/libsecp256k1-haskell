{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

-- |
-- Module      : Crypto.Secp256k1
-- License     : UNLICENSE
-- Maintainer  : Keagan McClelland <keagan.mcclelland@gmail.com>
-- Stability   : experimental
-- Portability : POSIX
--
-- Crytpographic functions from Bitcoin’s secp256k1 library.
module Crypto.Secp256k1 where

import Control.Monad (replicateM, unless, (<=<))
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Cont (ContT (..), evalContT)
import Crypto.Secp256k1.Internal
import Crypto.Secp256k1.Prim (flagsEcUncompressed)
import qualified Crypto.Secp256k1.Prim as Prim
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

-- import qualified Data.ByteString.Base16 as B16
import Data.ByteString.Unsafe (unsafePackCStringLen, unsafePackMallocCStringLen)
import Data.Functor (($>))

-- import Data.Hashable (Hashable (..))
import Data.Maybe (fromJust, fromMaybe, isJust)
import Data.String (IsString (..))

-- import Data.String.Conversions (ConvertibleStrings, cs)

import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Foreign (
    Bits (..),
    ForeignPtr,
    Ptr,
    alloca,
    allocaArray,
    allocaBytes,
    castForeignPtr,
    castPtr,
    finalizerFree,
    free,
    mallocBytes,
    newForeignPtr,
    nullFunPtr,
    nullPtr,
    peek,
    poke,
    pokeArray,
    withForeignPtr,
 )
import GHC.Generics (Generic)
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafePerformIO)
import Text.Read (
    Lexeme (String),
    lexP,
    parens,
    pfail,
    readPrec,
 )


newtype SecKey = SecKey {secKeyFPtr :: ForeignPtr Prim.Seckey32}
newtype PubKeyXY = PubKeyXY {pubKeyXYFPtr :: ForeignPtr Prim.Pubkey64}
newtype PubKeyXO = PubKeyXO {pubKeyXOFPtr :: ForeignPtr Prim.XonlyPubkey64}
newtype KeyPair = KeyPair {keyPairFPtr :: ForeignPtr Prim.Keypair96}
newtype MsgHash = MsgHash {msgHashFPtr :: ForeignPtr Prim.Msg32}
newtype Signature = Signature {signatureFPtr :: ForeignPtr Prim.Sig64}
newtype RecoverableSignature = RecoverableSignature {recoverableSignatureFPtr :: ForeignPtr Prim.RecSig65}
newtype Tweak = Tweak {tweakFPtr :: ForeignPtr Prim.Tweak32}


-- | Preinitialized context for signing and verification
ctx :: Prim.Ctx
ctx = unsafePerformIO $ Prim.contextCreate (Prim.flagsContextSign .|. Prim.flagsContextVerify)
{-# NOINLINE ctx #-}


importSecKey :: ByteString -> Maybe SecKey
importSecKey bs
    | BS.length bs /= 32 = Nothing
    | otherwise = unsafePerformIO $ do
        unsafeUseByteString bs $ \(ptr, len) -> do
            ret <- Prim.ecSecKeyVerify ctx ptr
            if isSuccess ret
                then do
                    newPtr <- mallocBytes 32
                    memcpy newPtr ptr 32
                    Just . SecKey <$> newForeignPtr finalizerFree newPtr
                else pure Nothing


-- | Parses a 33 or 65 byte public key, all other lengths will result in @Nothing@
importPubKeyXY :: ByteString -> Maybe PubKeyXY
importPubKeyXY bs = unsafePerformIO $
    unsafeUseByteString bs $ \(input, len) -> do
        pubkeyOutputBuf <- mallocBytes 64
        if len == 33 || len == 65
            then do
                ret <- Prim.ecPubkeyParse ctx (castPtr pubkeyOutputBuf) input len
                if isSuccess ret
                    then Just . PubKeyXY <$> newForeignPtr finalizerFree (castPtr pubkeyOutputBuf)
                    else free pubkeyOutputBuf $> Nothing
            else pure Nothing


-- | Serialize public key to 'ByteString'. First argument 'True' for compressed output. If the underlying Pubkey is
-- an 'XOnly
exportPubKeyXY :: Bool -> PubKeyXY -> ByteString
exportPubKeyXY compress (PubKeyXY fptr) = unsafePerformIO $ do
    let flags = if compress then Prim.flagsEcCompressed else Prim.flagsEcUncompressed
    let sz = if compress then 33 else 65
    buf <- mallocBytes sz
    alloca $ \written -> do
        -- always succeeds so we don't need to check
        _ret <- withForeignPtr fptr $ \ptr -> Prim.ecPubkeySerialize ctx buf written ptr flags
        len <- peek written
        unsafePackMallocCStringLen (castPtr buf, fromIntegral len)


importPubKeyXO :: ByteString -> Maybe PubKeyXO
importPubKeyXO bs
    | BS.length bs /= 32 = Nothing
    | otherwise = unsafePerformIO $ do
        outBuf <- mallocBytes 64
        unsafeUseByteString bs $ \(ptr, _) -> do
            ret <- Prim.xonlyPubkeyParse ctx outBuf ptr
            if isSuccess ret
                then Just . PubKeyXO <$> newForeignPtr finalizerFree outBuf
                else pure Nothing


exportPubKeyXO :: PubKeyXO -> ByteString
exportPubKeyXO (PubKeyXO pkFPtr) = unsafePerformIO $ do
    outBuf <- mallocBytes 32
    _ret <- withForeignPtr pkFPtr $ Prim.xonlyPubkeySerialize ctx outBuf
    unsafePackByteString (outBuf, 32)


importSignature :: ByteString -> Maybe Signature
importSignature bs = unsafePerformIO $
    unsafeUseByteString bs $ \(inBuf, len) -> do
        outBuf <- mallocBytes 64
        ret <-
            if
                    -- compact
                    | len == 64 -> Prim.ecdsaSignatureParseCompact ctx outBuf inBuf
                    -- der
                    | len >= 71 && len <= 73 -> Prim.ecdsaSignatureParseDer ctx outBuf inBuf len
                    -- invalid
                    | otherwise -> pure 0
        if isSuccess ret
            then Just . Signature <$> newForeignPtr finalizerFree (castPtr outBuf)
            else free outBuf $> Nothing


exportSignatureCompact :: Signature -> ByteString
exportSignatureCompact (Signature fptr) = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    -- always succeeds
    _ret <- withForeignPtr fptr $ Prim.ecdsaSignatureSerializeCompact ctx outBuf
    unsafePackByteString (outBuf, 64)


exportSignatureDer :: Signature -> ByteString
exportSignatureDer (Signature fptr) = unsafePerformIO $ do
    -- as of Q4'2015 73 byte sigs became nonstandard so we will never create one that big
    outBuf <- mallocBytes 72
    alloca $ \written -> do
        -- always succeeds
        _ret <- withForeignPtr fptr $ Prim.ecdsaSignatureSerializeDer ctx outBuf written
        len <- peek written
        unsafePackByteString (outBuf, len)


importTweak :: ByteString -> Maybe Tweak
importTweak = fmap (Tweak . castForeignPtr . secKeyFPtr) . importSecKey


-- | Verify message signature. 'True' means that the signature is correct.
ecdsaVerify :: ByteString -> PubKeyXY -> Signature -> Bool
ecdsaVerify msgHash (PubKeyXY pkFPtr) (Signature sigFPtr) = unsafePerformIO $
    evalContT $ do
        pkPtr <- ContT (withForeignPtr pkFPtr)
        sigPtr <- ContT (withForeignPtr sigFPtr)
        (msgHashPtr, n) <- ContT (unsafeUseByteString msgHash)
        lift $ isSuccess <$> Prim.ecdsaVerify ctx sigPtr msgHashPtr pkPtr


ecdsaSign :: SecKey -> ByteString -> Maybe Signature
ecdsaSign (SecKey skFPtr) msgHash
    | BS.length msgHash /= 32 = Nothing
    | otherwise = unsafePerformIO $
        evalContT $ do
            skPtr <- ContT (withForeignPtr skFPtr)
            (msgHashPtr, _) <- ContT (unsafeUseByteString msgHash)
            sigBuf <- lift $ mallocBytes 64
            ret <- lift $ Prim.ecdsaSign ctx sigBuf msgHashPtr skPtr Prim.nonceFunctionDefault nullPtr
            lift $
                if isSuccess ret
                    then Just . Signature <$> newForeignPtr finalizerFree sigBuf
                    else free sigBuf $> Nothing


derivePubKey :: SecKey -> PubKeyXY
derivePubKey (SecKey skFPtr) = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    ret <- withForeignPtr skFPtr $ Prim.ecPubkeyCreate ctx outBuf
    unless (isSuccess ret) $ do
        free outBuf
        error "Bug: Invalid Secret Key Constructed"
    PubKeyXY <$> newForeignPtr finalizerFree outBuf


ecdh :: SecKey -> PubKeyXY -> Digest SHA256
ecdh SecKey{..} PubKeyXY{..} = unsafePerformIO . evalContT $ do
    outBuf <- lift (mallocBytes 32)
    sk <- ContT (withForeignPtr secKeyFPtr)
    pk <- ContT (withForeignPtr pubKeyXYFPtr)
    ret <- lift (Prim.ecdh ctx outBuf pk sk Prim.ecdhHashFunctionSha256 nullPtr)
    if isSuccess ret
        then do
            bs <- lift $ unsafePackByteString (outBuf, 32)
            let Just digest = digestFromByteString bs
            pure digest
        else lift (free outBuf) *> error "Bug: Invalid Scalar or Overflow"


-- -- | Add tweak to secret key.
ecSecKeyTweakAdd :: SecKey -> Tweak -> Maybe SecKey
ecSecKeyTweakAdd SecKey{..} Tweak{..} = unsafePerformIO . evalContT $ do
    skPtr <- ContT (withForeignPtr secKeyFPtr)
    skOut <- lift (mallocBytes 32)
    lift (memcpy skOut skPtr 32)
    twkPtr <- ContT (withForeignPtr tweakFPtr)
    ret <- lift (Prim.ecSeckeyTweakAdd ctx skOut twkPtr)
    lift $
        if isSuccess ret
            then Just . SecKey <$> newForeignPtr finalizerFree skOut
            else free skOut $> Nothing


-- | Multiply secret key by tweak.
ecSecKeyTweakMul :: SecKey -> Tweak -> Maybe SecKey
ecSecKeyTweakMul SecKey{..} Tweak{..} = unsafePerformIO . evalContT $ do
    skPtr <- ContT (withForeignPtr secKeyFPtr)
    skOut <- lift (mallocBytes 32)
    lift (memcpy skOut skPtr 32)
    twkPtr <- ContT (withForeignPtr tweakFPtr)
    ret <- lift (Prim.ecSeckeyTweakMul ctx skOut twkPtr)
    lift $
        if isSuccess ret
            then Just . SecKey <$> newForeignPtr finalizerFree skOut
            else free skOut $> Nothing

-- -- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
-- tweakAddPubKey :: PubKey -> Tweak -> Maybe PubKey
-- tweakAddPubKey (PubKey pub_key) (Tweak t) = unsafePerformIO $
--     unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
--         unsafeUseByteString t $ \(tweak_ptr, _) -> do
--             ret <- Prim.ecPubkeyTweakAdd Prim.ctx pub_key_ptr tweak_ptr
--             if isSuccess ret
--                 then return (Just (PubKey new_bs))
--                 else return Nothing
--     where
--         new_bs = BS.copy pub_key

-- -- | Multiply public key by tweak. Tweak is multiplied first by G to obtain a
-- -- point.
-- tweakMulPubKey :: PubKey -> Tweak -> Maybe PubKey
-- tweakMulPubKey (PubKey pub_key) (Tweak t) = unsafePerformIO $
--     unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
--         unsafeUseByteString t $ \(tweak_ptr, _) -> do
--             ret <- Prim.ecPubkeyTweakMul Prim.ctx pub_key_ptr tweak_ptr
--             if isSuccess ret
--                 then return (Just (PubKey new_bs))
--                 else return Nothing
--     where
--         new_bs = BS.copy pub_key

-- -- | Add multiple public keys together.
-- combinePubKeys :: [PubKey] -> Maybe PubKey
-- combinePubKeys [] = Nothing
-- combinePubKeys pubs = unsafePerformIO $
--     pointers [] pubs $ \ps ->
--         allocaArray (length ps) $ \a -> do
--             out <- mallocBytes 64
--             pokeArray a ps
--             ret <- Prim.ecPubkeyCombine Prim.ctx out a (fromIntegral $ length ps)
--             if isSuccess ret
--                 then do
--                     bs <- unsafePackByteString (out, 64)
--                     return (Just (PubKey bs))
--                 else do
--                     free out
--                     return Nothing
--     where
--         pointers ps [] f = f ps
--         pointers ps (PubKey pub_key : pub_keys) f =
--             unsafeUseByteString pub_key $ \(p, _) ->
--                 pointers (p : ps) pub_keys f
