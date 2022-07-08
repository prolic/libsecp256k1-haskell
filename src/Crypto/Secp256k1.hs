{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -fno-show-valid-hole-fits #-}

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
import Data.ByteArray.Sized
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
import Data.Foldable (for_)
import Foreign (
    Bits (..),
    ForeignPtr,
    FunPtr,
    Ptr,
    Storable,
    Word8,
    alloca,
    allocaArray,
    allocaBytes,
    castForeignPtr,
    castPtr,
    finalizerFree,
    free,
    freeHaskellFunPtr,
    malloc,
    mallocBytes,
    newForeignPtr,
    newForeignPtr_,
    nullFunPtr,
    nullPtr,
    peek,
    peekByteOff,
    peekElemOff,
    plusPtr,
    poke,
    pokeArray,
    pokeByteOff,
    pokeElemOff,
    sizeOf,
    withForeignPtr,
 )
import Foreign.C (CInt (..), CSize (..))
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


-- newtype MsgHash = MsgHash {msgHashFPtr :: ForeignPtr Prim.Msg32}
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


importRecoverableSignature :: ByteString -> Maybe RecoverableSignature
importRecoverableSignature bs
    | BS.length bs /= 65 = Nothing
    | otherwise = unsafePerformIO . evalContT $ do
        outBuf <- lift (mallocBytes 65)
        (ptr, len) <- ContT (unsafeUseByteString bs)
        recId <- lift (peekByteOff @Word8 ptr 64)
        let recIdCInt = fromIntegral recId
        ret <- lift (Prim.ecdsaRecoverableSignatureParseCompact ctx outBuf ptr recIdCInt)
        lift $
            if isSuccess ret
                then Just . RecoverableSignature <$> newForeignPtr finalizerFree outBuf
                else free outBuf $> Nothing


exportRecoverableSignature :: RecoverableSignature -> ByteString
exportRecoverableSignature RecoverableSignature{..} = unsafePerformIO . evalContT $ do
    recSigPtr <- ContT (withForeignPtr recoverableSignatureFPtr)
    lift $ do
        outBuf <- mallocBytes 65
        recIdPtr <- malloc
        _ret <- Prim.ecdsaRecoverableSignatureSerializeCompact ctx outBuf recIdPtr recSigPtr
        recId <- peek recIdPtr
        unsafePackByteString (outBuf, 65)


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


ecdsaSignRecoverable :: SecKey -> ByteString -> Maybe RecoverableSignature
ecdsaSignRecoverable SecKey{..} bs
    | BS.length bs /= 32 = Nothing
    | otherwise = unsafePerformIO . evalContT $ do
        (msgHashPtr, _) <- ContT (unsafeUseByteString bs)
        secKeyPtr <- ContT (withForeignPtr secKeyFPtr)
        lift $ do
            recSigBuf <- mallocBytes 65
            ret <- Prim.ecdsaSignRecoverable ctx recSigBuf msgHashPtr secKeyPtr Prim.nonceFunctionDefault nullPtr
            if isSuccess ret
                then Just . RecoverableSignature <$> newForeignPtr finalizerFree recSigBuf
                else free recSigBuf $> Nothing


ecdsaRecover :: RecoverableSignature -> ByteString -> Maybe PubKeyXY
ecdsaRecover RecoverableSignature{..} msgHash
    | BS.length msgHash /= 32 = Nothing
    | otherwise = unsafePerformIO . evalContT $ do
        recSigPtr <- ContT (withForeignPtr recoverableSignatureFPtr)
        (msgHashPtr, _) <- ContT (unsafeUseByteString msgHash)
        lift $ do
            pubKeyBuf <- mallocBytes 64
            ret <- Prim.ecdsaRecover ctx pubKeyBuf recSigPtr msgHashPtr
            if isSuccess ret
                then Just . PubKeyXY <$> newForeignPtr finalizerFree pubKeyBuf
                else free pubKeyBuf $> Nothing


recSigToSig :: RecoverableSignature -> Signature
recSigToSig RecoverableSignature{..} = unsafePerformIO . evalContT $ do
    recSigPtr <- ContT (withForeignPtr recoverableSignatureFPtr)
    lift $ do
        sigBuf <- mallocBytes 64
        _ret <- Prim.ecdsaRecoverableSignatureConvert ctx sigBuf recSigPtr
        Signature <$> newForeignPtr finalizerFree sigBuf


derivePubKey :: SecKey -> PubKeyXY
derivePubKey (SecKey skFPtr) = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    ret <- withForeignPtr skFPtr $ Prim.ecPubkeyCreate ctx outBuf
    unless (isSuccess ret) $ do
        free outBuf
        error "Bug: Invalid SecKey Constructed"
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


keyPairCreate :: SecKey -> KeyPair
keyPairCreate SecKey{..} = unsafePerformIO $ do
    keyPairBuf <- mallocBytes 96
    ret <- withForeignPtr secKeyFPtr $ Prim.keypairCreate ctx keyPairBuf
    unless (isSuccess ret) $ do
        free keyPairBuf
        error "Bug: Invalid SecKey Constructed"
    KeyPair <$> newForeignPtr finalizerFree keyPairBuf


keyPairPubKeyXY :: KeyPair -> PubKeyXY
keyPairPubKeyXY KeyPair{..} = unsafePerformIO $ do
    pubKeyBuf <- mallocBytes 64
    ret <- withForeignPtr keyPairFPtr $ Prim.keypairPub ctx pubKeyBuf
    unless (isSuccess ret) $ do
        free pubKeyBuf
        error "Bug: Invalid KeyPair Constructed"
    PubKeyXY <$> newForeignPtr finalizerFree pubKeyBuf


keyPairSecKey :: KeyPair -> SecKey
keyPairSecKey KeyPair{..} = unsafePerformIO $ do
    secKeyBuf <- mallocBytes 32
    ret <- withForeignPtr keyPairFPtr $ Prim.keypairSec ctx secKeyBuf
    unless (isSuccess ret) $ do
        free secKeyBuf
        error "Bug: Invalid KeyPair Constructed"
    SecKey <$> newForeignPtr finalizerFree secKeyBuf


keyPairPubKeyXO :: KeyPair -> (PubKeyXO, Bool)
keyPairPubKeyXO KeyPair{..} = unsafePerformIO $ do
    pubKeyBuf <- mallocBytes 64
    parityPtr <- malloc
    ret <- withForeignPtr keyPairFPtr $ Prim.keypairXonlyPub ctx pubKeyBuf parityPtr
    unless (isSuccess ret) $ do
        free pubKeyBuf
        free parityPtr
        error "Bug: Invalid KeyPair Constructed"
    parity <- peek parityPtr
    negated <- case parity of
        0 -> pure False
        1 -> pure True
        _ -> do
            free pubKeyBuf
            free parityPtr
            error "Bug: Invalid pk_parity result from Prim"
    (,negated) . PubKeyXO <$> newForeignPtr finalizerFree pubKeyBuf


keyPairPubKeyXOTweakAdd :: KeyPair -> Tweak -> Maybe KeyPair
keyPairPubKeyXOTweakAdd KeyPair{..} Tweak{..} = unsafePerformIO . evalContT $ do
    keyPairPtr <- ContT (withForeignPtr keyPairFPtr)
    tweakPtr <- ContT (withForeignPtr tweakFPtr)
    lift $ do
        keyPairOut <- (mallocBytes 96)
        _ <- (memcpy keyPairOut keyPairPtr 96)
        ret <- Prim.keypairXonlyTweakAdd ctx keyPairOut tweakPtr
        if isSuccess ret
            then Just . KeyPair <$> newForeignPtr finalizerFree keyPairOut
            else free keyPairOut $> Nothing


schnorrSign :: KeyPair -> ByteString -> Maybe Signature
schnorrSign KeyPair{..} bs
    | BS.length bs /= 32 = Nothing
    | otherwise = unsafePerformIO . evalContT $ do
        (msgHashPtr, _) <- ContT (unsafeUseByteString bs)
        keyPairPtr <- ContT (withForeignPtr keyPairFPtr)
        lift $ do
            sigBuf <- mallocBytes 64
            -- TODO: provide randomness here instead of supplying a null pointer
            ret <- Prim.schnorrsigSign ctx sigBuf msgHashPtr keyPairPtr nullPtr
            if isSuccess ret
                then Just . Signature <$> newForeignPtr finalizerFree sigBuf
                else free sigBuf $> Nothing


data SchnorrExtra a = Storable a =>
    SchnorrExtra
    { schnorrExtraNonceFunHardened :: ByteString -> SecKey -> PubKeyXO -> ByteString -> a -> Maybe (SizedByteArray 32 ByteString)
    , schnorrExtraData :: a
    }
schnorrSignCustom :: forall a. KeyPair -> ByteString -> SchnorrExtra a -> Maybe Signature
schnorrSignCustom KeyPair{..} msg SchnorrExtra{..} = unsafePerformIO . evalContT $ do
    (msgPtr, msgLen) <- ContT (unsafeUseByteString msg)
    keyPairPtr <- ContT (withForeignPtr keyPairFPtr)
    lift $ do
        sigBuf <- mallocBytes 64
        -- convert fn into funptr
        funptr <- mkNonceFunHardened primFn
        -- allocate memory for extra data ptr
        dataptr <- malloc
        -- copy data to new pointer
        poke dataptr schnorrExtraData
        -- allocate extraparams structure
        extraPtr <- mallocBytes (4 + sizeOf funptr + sizeOf dataptr)
        -- fill magic
        pokeByteOff extraPtr 0 (0xDA :: Word8)
        pokeByteOff extraPtr 1 (0x6F :: Word8)
        pokeByteOff extraPtr 2 (0xB3 :: Word8)
        pokeByteOff extraPtr 3 (0x8C :: Word8)
        -- fill funptr
        pokeByteOff extraPtr 4 funptr
        -- fill dataptr
        pokeByteOff extraPtr (4 + sizeOf funptr) dataptr
        ret <- Prim.schnorrsigSignCustom ctx sigBuf msgPtr msgLen keyPairPtr extraPtr
        freeHaskellFunPtr funptr
        free dataptr
        free extraPtr
        if isSuccess ret
            then Just . Signature <$> newForeignPtr finalizerFree sigBuf
            else free sigBuf $> Nothing
    where
        primFn :: Storable a => Prim.NonceFunHardened a
        primFn outBuf msgPtr msgLen sk xopk algo algolen dataPtr = do
            msg <- unsafePackByteString (msgPtr, msgLen)
            sk <- SecKey <$> newForeignPtr_ (castPtr sk)
            xopk <- PubKeyXO <$> newForeignPtr_ (castPtr xopk)
            algo <- unsafePackByteString (algo, algolen)
            extra <- peek dataPtr
            case schnorrExtraNonceFunHardened msg sk xopk algo extra of
                Nothing -> pure 0
                Just bs -> evalContT $ do
                    (hashPtr, _) <- ContT (unsafeUseByteString (unSizedByteArray bs))
                    lift (memcpy outBuf hashPtr 32)
                    pure 1


schnorrVerify :: PubKeyXO -> ByteString -> Signature -> Bool
schnorrVerify PubKeyXO{..} bs Signature{..} = unsafePerformIO . evalContT $ do
    pubKeyPtr <- ContT (withForeignPtr pubKeyXOFPtr)
    signaturePtr <- ContT (withForeignPtr signatureFPtr)
    (msgPtr, msgLen) <- ContT (unsafeUseByteString bs)
    lift $ isSuccess <$> Prim.schnorrsigSignVerify ctx signaturePtr msgPtr msgLen pubKeyPtr


taggedSha256 :: ByteString -> ByteString -> Digest SHA256
taggedSha256 tag msg = unsafePerformIO . evalContT $ do
    (tagBuf, tagLen) <- ContT (unsafeUseByteString tag)
    (msgBuf, msgLen) <- ContT (unsafeUseByteString msg)
    lift $ do
        hashBuf <- mallocBytes 32
        ret <- Prim.taggedSha256 ctx hashBuf tagBuf tagLen msgBuf msgLen
        unless (isSuccess ret) $ do
            free hashBuf
            error "Bug: Invalid use of C Lib"
        bs <- unsafePackByteString (hashBuf, 32)
        let Just digest = digestFromByteString bs
        pure digest


pubKeyCombine :: [PubKeyXY] -> Maybe PubKeyXY
pubKeyCombine keys = unsafePerformIO $ do
    let n = length keys
    keysBuf <- mallocBytes (64 * n)
    for_ (zip [0 ..] keys) $ \(i, PubKeyXY{..}) ->
        withForeignPtr pubKeyXYFPtr $ pokeElemOff keysBuf i
    outBuf <- mallocBytes 64
    ret <- Prim.ecPubkeyCombine ctx outBuf keysBuf (fromIntegral n)
    if isSuccess ret
        then Just . PubKeyXY <$> newForeignPtr finalizerFree outBuf
        else free outBuf $> Nothing


pubKeyNegate :: PubKeyXY -> PubKeyXY
pubKeyNegate PubKeyXY{..} = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    withForeignPtr pubKeyXYFPtr $ flip (memcpy outBuf) 64
    _ret <- Prim.ecPubkeyNegate ctx outBuf
    PubKeyXY <$> newForeignPtr finalizerFree outBuf


pubKeyTweakAdd :: PubKeyXY -> Tweak -> Maybe PubKeyXY
pubKeyTweakAdd PubKeyXY{..} Tweak{..} = unsafePerformIO . evalContT $ do
    pubKeyPtr <- ContT (withForeignPtr pubKeyXYFPtr)
    tweakPtr <- ContT (withForeignPtr tweakFPtr)
    lift $ do
        pubKeyOutBuf <- mallocBytes 64
        memcpy pubKeyOutBuf pubKeyPtr 64
        ret <- Prim.ecPubkeyTweakAdd ctx pubKeyOutBuf tweakPtr
        if isSuccess ret
            then Just . PubKeyXY <$> newForeignPtr finalizerFree pubKeyOutBuf
            else free pubKeyOutBuf $> Nothing


pubKeyTweakMul :: PubKeyXY -> Tweak -> Maybe PubKeyXY
pubKeyTweakMul PubKeyXY{..} Tweak{..} = unsafePerformIO . evalContT $ do
    pubKeyPtr <- ContT (withForeignPtr pubKeyXYFPtr)
    tweakPtr <- ContT (withForeignPtr tweakFPtr)
    lift $ do
        pubKeyOutBuf <- mallocBytes 64
        memcpy pubKeyOutBuf pubKeyPtr 64
        ret <- Prim.ecPubkeyTweakMul ctx pubKeyOutBuf tweakPtr
        if isSuccess ret
            then Just . PubKeyXY <$> newForeignPtr finalizerFree pubKeyOutBuf
            else free pubKeyOutBuf $> Nothing


secKeyNegate :: SecKey -> SecKey
secKeyNegate SecKey{..} = unsafePerformIO $ do
    outBuf <- mallocBytes 32
    withForeignPtr secKeyFPtr $ flip (memcpy outBuf) 32
    _ret <- Prim.ecSeckeyNegate ctx outBuf
    SecKey <$> newForeignPtr finalizerFree outBuf


xyToXO :: PubKeyXY -> (PubKeyXO, Bool)
xyToXO PubKeyXY{..} = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    parityPtr <- malloc
    ret <- withForeignPtr pubKeyXYFPtr $ Prim.xonlyPubkeyFromPubkey ctx outBuf parityPtr
    unless (isSuccess ret) $ do
        free outBuf
        error "Bug: Couldn't convert xy to xo"
    parity <- peek parityPtr
    negated <- case parity of
        0 -> pure False
        1 -> pure True
        _ -> free outBuf *> error "Bug: Invalid pk_parity from Prim"
    (,negated) . PubKeyXO <$> newForeignPtr finalizerFree outBuf


pubKeyXOTweakAdd :: PubKeyXO -> Tweak -> Maybe PubKeyXY
pubKeyXOTweakAdd PubKeyXO{..} Tweak{..} = unsafePerformIO . evalContT $ do
    pubKeyXOPtr <- ContT (withForeignPtr pubKeyXOFPtr)
    tweakPtr <- ContT (withForeignPtr tweakFPtr)
    lift $ do
        outBuf <- mallocBytes 64
        ret <- Prim.xonlyPubkeyTweakAdd ctx outBuf pubKeyXOPtr tweakPtr
        if isSuccess ret
            then Just . PubKeyXY <$> newForeignPtr finalizerFree outBuf
            else free outBuf $> Nothing


pubKeyXOTweakAddCheck :: PubKeyXO -> Bool -> PubKeyXO -> Tweak -> Bool
pubKeyXOTweakAddCheck PubKeyXO{pubKeyXOFPtr = tweakedFPtr} parity PubKeyXO{pubKeyXOFPtr = origFPtr} Tweak{..} =
    unsafePerformIO . evalContT $ do
        tweakedPtr <- ContT (withForeignPtr tweakedFPtr)
        origPtr <- ContT (withForeignPtr origFPtr)
        tweakPtr <- ContT (withForeignPtr tweakFPtr)
        let parityInt = if parity then 1 else 0
        lift $ isSuccess <$> Prim.xonlyPubkeyTweakAddCheck ctx tweakedPtr parityInt origPtr tweakPtr


foreign import ccall "wrapper"
    mkNonceFunHardened :: Prim.NonceFunHardened a -> IO (FunPtr (Prim.NonceFunHardened a))
