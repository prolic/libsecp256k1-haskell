{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
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
module Crypto.Secp256k1 (
    -- * Core Types
    SecKey,
    PubKeyXY,
    PubKeyXO,
    KeyPair,
    Signature,
    RecoverableSignature,
    SchnorrSignature,
    Tweak,

    -- * Parsing and Serialization
    importSecKey,
    exportSecKey,
    importPubKeyXY,
    exportPubKeyXY,
    importPubKeyXO,
    exportPubKeyXO,
    importSignatureCompact,
    importSignatureDer,
    exportSignatureCompact,
    exportSignatureDer,
    importRecoverableSignature,
    exportRecoverableSignature,
    importSchnorrSignature,
    exportSchnorrSignature,
    importTweak,

    -- * ECDSA Operations
    ecdsaVerify,
    ecdsaSign,
    ecdsaSignRecoverable,
    ecdsaRecover,
    ecdsaNormalizeSignature,

    -- * Conversions
    recSigToSig,
    derivePubKey,
    keyPairCreate,
    keyPairSecKey,
    keyPairPubKeyXY,
    keyPairPubKeyXO,
    xyToXO,

    -- * Tweaks
    secKeyTweakAdd,
    secKeyTweakMul,
    keyPairPubKeyXOTweakAdd,
    pubKeyCombine,
    pubKeyNegate,
    secKeyNegate,
    tweakNegate,
    pubKeyTweakAdd,
    pubKeyTweakMul,
    pubKeyXOTweakAdd,
    pubKeyXOTweakAddCheck,

    -- * Schnorr Operations
    schnorrSign,
    schnorrSignDeterministic,
    schnorrSignNondeterministic,
    schnorrVerify,

    -- * Other
    taggedSha256,
    ecdh,
) where

import Control.Applicative (Alternative (..))
import Control.DeepSeq (NFData (..))
import Control.Monad (replicateM, unless, (<=<))
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Cont (ContT (..), evalContT)
import Crypto.Secp256k1.Internal
import Crypto.Secp256k1.Prim (flagsEcUncompressed)
import Crypto.Secp256k1.Prim qualified as Prim
import Data.ByteArray.Encoding qualified as BA
import Data.ByteArray.Sized
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as B8
import Data.ByteString.Unsafe (unsafePackCStringLen, unsafePackMallocCStringLen)
import Data.Char (isAlphaNum, isSpace)
import Data.Foldable (for_)
import Data.Functor (($>))
import Data.Hashable (Hashable (..))
import Data.Maybe (fromJust, fromMaybe, isJust, maybeToList)
import Data.Memory.PtrMethods (memCompare)
import Data.String (IsString (..))
import Foreign (
    Bits (..),
    ForeignPtr,
    FunPtr,
    Ptr,
    Storable,
    Word32,
    Word64,
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
import Foreign.Storable (Storable (..))
import GHC.Generics (Generic)
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafePerformIO)
import System.Random (StdGen, newStdGen, randoms, randomIO)
import Text.Read (
    Lexeme (String),
    lexP,
    parens,
    pfail,
    readPrec,
 )


-- | Secret Key
newtype SecKey = SecKey {secKeyFPtr :: ForeignPtr Prim.Seckey32}


instance Show SecKey where
    show sk = B8.unpack $ encodeBase16 $ exportSecKey sk
instance Read SecKey where
    readsPrec i cs = case decodeBase16 . B8.pack $ pre of
        Left e -> []
        Right a -> case importSecKey a of
            Nothing -> []
            Just x -> [(x, suf)]
        where
            (pre, suf) = Prelude.splitAt 64 (dropWhile isSpace cs)
instance Eq SecKey where
    sk == sk' = unsafePerformIO . evalContT $ do
        skp <- ContT $ withForeignPtr (secKeyFPtr sk)
        skp' <- ContT $ withForeignPtr (secKeyFPtr sk')
        (EQ ==) <$> lift (memCompare (castPtr skp) (castPtr skp') 32)
instance Ord SecKey where
    sk `compare` sk' = unsafePerformIO . evalContT $ do
        skp <- ContT $ withForeignPtr (secKeyFPtr sk)
        skp' <- ContT $ withForeignPtr (secKeyFPtr sk')
        lift (memCompare (castPtr skp) (castPtr skp') 32)
instance Hashable SecKey where
    hashWithSalt i k = hashWithSalt i $ exportSecKey k
instance NFData SecKey where
    rnf SecKey{..} = seq secKeyFPtr ()


-- | Public Key with both X and Y coordinates
newtype PubKeyXY = PubKeyXY {pubKeyXYFPtr :: ForeignPtr Prim.Pubkey64}


instance Show PubKeyXY where
    show pk = B8.unpack (encodeBase16 (exportPubKeyXY True pk))
instance Read PubKeyXY where
    readsPrec i cs = maybeToList $ case trimmed of
        ('0' : '2' : _) -> parseNextN 66 trimmed
        ('0' : '3' : _) -> parseNextN 66 trimmed
        ('0' : '4' : _) -> parseNextN 130 trimmed
        _ -> Nothing
        where
            trimmed = dropWhile isSpace cs
            hush x = case x of
                Left _ -> Nothing
                Right a -> Just a
            parseNextN n cs =
                let (key, rest) = Prelude.splitAt n cs
                 in (,rest) <$> (importPubKeyXY <=< hush . decodeBase16) (B8.pack key)
instance Eq PubKeyXY where
    pk == pk' = unsafePerformIO . evalContT $ do
        pkp <- ContT . withForeignPtr . pubKeyXYFPtr $ pk
        pkp' <- ContT . withForeignPtr . pubKeyXYFPtr $ pk'
        res <- lift (Prim.ecPubkeyCmp ctx pkp pkp')
        pure $ res == 0
instance Ord PubKeyXY where
    pk `compare` pk' = unsafePerformIO . evalContT $ do
        pkp <- ContT . withForeignPtr . pubKeyXYFPtr $ pk
        pkp' <- ContT . withForeignPtr . pubKeyXYFPtr $ pk'
        res <- lift (Prim.ecPubkeyCmp ctx pkp pkp')
        pure $ compare res 0
instance Hashable PubKeyXY where
    hashWithSalt i k = hashWithSalt i $ exportPubKeyXY True k
instance NFData PubKeyXY where
    rnf PubKeyXY{..} = seq pubKeyXYFPtr ()


-- | Public Key with only an X coordinate.
newtype PubKeyXO = PubKeyXO {pubKeyXOFPtr :: ForeignPtr Prim.XonlyPubkey64}


instance Show PubKeyXO where
    show pk = B8.unpack (encodeBase16 (exportPubKeyXO pk))
instance Read PubKeyXO where
    readsPrec i s = case decodeBase16 . B8.pack $ pre of
        Left e -> error s
        Right a -> maybeToList $ (,suf) <$> importPubKeyXO a
        where
            trimmed = dropWhile isSpace s
            (pre, suf) = Prelude.splitAt 64 trimmed
instance Eq PubKeyXO where
    pk == pk' = unsafePerformIO . evalContT $ do
        pkp <- ContT . withForeignPtr . pubKeyXOFPtr $ pk
        pkp' <- ContT . withForeignPtr . pubKeyXOFPtr $ pk'
        res <- lift (Prim.xonlyPubkeyCmp ctx pkp pkp')
        pure $ res == 0
instance Ord PubKeyXO where
    pk `compare` pk' = unsafePerformIO . evalContT $ do
        pkp <- ContT . withForeignPtr . pubKeyXOFPtr $ pk
        pkp' <- ContT . withForeignPtr . pubKeyXOFPtr $ pk'
        res <- lift (Prim.xonlyPubkeyCmp ctx pkp pkp')
        pure $ compare res 0
instance Hashable PubKeyXO where
    hashWithSalt i k = hashWithSalt i $ exportPubKeyXO k
instance NFData PubKeyXO where
    rnf PubKeyXO{..} = seq pubKeyXOFPtr ()


-- | Structure containing information equivalent to 'SecKey' and 'PubKeyXY'
newtype KeyPair = KeyPair {keyPairFPtr :: ForeignPtr Prim.Keypair96}


instance Eq KeyPair where
    kp == kp' = unsafePerformIO . evalContT $ do
        kpp <- ContT $ withForeignPtr (keyPairFPtr kp)
        kpp' <- ContT $ withForeignPtr (keyPairFPtr kp')
        (EQ ==) <$> lift (memCompare (castPtr kpp) (castPtr kpp') 96)
instance NFData KeyPair where
    rnf KeyPair{..} = seq keyPairFPtr ()


-- | Structure containing Signature (R,S) data.
newtype Signature = Signature {signatureFPtr :: ForeignPtr Prim.Sig64}


instance Show Signature where
    show sig = (B8.unpack . encodeBase16) (exportSignatureCompact sig)
instance Read Signature where
    readsPrec i cs = case decodeBase16 $ B8.pack token of
        Left e -> []
        Right a -> maybeToList $ (,rest) <$> (importSignatureCompact a <|> importSignatureDer a)
        where
            trimmed = dropWhile isSpace cs
            (token, rest) = span isAlphaNum trimmed
instance Eq Signature where
    sig == sig' = unsafePerformIO . evalContT $ do
        sigp <- ContT $ withForeignPtr (signatureFPtr sig)
        sigp' <- ContT $ withForeignPtr (signatureFPtr sig')
        (EQ ==) <$> lift (memCompare (castPtr sigp) (castPtr sigp') 64)
instance NFData Signature where
    rnf Signature{..} = seq signatureFPtr ()


-- | Structure containing Schnorr Signature
newtype SchnorrSignature = SchnorrSignature {schnorrSignatureFPtr :: ForeignPtr Prim.Sig64}


instance Show SchnorrSignature where
    show sig = (B8.unpack . encodeBase16) (exportSchnorrSignature sig)
instance Read SchnorrSignature where
    readsPrec i cs = case decodeBase16 $ B8.pack token of
        Left e -> []
        Right a -> maybeToList $ (,rest) <$> importSchnorrSignature a
        where
            trimmed = dropWhile isSpace cs
            (token, rest) = span isAlphaNum trimmed
instance Eq SchnorrSignature where
    sig == sig' = unsafePerformIO . evalContT $ do
        sigp <- ContT $ withForeignPtr (schnorrSignatureFPtr sig)
        sigp' <- ContT $ withForeignPtr (schnorrSignatureFPtr sig')
        (EQ ==) <$> lift (memCompare (castPtr sigp) (castPtr sigp') 64)
instance NFData SchnorrSignature where
    rnf SchnorrSignature{..} = seq schnorrSignatureFPtr ()


-- | Structure containing Signature AND recovery ID
newtype RecoverableSignature = RecoverableSignature {recoverableSignatureFPtr :: ForeignPtr Prim.RecSig65}


instance Show RecoverableSignature where
    show recSig = (B8.unpack . encodeBase16) (exportRecoverableSignature recSig)
instance Read RecoverableSignature where
    readsPrec i cs = case decodeBase16 $ B8.pack token of
        Left e -> error . show $ trimmed
        Right a -> maybeToList $ (,rest) <$> importRecoverableSignature a
        where
            trimmed = dropWhile isSpace cs
            (token, rest) = span isAlphaNum trimmed
instance Eq RecoverableSignature where
    rs == rs' = unsafePerformIO . evalContT $ do
        rsp <- ContT $ withForeignPtr (recoverableSignatureFPtr rs)
        rsp' <- ContT $ withForeignPtr (recoverableSignatureFPtr rs')
        (EQ ==) <$> lift (memCompare (castPtr rsp) (castPtr rsp') 65)
instance NFData RecoverableSignature where
    rnf RecoverableSignature{..} = seq recoverableSignatureFPtr ()


-- | Isomorphic to 'SecKey' but specifically used for tweaking (EC Group operations) other keys
newtype Tweak = Tweak {tweakFPtr :: ForeignPtr Prim.Tweak32}


instance Show Tweak where
    show (Tweak fptr) = show (SecKey $ castForeignPtr fptr)
instance Read Tweak where
    readsPrec i cs = case decodeBase16 . B8.pack $ pre of
        Left e -> []
        Right a -> case importTweak a of
            Nothing -> []
            Just x -> [(x, suf)]
        where
            (pre, suf) = Prelude.splitAt 64 (dropWhile isSpace cs)


instance Eq Tweak where
    sk == sk' = unsafePerformIO . evalContT $ do
        skp <- ContT $ withForeignPtr (tweakFPtr sk)
        skp' <- ContT $ withForeignPtr (tweakFPtr sk')
        (EQ ==) <$> lift (memCompare (castPtr skp) (castPtr skp') 32)
instance Ord Tweak where
    sk `compare` sk' = unsafePerformIO . evalContT $ do
        skp <- ContT $ withForeignPtr (tweakFPtr sk)
        skp' <- ContT $ withForeignPtr (tweakFPtr sk')
        lift (memCompare (castPtr skp) (castPtr skp') 32)
instance NFData Tweak where
    rnf Tweak{..} = seq tweakFPtr ()


-- | Preinitialized context for signing and verification
ctx :: Prim.Ctx
ctx = unsafePerformIO $ Prim.contextCreate (Prim.flagsContextSign .|. Prim.flagsContextVerify)
{-# NOINLINE ctx #-}


-- | Parses 'SecKey', will be @Nothing@ if the @ByteString@ corresponds to 0{32} or is not 32 bytes in length
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


exportSecKey :: SecKey -> ByteString
exportSecKey SecKey{..} = unsafePerformIO . evalContT $ do
    secKeyPtr <- ContT (withForeignPtr secKeyFPtr)
    lift $ packByteString (secKeyPtr, 32)


-- | Parses a 33 or 65 byte 'PubKeyXY', all other lengths will result in @Nothing@
importPubKeyXY :: ByteString -> Maybe PubKeyXY
importPubKeyXY bs = unsafePerformIO . evalContT $ do
    (input, len) <- ContT (unsafeUseByteString bs)
    lift $ do
        if len == 33 || len == 65
            then do
                pubkeyOutputBuf <- mallocBytes 64
                ret <- Prim.ecPubkeyParse ctx pubkeyOutputBuf input len
                if isSuccess ret
                    then Just . PubKeyXY <$> newForeignPtr finalizerFree pubkeyOutputBuf
                    else free pubkeyOutputBuf $> Nothing
            else pure Nothing


-- | Serialize 'PubKeyXY'. First argument @True@ for compressed output (33 bytes), @False@ for uncompressed (65 bytes).
exportPubKeyXY :: Bool -> PubKeyXY -> ByteString
exportPubKeyXY compress PubKeyXY{..} = unsafePerformIO . evalContT $ do
    let flags = if compress then Prim.flagsEcCompressed else Prim.flagsEcUncompressed
    let sz = if compress then 33 else 65
    ptr <- ContT (withForeignPtr pubKeyXYFPtr)
    written <- ContT alloca
    lift $ do
        poke written (fromIntegral sz)
        buf <- mallocBytes sz
        -- always succeeds so we don't need to check
        _ret <- Prim.ecPubkeySerialize ctx buf written ptr flags
        len <- peek written
        unsafePackMallocCStringLen (castPtr buf, fromIntegral len)


-- | Parses 'PubKeyXO' from @ByteString@, will be @Nothing@ if the pubkey corresponds to the Point at Infinity or the
-- the @ByteString@ is not 32 bytes long
importPubKeyXO :: ByteString -> Maybe PubKeyXO
importPubKeyXO bs
    | BS.length bs /= 32 = Nothing
    | otherwise = unsafePerformIO $ do
        outBuf <- mallocBytes 64
        unsafeUseByteString bs $ \(ptr, _) -> do
            ret <- Prim.xonlyPubkeyParse ctx outBuf ptr
            if isSuccess ret
                then Just . PubKeyXO <$> newForeignPtr finalizerFree outBuf
                else free outBuf $> Nothing


-- | Serializes 'PubKeyXO' to 32 byte @ByteString@
exportPubKeyXO :: PubKeyXO -> ByteString
exportPubKeyXO (PubKeyXO pkFPtr) = unsafePerformIO $ do
    outBuf <- mallocBytes 32
    _ret <- withForeignPtr pkFPtr $ Prim.xonlyPubkeySerialize ctx outBuf
    unsafePackByteString (outBuf, 32)


-- | Parses 'Signature' from Compact (64 bytes) representation.
importSignatureCompact :: ByteString -> Maybe Signature
importSignatureCompact bs = unsafePerformIO $
    unsafeUseByteString bs $ \(inBuf, len) -> do
        outBuf <- mallocBytes 64
        ret <-
            if len == 64
                -- compact
                then Prim.ecdsaSignatureParseCompact ctx outBuf inBuf
                -- invalid
                else pure 0
        if isSuccess ret
            then Just . Signature <$> newForeignPtr finalizerFree outBuf
            else free outBuf $> Nothing


-- | Parses 'Signature' from DER representation.
importSignatureDer :: ByteString -> Maybe Signature
importSignatureDer bs = unsafePerformIO $
    unsafeUseByteString bs $ \(inBuf, len) -> do
        outBuf <- mallocBytes 64
        ret <- Prim.ecdsaSignatureParseDer ctx outBuf inBuf len
        if isSuccess ret
            then Just . Signature <$> newForeignPtr finalizerFree outBuf
            else pure Nothing


-- | Serializes 'Signature' to Compact (64 byte) representation
exportSignatureCompact :: Signature -> ByteString
exportSignatureCompact (Signature fptr) = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    -- always succeeds
    _ret <- withForeignPtr fptr $ Prim.ecdsaSignatureSerializeCompact ctx outBuf
    unsafePackByteString (outBuf, 64)


-- | Serializes 'Signature' to DER (71 | 72 bytes) representation
exportSignatureDer :: Signature -> ByteString
exportSignatureDer (Signature fptr) = unsafePerformIO $ do
    -- as of Q4'2015 73 byte sigs became nonstandard so we will never create one that big
    outBuf <- mallocBytes 72
    alloca $ \written -> do
        poke written 72
        -- always succeeds
        _ret <- withForeignPtr fptr $ Prim.ecdsaSignatureSerializeDer ctx outBuf written
        len <- peek written
        unsafePackByteString (outBuf, len)


-- | Parses 'RecoverableSignature' from Compact (65 byte) representation
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


-- | Serializes 'RecoverableSignature' to Compact (65 byte) representation
exportRecoverableSignature :: RecoverableSignature -> ByteString
exportRecoverableSignature RecoverableSignature{..} = unsafePerformIO . evalContT $ do
    recSigPtr <- ContT (withForeignPtr recoverableSignatureFPtr)
    lift $ do
        outBuf <- mallocBytes 65
        recIdPtr <- malloc
        _ret <- Prim.ecdsaRecoverableSignatureSerializeCompact ctx outBuf recIdPtr recSigPtr
        recId <- peek recIdPtr
        pokeByteOff outBuf 64 recId
        unsafePackByteString (outBuf, 65)


-- | Parses 'SchnorrSignature' from Schnorr (64 byte) representation
importSchnorrSignature :: ByteString -> Maybe SchnorrSignature
importSchnorrSignature bs
    | BS.length bs /= 64 = Nothing
    | otherwise = unsafePerformIO $ do
        outBuf <- mallocBytes 64
        unsafeUseByteString bs $ \(ptr, _) -> do
            memcpy outBuf ptr 64
        Just . SchnorrSignature <$> newForeignPtr finalizerFree outBuf


-- | Serializes 'SchnorrSignature' to Schnorr (64 byte) representation
exportSchnorrSignature :: SchnorrSignature -> ByteString
exportSchnorrSignature (SchnorrSignature fptr) = unsafePerformIO $
    withForeignPtr fptr $ \ptr -> BS.packCStringLen (castPtr ptr, 64)


-- | Parses 'Tweak' from 32 byte @ByteString@. If the @ByteString@ is an invalid 'SecKey' then this will yield @Nothing@
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


-- | Signs @ByteString@ with 'SecKey' only if @ByteString@ is 32 bytes.
ecdsaSign :: SecKey -> ByteString -> Maybe Signature
ecdsaSign (SecKey skFPtr) msgHash
    | BS.length msgHash /= 32 = Nothing
    | otherwise = unsafePerformIO . evalContT $ do
        skPtr <- ContT (withForeignPtr skFPtr)
        (msgHashPtr, _) <- ContT (unsafeUseByteString msgHash)
        lift $ do
            sigBuf <- mallocBytes 64
            ret <- Prim.ecdsaSign ctx sigBuf msgHashPtr skPtr Prim.nonceFunctionDefault nullPtr
            if isSuccess ret
                then Just . Signature <$> newForeignPtr finalizerFree sigBuf
                else free sigBuf $> Nothing


-- | Signs @ByteString@ with 'SecKey' only if @ByteString@ is 32 bytes. Retains ability to compute 'PubKeyXY' from the
-- 'RecoverableSignature' and the original message (@ByteString@)
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


-- | Computes 'PubKeyXY' from 'RecoverableSignature' and the original message that was signed (must be 32 bytes).
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


-- | Convert a 'Signature' to a normalized lower-S form. If the 'Signature' was already in its lower-S form it will
-- be equal to the input.
ecdsaNormalizeSignature :: Signature -> Signature
ecdsaNormalizeSignature Signature{..} = unsafePerformIO . evalContT $ do
    sigPtr <- ContT (withForeignPtr signatureFPtr)
    lift $ do
        outBuf <- mallocBytes 64
        _ret <- Prim.ecdsaSignatureNormalize ctx outBuf sigPtr
        Signature <$> newForeignPtr finalizerFree outBuf


-- | Forgets the recovery id of a signature
recSigToSig :: RecoverableSignature -> Signature
recSigToSig RecoverableSignature{..} = unsafePerformIO . evalContT $ do
    recSigPtr <- ContT (withForeignPtr recoverableSignatureFPtr)
    lift $ do
        sigBuf <- mallocBytes 64
        _ret <- Prim.ecdsaRecoverableSignatureConvert ctx sigBuf recSigPtr
        Signature <$> newForeignPtr finalizerFree sigBuf


-- | Use 'SecKey' to compute the corresponding 'PubKeyXY'
derivePubKey :: SecKey -> PubKeyXY
derivePubKey (SecKey skFPtr) = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    ret <- withForeignPtr skFPtr $ Prim.ecPubkeyCreate ctx outBuf
    unless (isSuccess ret) $ do
        free outBuf
        error "Bug: Invalid SecKey Constructed"
    PubKeyXY <$> newForeignPtr finalizerFree outBuf


-- | Compute a shared secret using ECDH and SHA256. This algorithm uses your own 'SecKey', your counterparty's 'PubKeyXY'
-- and results in a 32 byte SHA256 Digest.
ecdh :: SecKey -> PubKeyXY -> SizedByteArray 32 ByteString
ecdh SecKey{..} PubKeyXY{..} = unsafePerformIO . evalContT $ do
    outBuf <- lift (mallocBytes 32)
    sk <- ContT (withForeignPtr secKeyFPtr)
    pk <- ContT (withForeignPtr pubKeyXYFPtr)
    ret <- lift (Prim.ecdh ctx outBuf pk sk Prim.ecdhHashFunctionSha256 nullPtr)
    if isSuccess ret
        then do
            bs <- lift $ unsafePackByteString (outBuf, 32)
            let Just digest = sizedByteArray bs
            pure digest
        else lift (free outBuf) *> error "Bug: Invalid Scalar or Overflow"


-- | Add 'Tweak' to 'SecKey'.
secKeyTweakAdd :: SecKey -> Tweak -> Maybe SecKey
secKeyTweakAdd SecKey{..} Tweak{..} = unsafePerformIO . evalContT $ do
    skPtr <- ContT (withForeignPtr secKeyFPtr)
    skOut <- lift (mallocBytes 32)
    lift (memcpy skOut skPtr 32)
    twkPtr <- ContT (withForeignPtr tweakFPtr)
    ret <- lift (Prim.ecSeckeyTweakAdd ctx skOut twkPtr)
    lift $
        if isSuccess ret
            then Just . SecKey <$> newForeignPtr finalizerFree skOut
            else free skOut $> Nothing


-- | Multiply 'SecKey' by 'Tweak'.
secKeyTweakMul :: SecKey -> Tweak -> Maybe SecKey
secKeyTweakMul SecKey{..} Tweak{..} = unsafePerformIO . evalContT $ do
    skPtr <- ContT (withForeignPtr secKeyFPtr)
    skOut <- lift (mallocBytes 32)
    lift (memcpy skOut skPtr 32)
    twkPtr <- ContT (withForeignPtr tweakFPtr)
    ret <- lift (Prim.ecSeckeyTweakMul ctx skOut twkPtr)
    lift $
        if isSuccess ret
            then Just . SecKey <$> newForeignPtr finalizerFree skOut
            else free skOut $> Nothing


-- | Compute 'KeyPair' structure from 'SecKey'
keyPairCreate :: SecKey -> KeyPair
keyPairCreate SecKey{..} = unsafePerformIO $ do
    keyPairBuf <- mallocBytes 96
    ret <- withForeignPtr secKeyFPtr $ Prim.keypairCreate ctx keyPairBuf
    unless (isSuccess ret) $ do
        free keyPairBuf
        error "Bug: Invalid SecKey Constructed"
    KeyPair <$> newForeignPtr finalizerFree keyPairBuf


-- | Project 'PubKeyXY' from 'KeyPair'
keyPairPubKeyXY :: KeyPair -> PubKeyXY
keyPairPubKeyXY KeyPair{..} = unsafePerformIO $ do
    pubKeyBuf <- mallocBytes 64
    ret <- withForeignPtr keyPairFPtr $ Prim.keypairPub ctx pubKeyBuf
    unless (isSuccess ret) $ do
        free pubKeyBuf
        error "Bug: Invalid KeyPair Constructed"
    PubKeyXY <$> newForeignPtr finalizerFree pubKeyBuf


-- | Project 'SecKey' from 'KeyPair'
keyPairSecKey :: KeyPair -> SecKey
keyPairSecKey KeyPair{..} = unsafePerformIO $ do
    secKeyBuf <- mallocBytes 32
    ret <- withForeignPtr keyPairFPtr $ Prim.keypairSec ctx secKeyBuf
    unless (isSuccess ret) $ do
        free secKeyBuf
        error "Bug: Invalid KeyPair Constructed"
    SecKey <$> newForeignPtr finalizerFree secKeyBuf


-- | Project 'PubKeyXO' from 'KeyPair' as well as parity bit. @True@ indicates that the public key is the same as it
-- would be if you had serialized the 'PubKeyXO' and it was prefixed with 'Prim.flagsTagPubkeyOdd'. @False@ indicates
-- it would be prefixed by 'Prim.flagsTagPubkeyEven'
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


-- | Tweak a 'KeyPair' with a 'Tweak'. If the resulting 'KeyPair' is invalid (0, Infinity), then the result is @Nothing@
keyPairPubKeyXOTweakAdd :: KeyPair -> Tweak -> Maybe KeyPair
keyPairPubKeyXOTweakAdd KeyPair{..} Tweak{..} = unsafePerformIO . evalContT $ do
    keyPairPtr <- ContT (withForeignPtr keyPairFPtr)
    tweakPtr <- ContT (withForeignPtr tweakFPtr)
    lift $ do
        keyPairOut <- mallocBytes 96
        _ <- memcpy keyPairOut keyPairPtr 96
        ret <- Prim.keypairXonlyTweakAdd ctx keyPairOut tweakPtr
        if isSuccess ret
            then Just . KeyPair <$> newForeignPtr finalizerFree keyPairOut
            else free keyPairOut $> Nothing


-- | Compute a schnorr signature using a 'KeyPair'. The @ByteString@ must be 32 bytes long to get 
-- a @Just@ out of this function. Optionally takes a 'StdGen' for deterministic signing.
schnorrSign :: Maybe StdGen -> KeyPair -> ByteString -> Maybe SchnorrSignature
schnorrSign mGen KeyPair{..} bs
    | BS.length bs /= 32 = Nothing
    | otherwise = unsafePerformIO . evalContT $ do
        (msgHashPtr, _) <- ContT (unsafeUseByteString bs)
        keyPairPtr <- ContT (withForeignPtr keyPairFPtr)
        lift $ do
            sigBuf <- mallocBytes 64
            ret <- case mGen of
                Just gen -> do
                    let randomBytes = BS.pack $ Prelude.take 32 $ randoms gen
                    BS.useAsCStringLen randomBytes $ \(ptr, _) ->
                        Prim.schnorrsigSign ctx sigBuf msgHashPtr keyPairPtr (castPtr ptr)
                Nothing ->
                    Prim.schnorrsigSign ctx sigBuf msgHashPtr keyPairPtr nullPtr
            if isSuccess ret
                then Just . SchnorrSignature <$> newForeignPtr finalizerFree sigBuf
                else do
                    free sigBuf
                    return Nothing


-- | Compute a deterministic schnorr signature using a 'KeyPair'.
schnorrSignDeterministic :: KeyPair -> ByteString -> Maybe SchnorrSignature
schnorrSignDeterministic = schnorrSign Nothing


-- | Compute a non-deterministic schnorr signature using a 'KeyPair'.
schnorrSignNondeterministic :: KeyPair -> ByteString -> IO (Maybe SchnorrSignature)
schnorrSignNondeterministic kp bs = newStdGen >>= \gen -> pure $ schnorrSign (Just gen) kp bs


-- | Verify the authenticity of a schnorr signature. @True@ means the 'Signature' is correct.
schnorrVerify :: PubKeyXO -> ByteString -> SchnorrSignature -> Bool
schnorrVerify PubKeyXO{..} bs SchnorrSignature{..} = unsafePerformIO . evalContT $ do
    pubKeyPtr <- ContT (withForeignPtr pubKeyXOFPtr)
    schnorrSignaturePtr <- ContT (withForeignPtr schnorrSignatureFPtr)
    (msgPtr, msgLen) <- ContT (unsafeUseByteString bs)
    lift $ isSuccess <$> Prim.schnorrsigSignVerify ctx schnorrSignaturePtr msgPtr msgLen pubKeyPtr


-- | Generate a tagged sha256 digest as specified in BIP340
taggedSha256 :: ByteString -> ByteString -> SizedByteArray 32 ByteString
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
        let Just digest = sizedByteArray bs
        pure digest


-- | Combine a list of 'PubKeyXY's into a single 'PubKeyXY'. This will result in @Nothing@ if the group operation results
-- in the Point at Infinity
pubKeyCombine :: [PubKeyXY] -> Maybe PubKeyXY
pubKeyCombine keys@(_ : _) = unsafePerformIO $ do
    let n = length keys
    keysBuf <- mallocBytes (64 * n)
    for_ (zip [0 ..] keys) $ \(i, PubKeyXY{..}) ->
        withForeignPtr pubKeyXYFPtr $ pokeElemOff keysBuf i
    outBuf <- mallocBytes 64
    ret <- Prim.ecPubkeyCombine ctx outBuf keysBuf (fromIntegral n)
    if isSuccess ret
        then Just . PubKeyXY <$> newForeignPtr finalizerFree outBuf
        else free outBuf $> Nothing
pubKeyCombine [] = Nothing


-- | Negate a 'PubKeyXY'
pubKeyNegate :: PubKeyXY -> PubKeyXY
pubKeyNegate PubKeyXY{..} = unsafePerformIO $ do
    outBuf <- mallocBytes 64
    withForeignPtr pubKeyXYFPtr $ flip (memcpy outBuf) 64
    _ret <- Prim.ecPubkeyNegate ctx outBuf
    PubKeyXY <$> newForeignPtr finalizerFree outBuf


-- | Add 'Tweak' to 'PubKeyXY'. This will result in @Nothing@ if the group operation results in the Point at Infinity
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


-- | Multiply 'PubKeyXY' by 'Tweak'. This will result in @Nothing@ if the group operation results in the Point at Infinity
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


-- | Negate a 'SecKey'
secKeyNegate :: SecKey -> SecKey
secKeyNegate SecKey{..} = unsafePerformIO $ do
    outBuf <- mallocBytes 32
    withForeignPtr secKeyFPtr $ flip (memcpy outBuf) 32
    _ret <- Prim.ecSeckeyNegate ctx outBuf
    SecKey <$> newForeignPtr finalizerFree outBuf


-- | Negate a 'Tweak'
tweakNegate :: Tweak -> Tweak
tweakNegate Tweak{..} = unsafePerformIO $ do
    outBuf <- mallocBytes 32
    let asKey = castForeignPtr tweakFPtr
    withForeignPtr asKey $ flip (memcpy outBuf) 32
    _ret <- Prim.ecSeckeyNegate ctx outBuf
    Tweak <$> newForeignPtr finalizerFree (castPtr outBuf)


-- | Convert 'PubKeyXY' to 'PubKeyXO'. See 'keyPairPubKeyXO' for more information on how to interpret the parity bit.
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


-- | Add 'Tweak' to 'PubKeyXO'. This will result in @Nothing@ if the group operation results in the Point at Infinity
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


-- | Check that a 'PubKeyXO' is the result of the specified tweak operation. @True@ means it was.
pubKeyXOTweakAddCheck :: PubKeyXO -> Bool -> PubKeyXO -> Tweak -> Bool
pubKeyXOTweakAddCheck PubKeyXO{pubKeyXOFPtr = tweakedFPtr} parity PubKeyXO{pubKeyXOFPtr = origFPtr} Tweak{..} =
    unsafePerformIO . evalContT $ do
        tweakedPtr <- ContT (withForeignPtr tweakedFPtr)
        origPtr <- ContT (withForeignPtr origFPtr)
        tweakPtr <- ContT (withForeignPtr tweakFPtr)
        let parityInt = if parity then 1 else 0
        lift $ isSuccess <$> Prim.xonlyPubkeyTweakAddCheck ctx tweakedPtr parityInt origPtr tweakPtr
