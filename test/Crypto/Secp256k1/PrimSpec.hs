{-# LANGUAGE OverloadedStrings #-}

module Crypto.Secp256k1.PrimSpec (spec) where

import Control.Monad

import Control.Monad.IO.Class
import Control.Monad.Trans.Cont
import Crypto.Secp256k1.Internal
import Crypto.Secp256k1.Prim
import Data.ByteArray.Encoding qualified as BA
import Data.ByteString (
    ByteString,
    copy,
    packCStringLen,
    useAsCString,
    useAsCStringLen,
 )
import Data.Either (fromRight)
import Foreign
import System.Entropy
import Test.HUnit (Assertion, assertBool, assertEqual)
import Test.Hspec


spec :: Spec
spec = do
    describe "housekeeping" $ do
        it "creates context" createContextTest
        it "randomizes context" randomizeContextTest
        it "clones context" cloneContextTest
    describe "serialization" $ do
        it "parses public key" ecPubkeyParseTest
        it "serializes public key" ecPubKeySerializeTest
        it "parses DER signature" ecdsaSignatureParseDerTest
        it "serializes DER signature" ecdsaSignatureSerializeDerTest
    describe "signatures" $ do
        it "verifies signature" ecdsaVerifyTest
        it "signs message" ecdsaSignTest
    describe "secret keys" $ do
        it "verifies secret key" ecSecKeyVerifyTest
        it "creates public key" ecPubkeyCreateTest
        it "adds secret key" ecSecKeyTweakAddTest
        it "multiplies secret key" ecSecKeyTweakMulTest
    describe "public keys" $ do
        it "adds public key" ecPubKeyTweakAddTest
        it "multiplies public key" ecPubKeyTweakMulTest
        it "combines public keys" ecPubKeyCombineTest


flagsSignVerify :: ContextFlags
flagsSignVerify = flagsContextSign .|. flagsContextVerify


withEntropy :: (Ptr Seed32 -> IO a) -> IO a
withEntropy f =
    getEntropy 32 >>= \e ->
        useByteString e $ \(s, _) -> f s


createContextTest :: Assertion
createContextTest = do
    context_ptr <- liftIO $ contextCreate flagsSignVerify
    assertBool "context not null" $ context_ptr /= nullPtr


randomizeContextTest :: Assertion
randomizeContextTest = do
    ret <- liftIO $ contextCreate flagsContextSign >>= withEntropy . contextRandomize
    assertBool "context randomized" $ isSuccess ret


cloneContextTest :: Assertion
cloneContextTest = do
    (x1, x2) <- liftIO $ do
        x1 <- contextCreate flagsSignVerify
        ret <- withEntropy $ contextRandomize x1
        unless (isSuccess ret) $ error "failed to randomize context"
        x2 <- contextClone x1
        return (x1, x2)
    assertBool "original context not null" $ x1 /= nullPtr
    assertBool "cloned context not null" $ x2 /= nullPtr
    assertBool "context ptrs different" $ x1 /= x2


ecPubkeyParseTest :: Assertion
ecPubkeyParseTest = evalContT $ do
    (i, il) <- ContT (useAsCStringLen der)
    pubkey <- ContT (allocaBytes 64)
    liftIO $ do
        x <- contextCreate flagsContextVerify
        ret <- ecPubkeyParse x pubkey (castPtr i) (fromIntegral il)
        assertBool "parsed public key" (isSuccess ret)
    where
        der =
            fromRight undefined $
                decodeBase16
                    "03dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705"


ecPubKeySerializeTest :: Assertion
ecPubKeySerializeTest = evalContT $ do
    (i, il) <- ContT (useByteString der)
    k <- ContT (allocaBytes 64)
    ol <- ContT alloca
    o <- ContT (allocaBytes 72)
    liftIO $ do
        poke ol 72
        x <- contextCreate flagsContextVerify
        ret1 <- ecPubkeyParse x k i il
        unless (isSuccess ret1) $ error "failed to parse pubkey"
        ret2 <- ecPubkeySerialize x o ol k flagsEcCompressed
        len <- fromIntegral <$> peek ol
        decoded <- packCStringLen (castPtr o, len)

        assertBool "serialized public key successfully" $ isSuccess ret2
        assertEqual "public key matches" der decoded
    where
        der =
            fromRight undefined $
                decodeBase16
                    "03dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705"


ecdsaSignatureParseDerTest :: Assertion
ecdsaSignatureParseDerTest = evalContT $ do
    (d, dl) <- ContT (useAsCStringLen der)
    s <- ContT (allocaBytes 64)
    liftIO $ do
        x <- contextCreate flagsContextVerify
        ret <- ecdsaSignatureParseDer x s (castPtr d) (fromIntegral dl)
        assertBool "parsed signature successfully" $ isSuccess ret
    where
        der =
            fromRight undefined $
                decodeBase16
                    "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
                    \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
                    \45"


parseDer :: Ctx -> ByteString -> IO ByteString
parseDer x bs = evalContT $ do
    (d, dl) <- ContT (useAsCStringLen bs)
    s <- ContT (allocaBytes 64)
    liftIO $ do
        ret <- ecdsaSignatureParseDer x s (castPtr d) (fromIntegral dl)
        unless (isSuccess ret) $ error "could not parse DER"
        packByteString (s, 64)


ecdsaSignatureSerializeDerTest :: Assertion
ecdsaSignatureSerializeDerTest = evalContT $ do
    ol <- ContT alloca
    o <- ContT (allocaBytes 72)
    x <- liftIO $ contextCreate flagsContextVerify
    sig <- liftIO $ parseDer x der
    (s, _) <- ContT (useByteString sig)
    liftIO $ do
        poke ol 72
        ret <- ecdsaSignatureSerializeDer x o ol s
        len <- fromIntegral <$> peek ol
        enc <- packCStringLen (castPtr o, len)
        assertBool "serialization successful" $ isSuccess ret
        assertEqual "signatures match" der enc
    where
        der =
            fromRight undefined $
                decodeBase16
                    "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
                    \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
                    \45"


ecdsaVerifyTest :: Assertion
ecdsaVerifyTest = evalContT $ do
    (p, pl) <- ContT (useByteString pub)
    (m, _) <- ContT (useByteString msg)
    k <- ContT (allocaBytes 64)
    (x, pk, sig) <- liftIO $ do
        x <- contextCreate flagsContextVerify
        ret <- ecPubkeyParse x k p (fromIntegral pl)
        sig <- parseDer x der
        unless (isSuccess ret) $ error "could not parse public key"
        pk <- packByteString (k, 64)
        pure (x, pk, sig)

    (k, _) <- ContT (useByteString pk)
    (s, _) <- ContT (useByteString sig)
    ret <- liftIO $ ecdsaVerify x s m k
    liftIO $ assertBool "signature valid" $ isSuccess ret
    where
        der =
            fromRight undefined $
                decodeBase16
                    "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
                    \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
                    \45"
        pub =
            fromRight undefined $
                decodeBase16
                    "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
                    \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
        msg =
            fromRight undefined $
                decodeBase16
                    "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"


signCtx :: IO Ctx
signCtx = do
    c <- contextCreate flagsContextSign
    r <- withEntropy (contextRandomize c)
    unless (isSuccess r) (error "failed to randomize context")
    pure c


createPubKey :: Ctx -> Ptr Seckey32 -> Ptr Pubkey64 -> IO ()
createPubKey x k p = do
    ret <- ecPubkeyCreate x p k
    unless (isSuccess ret) $ error "failed to create public key"


ecdsaSignTest :: Assertion
ecdsaSignTest = do
    x <- signCtx
    der <- evalContT $ do
        s <- ContT (allocaBytes 64)
        (m, _) <- ContT (useByteString msg)
        (k, _) <- ContT (useByteString key)
        ol <- ContT alloca
        o <- ContT (allocaBytes 72)
        liftIO $ do
            poke ol 72
            ret1 <- ecdsaSign x s m k nullFunPtr nullPtr
            unless (isSuccess ret1) $ error "could not sign message"
            ret2 <- ecdsaSignatureSerializeDer x o ol s
            unless (isSuccess ret2) $ error "could not serialize signature"
            len <- peek ol
            packCStringLen (castPtr o, fromIntegral len)
    ret <- evalContT $ do
        p <- ContT (allocaBytes 64)
        (s, _) <- ContT (useByteString key)
        (m, _) <- ContT (useByteString msg)
        pub <- liftIO $ do
            x <- signCtx
            createPubKey x s p
            packByteString (p, 64)
        (p, _) <- ContT (useByteString pub)
        x <- liftIO $ contextCreate flagsContextVerify
        s' <- liftIO $ parseDer x der
        (s, _) <- ContT (useByteString s')
        liftIO $ ecdsaVerify x s m p
    assertBool "signature matches" (isSuccess ret)
    where
        msg =
            fromRight undefined $
                decodeBase16
                    "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        key =
            fromRight undefined $
                decodeBase16
                    "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"


ecSecKeyVerifyTest :: Assertion
ecSecKeyVerifyTest = evalContT $ do
    (k, _) <- ContT (useByteString key)
    liftIO $ do
        x <- signCtx
        ret <- ecSecKeyVerify x k
        assertBool "valid secret key" $ isSuccess ret
    where
        key =
            fromRight undefined $
                decodeBase16
                    "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"


ecPubkeyCreateTest :: Assertion
ecPubkeyCreateTest = evalContT $ do
    (s, _) <- ContT (useByteString key)
    k <- ContT (allocaBytes 64)
    o <- ContT (allocaBytes 65)
    ol <- ContT alloca
    liftIO $ do
        x <- signCtx
        createPubKey x s k
        poke ol 65
        rets <- ecPubkeySerialize x o ol k flagsEcUncompressed
        unless (isSuccess rets) $ error "failed to serialize public key"
        len <- fromIntegral <$> peek ol
        pk <- packCStringLen (castPtr o, len)
        assertEqual "public key matches" pub pk
    where
        key =
            fromRight undefined $
                decodeBase16
                    "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
        pub =
            fromRight undefined $
                decodeBase16
                    "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
                    \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"


ecSecKeyTweakAddTest :: Assertion
ecSecKeyTweakAddTest = evalContT $ do
    (w, _) <- ContT (useByteString tweak)
    (k, _) <- ContT (useByteString key)
    liftIO $ do
        x <- signCtx
        ret <- ecSeckeyTweakAdd x k w
        tweaked <- packByteString (k, 32)

        assertBool "successful secret key tweak" $ isSuccess ret
        assertEqual "tweaked keys match" expected tweaked
    where
        key =
            fromRight undefined $
                decodeBase16
                    "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
        tweak =
            fromRight undefined $
                decodeBase16
                    "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        expected =
            fromRight undefined $
                decodeBase16
                    "ec1e3ce1cefa18a671d51125e2b249688d934b0e28f5d1665384d9b02f929059"


ecSecKeyTweakMulTest :: Assertion
ecSecKeyTweakMulTest = evalContT $ do
    (w, _) <- ContT (useByteString tweak)
    (k, _) <- ContT (useByteString key)
    liftIO $ do
        x <- contextCreate flagsContextSign
        retr <- withEntropy $ contextRandomize x
        unless (isSuccess retr) $ error "failed to randomize context"
        ret <- ecSeckeyTweakMul x k w
        tweaked <- packByteString (k, 32)

        assertBool "successful secret key tweak" $ isSuccess ret
        assertEqual "tweaked keys match" expected tweaked
    where
        key =
            fromRight undefined $
                decodeBase16
                    "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
        tweak =
            fromRight undefined $
                decodeBase16
                    "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        expected =
            fromRight undefined $
                decodeBase16
                    "a96f5962493acb179f60a86a9785fc7a30e0c39b64c09d24fe064d9aef15e4c0"


serializeKey :: Ctx -> Ptr Pubkey64 -> IO ByteString
serializeKey x p = evalContT $ do
    d <- ContT (allocaBytes 72)
    dl <- ContT alloca
    liftIO $ do
        poke dl 72
        ret <- ecPubkeySerialize x d dl p flagsEcUncompressed
        unless (isSuccess ret) $ error "could not serialize public key"
        len <- peek dl
        packCStringLen (castPtr d, fromIntegral len)


parseKey :: Ctx -> ByteString -> IO ByteString
parseKey x bs = evalContT $ do
    p <- ContT (allocaBytes 64)
    (d, dl) <- ContT (useByteString bs)
    liftIO $ do
        ret <- ecPubkeyParse x p d dl
        unless (isSuccess ret) $ error "could not parse public key"
        packByteString (p, 64)


ecPubKeyTweakAddTest :: Assertion
ecPubKeyTweakAddTest = do
    x <- contextCreate flagsContextVerify
    pk <- copy <$> parseKey x pub
    (w, p) <- evalContT $ do
        (w, _) <- ContT (useByteString tweak)
        (p, _) <- ContT (useByteString pk)
        pure (w, p)

    ret <- ecPubkeyTweakAdd x p w
    tweaked <- serializeKey x p

    assertBool "successful secret key tweak" $ isSuccess ret
    assertEqual "tweaked keys match" expected tweaked
    where
        pub =
            fromRight undefined $
                decodeBase16
                    "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
                    \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
        tweak =
            fromRight undefined $
                decodeBase16
                    "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        expected =
            fromRight undefined $
                decodeBase16
                    "04441c3982b97576646e0df0c96736063df6b42f2ee566d13b9f6424302d1379e518fd\
                    \c87a14c5435bff7a5db4552042cb4120c6b86a4bbd3d0643f3c14ad01368"


ecPubKeyTweakMulTest :: Assertion
ecPubKeyTweakMulTest = do
    x <- contextCreate flagsContextVerify
    pk <- copy <$> parseKey x pub
    (w, p) <- evalContT $ do
        (w, _) <- ContT (useByteString tweak)
        (p, _) <- ContT (useByteString pk)
        pure (w, p)
    ret <- ecPubkeyTweakMul x p w
    tweaked <- serializeKey x p
    assertBool "successful secret key tweak" $ isSuccess ret
    assertEqual "tweaked keys match" expected tweaked
    where
        pub =
            fromRight undefined $
                decodeBase16
                    "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
                    \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
        tweak =
            fromRight undefined $
                decodeBase16
                    "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        expected =
            fromRight undefined $
                decodeBase16
                    "04f379dc99cdf5c83e433defa267fbb3377d61d6b779c06a0e4ce29ae3ff5353b12ae4\
                    \9c9d07e7368f2ba5a446c203255ce912322991a2d6a9d5d5761c61ed1845"


ecPubKeyCombineTest :: Assertion
ecPubKeyCombineTest = evalContT $ do
    p1 <- ContT (allocaBytes 64)
    p2 <- ContT (allocaBytes 64)
    p3 <- ContT (allocaBytes 64)
    a <- ContT (allocaArray 3)
    p <- ContT (allocaBytes 64)

    liftIO $ do
        x <- contextCreate flagsContextVerify
        parse x pub1 p1
        parse x pub2 p2
        parse x pub3 p3
        pokeArray a [p1, p2, p3]
        ret <- ecPubkeyCombine x p a 3
        com <- serializeKey x p

        assertBool "successful key combination" $ isSuccess ret
        assertEqual "combined keys match" expected com
    where
        parse x pub p = useByteString pub $ \(d, dl) -> do
            ret <- ecPubkeyParse x p d dl
            unless (isSuccess ret) $ error "could not parse public key"
        pub1 =
            fromRight undefined $
                decodeBase16
                    "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
                    \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
        pub2 =
            fromRight undefined $
                decodeBase16
                    "0487d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d153f5\
                    \77dd2dba6c7ae4cfd7b6622409d7edd2d76dd13a8092cd3af97b77bd2c77"
        pub3 =
            fromRight undefined $
                decodeBase16
                    "049b101edcbe1ee37ff6b2318526a425b629e823d7d8d9154417880595a28000ee3feb\
                    \d908754b8ce4e491aa6fe488b41fb5d4bb3788e33c9ff95a7a9229166d59"
        expected =
            fromRight undefined $
                decodeBase16
                    "043d9a7ec70011efc23c33a7e62d2ea73cca87797e3b659d93bea6aa871aebde56c3bc\
                    \6134ca82e324b0ab9c0e601a6d2933afe7fb5d9f3aae900f5c5dc6e362c8"
