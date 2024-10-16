{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.Secp256k1Prop where

import Control.Applicative (Applicative (liftA2), empty)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Crypto.Secp256k1
import Crypto.Secp256k1.Gen
import Data.ByteArray.Sized (sizedByteArray)
import Data.ByteString qualified as BS
import Data.Maybe (fromJust, isJust)
import Data.Void
import Hedgehog
import Hedgehog.Gen hiding (discard, maybe, prune)
import Hedgehog.Range (linear, singleton)
import Text.Read (readMaybe)
import System.Random (StdGen, mkStdGen)


prop_secKeyReadInvertsShow :: Property
prop_secKeyReadInvertsShow = property $ do
    sk <- forAll secKeyGen
    let str = show sk
    case readMaybe str of
        Nothing -> failure
        Just x -> x === sk


prop_secKeyParseInvertsSerialize :: Property
prop_secKeyParseInvertsSerialize = property $ do
    sk <- forAll secKeyGen
    case importSecKey $ exportSecKey sk of
        Nothing -> failure
        Just x -> x === sk


prop_secKeySerializeInvertsParse :: Property
prop_secKeySerializeInvertsParse = property $ do
    bs <- forAll (bytes $ singleton 32)
    case importSecKey bs of
        Nothing -> discard
        Just sk -> exportSecKey sk === bs


prop_pubKeyXYReadInvertsShow :: Property
prop_pubKeyXYReadInvertsShow = property $ do
    pk <- forAll pubKeyXYGen
    let str = show pk
    case readMaybe str of
        Nothing -> failure
        Just x -> x === pk


prop_pubKeyXYParseInvertsSerialize :: Property
prop_pubKeyXYParseInvertsSerialize = property $ do
    pk <- forAll pubKeyXYGen
    compress <- forAll $ element [False, True]
    case importPubKeyXY (exportPubKeyXY compress pk) of
        Nothing -> failure
        Just x -> x === pk


prop_pubKeyXYSerializeInvertsParse :: Property
prop_pubKeyXYSerializeInvertsParse = withDiscards 200 $
    property $ do
        bs <- forAll $ bytes (singleton 32)
        negate <- forAll enumBounded
        let withParity =
                flip BS.cons bs $
                    if negate
                        then 0x03
                        else 0x02
        case importPubKeyXY withParity of
            Nothing -> discard
            Just pk -> exportPubKeyXY True pk === withParity


prop_pubKeyXOReadInvertsShow :: Property
prop_pubKeyXOReadInvertsShow = property $ do
    pk <- forAll pubKeyXOGen
    let str = show pk
    case readMaybe str of
        Nothing -> failure
        Just x -> x === pk


prop_pubKeyXOParseInvertsSerialize :: Property
prop_pubKeyXOParseInvertsSerialize = property $ do
    pk <- forAll pubKeyXOGen
    case importPubKeyXO (exportPubKeyXO pk) of
        Nothing -> failure
        Just x -> x === pk


prop_pubKeyXOSerializeInvertsParse :: Property
prop_pubKeyXOSerializeInvertsParse = withDiscards 200 . property $ do
    bs <- forAll (bytes $ singleton 32)
    case importPubKeyXO bs of
        Nothing -> discard
        Just pk -> exportPubKeyXO pk === bs


prop_signatureReadInvertsShow :: Property
prop_signatureReadInvertsShow = property $ do
    sk <- forAll secKeyGen
    bs <- forAll (bytes $ singleton 32)
    sig <- maybe failure pure $ ecdsaSign sk bs
    case readMaybe (show sig) of
        Nothing -> failure
        Just x -> sig === x


prop_signatureParseInvertsSerialize :: Property
prop_signatureParseInvertsSerialize = property $ do
    sk <- forAll secKeyGen
    bs <- forAll $ bytes (singleton 32)

    sig <- maybe failure pure $ ecdsaSign sk bs

    exportDer <- forAll $ element [False, True]
    let export = if exportDer then exportSignatureDer else exportSignatureCompact
    let serialized = export sig
    annotateShow serialized
    annotateShow (BS.length serialized)
    let parse = if exportDer then importSignatureDer else importSignatureCompact
    case parse serialized of
        Nothing -> failure
        Just x -> x === sig


prop_recoverableSignatureReadInvertsShow :: Property
prop_recoverableSignatureReadInvertsShow = property $ do
    sk <- forAll secKeyGen
    bs <- forAll $ bytes (singleton 32)
    recSig <- maybe failure pure $ ecdsaSignRecoverable sk bs
    let export = exportRecoverableSignature recSig
    case importRecoverableSignature export of
        Nothing -> failure
        Just x -> x === recSig


prop_recoverableSignatureParseInvertsSerialize :: Property
prop_recoverableSignatureParseInvertsSerialize = property $ do
    sk <- forAll secKeyGen
    bs <- forAll $ bytes (singleton 32)

    sig <- maybe failure pure (ecdsaSignRecoverable sk bs)

    let serialized = exportRecoverableSignature sig
    annotateShow serialized
    annotateShow (BS.length serialized)
    case importRecoverableSignature serialized of
        Nothing -> failure
        Just x -> x === sig


prop_validSecKeyImpliesValidTweak :: Property
prop_validSecKeyImpliesValidTweak = property $ do
    sk <- forAll secKeyGen
    assert $ isJust $ importTweak (exportSecKey sk)


prop_ecdsaSignaturesProducedAreValid :: Property
prop_ecdsaSignaturesProducedAreValid = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let sig = ecdsaSign sk msg
    case sig of
        Nothing -> failure
        Just sig -> assert $ ecdsaVerify msg (derivePubKey sk) sig


prop_ecdsaRecoverableSignaturesProducedAreValid :: Property
prop_ecdsaRecoverableSignaturesProducedAreValid = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    case ecdsaSignRecoverable sk msg of
        Nothing -> failure
        Just recSig -> assert $ ecdsaVerify msg (derivePubKey sk) (recSigToSig recSig)


prop_ecdsaSignatureValidityPreservedOverSerialization :: Property
prop_ecdsaSignatureValidityPreservedOverSerialization = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    sig <- maybe failure pure $ ecdsaSign sk msg
    useDer <- forAll enumBounded
    let (serialize, parse) =
            if useDer
                then (exportSignatureDer, importSignatureDer)
                else (exportSignatureCompact, importSignatureCompact)
    let serialized = serialize sig
    let parsed = fromJust (parse serialized)
    assert $ ecdsaVerify msg (derivePubKey sk) parsed


prop_ecdsaRecoverableSignatureProducesValidPubKey :: Property
prop_ecdsaRecoverableSignatureProducesValidPubKey = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    case ecdsaRecover (fromJust $ ecdsaSignRecoverable sk msg) msg of
        Nothing -> failure
        Just pk -> pk === derivePubKey sk


prop_ecdsaRecoverableSignatureIdentity :: Property
prop_ecdsaRecoverableSignatureIdentity = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    case ecdsaSignRecoverable sk msg of
        Nothing -> failure
        Just sig -> Just (recSigToSig sig) === ecdsaSign sk msg


prop_keyPairIdentities :: Property
prop_keyPairIdentities = property $ do
    sk <- forAll secKeyGen
    let kp = keyPairCreate sk
    keyPairSecKey kp === sk
    keyPairPubKeyXY kp === derivePubKey sk
    keyPairPubKeyXO kp === xyToXO (derivePubKey sk)


prop_tweakDistributesOverPubKeyDerivation :: Property
prop_tweakDistributesOverPubKeyDerivation = property $ do
    sk <- forAll secKeyGen
    tweak <- forAll tweakGen
    (derivePubKey <$> secKeyTweakAdd sk tweak) === pubKeyTweakAdd (derivePubKey sk) tweak
    (derivePubKey <$> secKeyTweakMul sk tweak) === pubKeyTweakMul (derivePubKey sk) tweak


prop_pubKeyCombineOrderIndependent :: Property
prop_pubKeyCombineOrderIndependent = property $ do
    ls <- forAll $ list (linear 0 20) pubKeyXYGen
    ls' <- forAll $ shuffle ls
    pubKeyCombine ls === pubKeyCombine ls'


prop_negationDistributesOverPubKeyDerivation :: Property
prop_negationDistributesOverPubKeyDerivation = property $ do
    sk <- forAll secKeyGen
    derivePubKey (secKeyNegate sk) === pubKeyNegate (derivePubKey sk)


prop_secKeyDoubleNegationIdentity :: Property
prop_secKeyDoubleNegationIdentity = property $ do
    sk <- forAll secKeyGen
    (secKeyNegate . secKeyNegate) sk === sk


prop_pubKeyDoubleNegationIdentity :: Property
prop_pubKeyDoubleNegationIdentity = property $ do
    pk <- forAll pubKeyXYGen
    (pubKeyNegate . pubKeyNegate) pk === pk


prop_schnorrSignaturesProducedAreValid :: Property
prop_schnorrSignaturesProducedAreValid = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let kp = keyPairCreate sk
    sig <- maybe failure pure $ schnorrSignDeterministic kp msg
    assert $ schnorrVerify (fst $ keyPairPubKeyXO kp) msg sig


prop_schnorrSignaturesProducedAreValidNonDeterministic :: Property
prop_schnorrSignaturesProducedAreValidNonDeterministic = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let kp = keyPairCreate sk
    sig <- liftIO $ maybe (error "Failed to sign") pure =<< schnorrSignNondeterministic kp msg
    assert $ schnorrVerify (fst $ keyPairPubKeyXO kp) msg sig


prop_pubKeyCombineTweakIdentity :: Property
prop_pubKeyCombineTweakIdentity = property $ do
    sk <- forAll secKeyGen
    sk' <- forAll secKeyGen
    pubKeyCombine [derivePubKey sk, derivePubKey sk'] === pubKeyTweakAdd (derivePubKey sk) (fromJust $ importTweak (exportSecKey sk'))


prop_ecdhIdentity :: Property
prop_ecdhIdentity = property $ do
    sk <- forAll secKeyGen
    sk' <- forAll secKeyGen
    ecdh sk (derivePubKey sk') === ecdh sk' (derivePubKey sk)


prop_ecdsaSignaturesUnforgeable :: Property
prop_ecdsaSignaturesUnforgeable = property $ do
    sk <- forAll secKeyGen
    pk <- forAll pubKeyXYGen
    when (pk == derivePubKey sk) discard
    msg <- forAll $ bytes (singleton 32)
    let sig = ecdsaSign sk msg
    case sig of
        Nothing -> failure
        Just sig -> assert . not $ ecdsaVerify msg pk sig


prop_schnorrSignaturesUnforgeable :: Property
prop_schnorrSignaturesUnforgeable = property $ do
    sk <- forAll secKeyGen
    let kp = keyPairCreate sk
    pk <- forAll pubKeyXOGen
    msg <- forAll $ bytes (singleton 32)
    sig <- maybe failure pure $ schnorrSignDeterministic kp msg
    assert . not $ schnorrVerify pk msg sig


prop_schnorrSignaturesUnforgeableNonDeterministic :: Property
prop_schnorrSignaturesUnforgeableNonDeterministic = property $ do
    sk <- forAll secKeyGen
    let kp = keyPairCreate sk
    pk <- forAll pubKeyXOGen
    msg <- forAll $ bytes (singleton 32)
    sig <- liftIO $ maybe (error "Failed to sign") pure =<< schnorrSignNondeterministic kp msg
    assert . not $ schnorrVerify pk msg sig


newtype Wrapped a = Wrapped {secKey :: a} deriving (Show, Read, Eq)


derivedCompositeReadShowInvertTemplate :: (Eq a, Read a, Show a) => Gen a -> Property
derivedCompositeReadShowInvertTemplate gen = property $ do
    a <- forAll gen
    annotateShow a
    annotateShow (length $ show a)
    annotateShow (Wrapped a)
    case readMaybe (show (Wrapped a)) of
        Nothing -> failure
        Just x -> x === Wrapped a


prop_derivedCompositeReadShowInvertSecKey :: Property
prop_derivedCompositeReadShowInvertSecKey = derivedCompositeReadShowInvertTemplate secKeyGen


prop_derivedCompositeReadShowInvertPubKeyXY :: Property
prop_derivedCompositeReadShowInvertPubKeyXY = derivedCompositeReadShowInvertTemplate pubKeyXYGen


prop_derivedCompositeReadShowInvertPubKeyXO :: Property
prop_derivedCompositeReadShowInvertPubKeyXO = derivedCompositeReadShowInvertTemplate pubKeyXOGen


prop_derivedCompositeReadShowInvertTweak :: Property
prop_derivedCompositeReadShowInvertTweak = derivedCompositeReadShowInvertTemplate tweakGen


prop_derivedCompositeReadShowInvertSignature :: Property
prop_derivedCompositeReadShowInvertSignature = derivedCompositeReadShowInvertTemplate ecdsaSignGen
    where
        ecdsaSignGen = do
            sk <- secKeyGen
            msg <- bytes (singleton 32)
            maybe empty pure $ ecdsaSign sk msg


prop_derivedCompositeReadShowInvertSchnorrSignature :: Property
prop_derivedCompositeReadShowInvertSchnorrSignature = property $ do
    sk <- forAll secKeyGen
    let kp = keyPairCreate sk
    msg <- forAll $ bytes (singleton 32)
    sig <- maybe failure pure $ schnorrSignDeterministic kp msg
    let a = sig
    annotateShow a
    annotateShow (length $ show a)
    annotateShow (Wrapped a)
    case readMaybe (show (Wrapped a)) of
        Nothing -> failure
        Just x  -> x === Wrapped a


prop_derivedCompositeReadShowInvertRecoverableSignature :: Property
prop_derivedCompositeReadShowInvertRecoverableSignature = derivedCompositeReadShowInvertTemplate $ do
    sk <- secKeyGen
    msg <- bytes (singleton 32)
    maybe empty pure $ ecdsaSignRecoverable sk msg


prop_eqImportImpliesEqSecKey :: Property
prop_eqImportImpliesEqSecKey = property $ do
    bs <- forAll $ bytes $ singleton 32
    k0 <- maybe discard pure $ importSecKey bs
    k1 <- maybe discard pure $ importSecKey bs
    k0 === k1


prop_schnorrSignatureParseInvertsSerialize :: Property
prop_schnorrSignatureParseInvertsSerialize = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let kp = keyPairCreate sk
    sig <- maybe failure pure $ schnorrSignDeterministic kp msg
    let serialized = exportSchnorrSignature sig
    annotateShow serialized
    annotateShow (BS.length serialized)
    let parsed = importSchnorrSignature serialized
    parsed === Just sig


prop_schnorrSignatureValidityPreservedOverSerialization :: Property
prop_schnorrSignatureValidityPreservedOverSerialization = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let kp = keyPairCreate sk
    sig <- maybe failure pure $ schnorrSignDeterministic kp msg
    let serialized = exportSchnorrSignature sig
    let parsed = importSchnorrSignature serialized
    parsed === Just sig
    assert $ schnorrVerify (fst $ keyPairPubKeyXO kp) msg sig


prop_schnorrSignatureDeterministic :: Property
prop_schnorrSignatureDeterministic = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let kp = keyPairCreate sk
    sig1 <- maybe failure pure $ schnorrSignDeterministic kp msg
    sig2 <- maybe failure pure $ schnorrSignDeterministic kp msg
    sig1 === sig2


prop_schnorrSignatureNonDeterministic :: Property
prop_schnorrSignatureNonDeterministic = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let kp = keyPairCreate sk
    sig1 <- liftIO $ maybe (error "Failed to sign") pure =<< schnorrSignNondeterministic kp msg
    sig2 <- liftIO $ maybe (error "Failed to sign") pure =<< schnorrSignNondeterministic kp msg
    sig1 /== sig2


prop_schnorrSignWithStdGen :: Property
prop_schnorrSignWithStdGen = property $ do
    sk <- forAll secKeyGen
    msg <- forAll $ bytes (singleton 32)
    let kp = keyPairCreate sk
    stdGen <- forAll $ mkStdGen <$> integral (linear 0 maxBound)
    sig1 <- maybe failure pure $ schnorrSign (Just stdGen) kp msg
    sig2 <- maybe failure pure $ schnorrSign (Just stdGen) kp msg
    sig1 === sig2


tests :: Group
tests = $$discover
