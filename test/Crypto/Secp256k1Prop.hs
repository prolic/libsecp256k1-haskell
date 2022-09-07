{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.Secp256k1Prop where

import Control.Monad (when)
import Crypto.Secp256k1
import Crypto.Secp256k1.Gen
import Data.ByteArray.Sized (sizedByteArray)
import qualified Data.ByteString as BS
import Data.Maybe (fromJust, isJust)
import Data.Void
import Hedgehog
import Hedgehog.Gen hiding (discard, maybe)
import Hedgehog.Range (linear, singleton)


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


prop_signatureParseInvertsSerialize :: Property
prop_signatureParseInvertsSerialize = property $ do
    sk <- forAll secKeyGen
    bs <- forAll $ bytes (singleton 32)
    sig <- case ecdsaSign sk bs of
        Nothing -> failure
        Just x -> pure x
    exportDer <- forAll $ element [False, True]
    let export = if exportDer then exportSignatureDer else exportSignatureCompact
    let serialized = (export sig)
    annotateShow serialized
    annotateShow (BS.length serialized)
    case importSignature serialized of
        Nothing -> failure
        Just x -> x === sig


prop_recoverableSignatureParseInvertsSerialize :: Property
prop_recoverableSignatureParseInvertsSerialize = property $ do
    sk <- forAll secKeyGen
    bs <- forAll $ bytes (singleton 32)
    sig <- case ecdsaSignRecoverable sk bs of
        Nothing -> failure
        Just x -> pure x
    let serialized = (exportRecoverableSignature sig)
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
    case ecdsaSign sk msg of
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
    let sig = fromJust $ ecdsaSign sk msg
    useDer <- forAll enumBounded
    let export =
            if useDer
                then exportSignatureDer
                else exportSignatureCompact
    let serialized = export sig
    let parsed = fromJust (importSignature serialized)
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
    case schnorrSign kp msg of
        Nothing -> failure
        Just sig -> assert $ schnorrVerify (fst $ keyPairPubKeyXO kp) msg sig


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
    case ecdsaSign sk msg of
        Nothing -> failure
        Just sig -> assert . not $ ecdsaVerify msg pk sig


prop_schnorrSignaturesUnforgeable :: Property
prop_schnorrSignaturesUnforgeable = property $ do
    sk <- forAll secKeyGen
    let kp = keyPairCreate sk
    pk <- forAll pubKeyXOGen
    msg <- forAll $ bytes (singleton 32)
    case schnorrSign kp msg of
        Nothing -> failure
        Just sig -> assert . not $ schnorrVerify pk msg sig


tests :: Group
tests = $$(discover)