{-# LANGUAGE TemplateHaskell #-}

module Crypto.Secp256k1Prop where

import Crypto.Secp256k1
import Crypto.Secp256k1.Gen
import qualified Data.ByteString as BS
import Hedgehog
import Hedgehog.Gen
import Hedgehog.Range (singleton)


prop_secKeyParseInvertsSerialize :: Property
prop_secKeyParseInvertsSerialize = property $ do
    sk <- forAll secKeyGen
    case importSecKey $ exportSecKey sk of
        Nothing -> failure
        Just x -> x === sk


prop_pubKeyXYParseInvertsSerialize :: Property
prop_pubKeyXYParseInvertsSerialize = property $ do
    pk <- forAll pubKeyXYGen
    compress <- forAll $ element [False, True]
    case importPubKeyXY (exportPubKeyXY compress pk) of
        Nothing -> failure
        Just x -> x === pk


prop_pubKeyXOParseInvertsSerialize :: Property
prop_pubKeyXOParseInvertsSerialize = property $ do
    pk <- forAll pubKeyXOGen
    case importPubKeyXO (exportPubKeyXO pk) of
        Nothing -> failure
        Just x -> x === pk


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


tests :: Group
tests = $$(discover)