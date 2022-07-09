module Crypto.Secp256k1.Gen where

import Crypto.Secp256k1 (KeyPair, PubKeyXO, PubKeyXY, SecKey, Tweak, derivePubKey, importSecKey, importTweak, keyPairCreate, xyToXO)
import Hedgehog (MonadGen)
import Hedgehog.Gen (bytes, discard)
import Hedgehog.Range (singleton)


secKeyGen :: MonadGen m => m SecKey
secKeyGen = do
    bs <- bytes (singleton 32)
    maybe discard pure (importSecKey bs)


pubKeyXYGen :: MonadGen m => m PubKeyXY
pubKeyXYGen = derivePubKey <$> secKeyGen


pubKeyXOGen :: MonadGen m => m PubKeyXO
pubKeyXOGen = fst . xyToXO <$> pubKeyXYGen


keyPairGen :: MonadGen m => m KeyPair
keyPairGen = keyPairCreate <$> secKeyGen


tweakGen :: MonadGen m => m Tweak
tweakGen = do
    bs <- bytes (singleton 32)
    maybe discard pure (importTweak bs)