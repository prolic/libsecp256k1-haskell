module Spec where

import Crypto.Secp256k1.PrimSpec qualified as Prim
import Crypto.Secp256k1Spec qualified as Secp256k1
import Test.Hspec


spec :: Spec
spec = do
    Prim.spec
    Secp256k1.spec