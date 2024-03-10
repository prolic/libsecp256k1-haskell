module Spec where

import qualified Crypto.Secp256k1.PrimSpec as Prim
import qualified Crypto.Secp256k1Spec as Secp256k1
import Test.Hspec


spec :: Spec
spec = do
    Prim.spec
    Secp256k1.spec