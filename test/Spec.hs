module Spec where

import qualified Crypto.Secp256k1Spec as Secp256k1
import Test.Hspec


spec :: Spec
spec = do
    Secp256k1.spec