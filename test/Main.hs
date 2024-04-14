module Main where

import Crypto.Secp256k1
import Crypto.Secp256k1Prop qualified as Secp256k1Prop
import GHC.IO.Encoding (setLocaleEncoding, utf8)
import Hedgehog (checkSequential)
import Hedgehog.Main
import Spec qualified
import Test.Hspec.Api.Formatters.V1
import Test.Hspec.Runner (Config (..), defaultConfig, hspecWith)


main :: IO ()
main = do
    setLocaleEncoding utf8
    hspecWith (useFormatter ("progress", progress) defaultConfig) Spec.spec
    defaultMain
        [ checkSequential Secp256k1Prop.tests
        ]