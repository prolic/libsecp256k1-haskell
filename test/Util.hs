module Util where

import qualified Data.ByteArray.Encoding as BA
import Data.ByteString


decodeBase16 :: ByteString -> Either String ByteString
decodeBase16 = BA.convertFromBase BA.Base16


encodeBase16 :: ByteString -> ByteString
encodeBase16 = BA.convertToBase BA.Base16