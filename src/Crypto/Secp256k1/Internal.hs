module Crypto.Secp256k1.Internal where

import Crypto.Secp256k1.Prim
import qualified Data.ByteArray.Encoding as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BU
import Foreign (Ptr, castPtr)
import Foreign.C (CSize)


unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
    BU.unsafeUseAsCStringLen bs $ \(b, l) ->
        f (castPtr b, fromIntegral l)


useByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useByteString bs f =
    BS.useAsCStringLen bs $ \(b, l) ->
        f (castPtr b, fromIntegral l)


unsafePackByteString :: (Ptr a, CSize) -> IO ByteString
unsafePackByteString (b, l) =
    BU.unsafePackMallocCStringLen (castPtr b, fromIntegral l)


packByteString :: (Ptr a, CSize) -> IO ByteString
packByteString (b, l) =
    BS.packCStringLen (castPtr b, fromIntegral l)


isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n


encodeBase16 :: ByteString -> ByteString
encodeBase16 = BA.convertToBase BA.Base16


decodeBase16 :: ByteString -> Either String ByteString
decodeBase16 = BA.convertFromBase BA.Base16