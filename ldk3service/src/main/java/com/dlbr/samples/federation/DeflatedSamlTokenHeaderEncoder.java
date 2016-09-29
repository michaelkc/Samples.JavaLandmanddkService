package com.dlbr.samples.federation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import org.apache.commons.codec.binary.Base64;

public class DeflatedSamlTokenHeaderEncoder {
    public String Encode(String token) throws IOException {
        byte[] bytes = token.getBytes(StandardCharsets.UTF_8);
        byte[] deflatedBytes = deflaterCompress(bytes);
        byte[] base64Bytes = Base64.encodeBase64(deflatedBytes);
        String base64String = new String(base64Bytes, StandardCharsets.UTF_8);
        String urlEncodedString = URLEncoder.encode(base64String, StandardCharsets.UTF_8.toString());
        return urlEncodedString;
    }
    
    public String Decode(String encodedToken) throws IOException {
    	String base64String = URLDecoder.decode(encodedToken, StandardCharsets.UTF_8.toString());
    	byte[] base64Bytes = base64String.getBytes(StandardCharsets.UTF_8);
    	byte[] deflatedBytes =  Base64.decodeBase64(base64Bytes);
        byte[] bytes = deflaterDecompress(deflatedBytes);
        String token = new String(bytes, StandardCharsets.UTF_8);
        return token;
    }

    private byte[] deflaterCompress(byte[] toCompress) {
        try {
            ByteArrayOutputStream compressedStream = new ByteArrayOutputStream();

            DeflaterOutputStream inflater = new DeflaterOutputStream(compressedStream);
            inflater.write(toCompress, 0, toCompress.length);
            inflater.close();

            // http://george.chiramattel.com/blog/2007/09/deflatestream-block-length-does-not-match.html
            byte[] rfc1950Bytes = compressedStream.toByteArray();
            byte[] rfc1951Bytes = Arrays.copyOfRange(rfc1950Bytes, 2, rfc1950Bytes.length - 2);
            return rfc1951Bytes;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    private byte[] deflaterDecompress(byte[] toDecompress) throws IOException {
    	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        InflaterOutputStream  inflater = new InflaterOutputStream (outputStream,new Inflater(true));
        inflater.write(toDecompress, 0, toDecompress.length);
        inflater.close();
        byte[] inflatedBytes =outputStream.toByteArray();
        return inflatedBytes;
    }

}
