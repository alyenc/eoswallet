package com.alyenc.eoswallet.utils;

public class StringUtils {
    public static boolean isEmpty( CharSequence data ) {
        return ( null == data ) || ( data.length() <= 0);
    }
}
