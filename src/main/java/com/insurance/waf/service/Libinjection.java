package com.insurance.waf.service;
import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * This interface provides a mapping to the native libinjection C library.
 * JNA will dynamically implement this interface for us.
 */
public interface Libinjection extends Library {

    /**
     * Loads the 'injection' library and creates an instance of this interface.
     * JNA automatically searches for 'libinjection.so', 'injection.dll', etc.
     */
    Libinjection INSTANCE = Native.load("libinjection", Libinjection.class);

    /**
     * Maps to the C function: int libinjection_xss(const char* s, size_t len);
     *
     * @param s   The input string to check for XSS.
     * @param len The length of the input string.
     * @return 1 if XSS is detected, 0 otherwise.
     */
    int libinjection_xss(String s, int len);
}

