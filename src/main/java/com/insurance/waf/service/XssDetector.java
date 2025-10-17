package com.insurance.waf.service;

public class XssDetector {

    /**
     * Detects XSS using the libinjection C library via JNA.
     * @param input The string to check for XSS.
     * @return true if XSS is detected, false otherwise.
     */
    public boolean detectXss(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        int isXss = Libinjection.INSTANCE.libinjection_xss(input, input.length());

        if (isXss != 0) {
            System.out.println("Detected XSS using libinjection in: " + input);
        } else {
            System.out.println("No XSS found by libinjection in: " + input);
        }

        return isXss != 0;
    }

    public static void main(String[] args) {
        XssDetector detector = new XssDetector();

        System.out.println("Checking 'alert(1)': " + detector.detectXss("alert(1)"));
        System.out.println("Checking '<script>alert(1)</script>': " + detector.detectXss("<script>alert(1)</script>"));
        System.out.println("Checking 'safe string': " + detector.detectXss("safe string"));
        System.out.println("Checking '<IMG SRC=javascript:alert('XSS')>': " + detector.detectXss("<IMG SRC=javascript:alert('XSS')>"));
        System.out.println("Checking '\" onclick=alert(1)>': " + detector.detectXss("\" onclick=alert(1)>"));
    }
}

