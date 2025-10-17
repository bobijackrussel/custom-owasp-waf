package com.insurance.waf.filter;

import com.insurance.waf.model.Rule;
import com.insurance.waf.service.XssDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static com.insurance.waf.service.Test.parseFile;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

public class SQLIFilter implements Filter {

    private XssDetector xssDetector = new XssDetector();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Check request parameters
        Enumeration<String> paramNames = httpRequest.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String[] paramValues = httpRequest.getParameterValues(paramName);
            for (String value : paramValues) {
                if (xssDetector.detectXss(value)) {
                    System.out.println("XSS detected in parameter: " + paramName + " with value: " + value);
                    // You might want to log this, return an error, or sanitize
                    httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "XSS Detected");
                    return; // Stop further processing
                }
            }
        }

        // You would also need to handle request body for POST requests, which is more complex
        // and often involves wrapping the request to read the body multiple times.

        chain.doFilter(request, response); // Continue to the next filter or servlet
    }

    @Override
    public void destroy() {
        // Cleanup if needed
    }
}