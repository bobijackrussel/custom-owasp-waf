package com.insurance.waf.filter;

import com.insurance.waf.model.CachedBodyHttpServletRequest;
import com.insurance.waf.model.Rule;
import com.insurance.waf.model.opertion.operationImpl.BodyOperation;
import com.insurance.waf.model.opertion.operationImpl.RxOperation;
import com.insurance.waf.model.transformation.Transformation;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;

import static com.insurance.waf.service.Test.parseFile;

@Component
@Order(1)
@RequiredArgsConstructor
public class XSSFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(XSSFilter.class);
    private static final List<Rule> xssRules=loadRules();

    public static  List<Rule>  loadRules() {
        try {
        Path p = Paths.get("C:\\Users\\User\\Downloads\\REQUEST-941-APPLICATION-ATTACK-XSS.conf");
        List<Rule> toReturn=parseFile(p).stream().filter(s->s!=null).sorted((Rule a,Rule b)->{return Integer.compare(a.getPhase(),b.getPhase());}).toList();
        toReturn.forEach(r->System.out.println(r.getPhase()));
        return toReturn;
        }
    catch(Exception e){
        return null;
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        CachedBodyHttpServletRequest cachedBodyRequest = new CachedBodyHttpServletRequest(httpRequest);

        try
        {
            if (isMaliciousRequest(cachedBodyRequest)) {
                handleMaliciousRequest(httpRequest, httpResponse);
                return;
            }
            chain.doFilter(cachedBodyRequest, response);
            System.out.println("Passed!");

        } catch (Exception e) {
            logger.error("Error processing security filter", e);
            chain.doFilter(cachedBodyRequest, response);
        }
    }

    private boolean isMaliciousRequest(CachedBodyHttpServletRequest request) {
        for (Rule rule : xssRules) {
            if (rule.getOperation()!=null/*&&!(rule.getOperation() instanceof BodyOperation)*/ && evaluateRule(rule, request))
            {
                logger.warn("Caught malicious request: "+rule.getMsg());
                return true;
            }
        }
        return false;
    }

    private boolean evaluateRule(Rule rule, CachedBodyHttpServletRequest request) {

        List<Object> matchedVars = new ArrayList<>();
        List<Object> matchedVarNames = new ArrayList<>();
        List<String> targets=rule.getTargets();

        if(rule.getOperation() instanceof BodyOperation ){
            ((BodyOperation) rule.getOperation())
                    .setOperations(xssRules.stream()
                            .map(Rule::getOperation)
                            .filter(o->o instanceof RxOperation)
                            .toList());
            //targets=Arrays.stream(new String[]{"REQUEST_BODY"}).toList();
        }

        for (String target : targets) {

            List<String> values = extractValuesFromTarget(target, request);
            for (String value : values) {
                if (value != null && !value.trim().isEmpty()){
                    try {
                        String transformedValue = applyTransformations(value, rule.getTransforms());


                        boolean isMatch = rule.getOperation().performOperation(transformedValue);

                        if (isMatch) {
                            //System.out.println(value);
                            matchedVars.add(value);
                            matchedVarNames.add(target);

                            if (rule.isChained() && rule.getChainedRule() != null) {
                                request.setAttribute("OWASP_MATCHED_VARS", matchedVars);
                                request.setAttribute("OWASP_MATCHED_VAR_NAMES", matchedVarNames);
                                return evaluateChainedRule(rule.getChainedRule(), request);
                            }

                            return true;
                        }
                    }
                    catch(Exception e){
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean evaluateChainedRule(Rule chainedRule, CachedBodyHttpServletRequest request) {
        for (String target : chainedRule.getTargets()) {
            List<String> values = extractValuesFromTarget(target, request);

            for (String value : values) {
                if (value != null && !value.trim().isEmpty()) {
                    String transformedValue = applyTransformations(value, chainedRule.getTransforms());
                    boolean isMatch = chainedRule.getOperation().performOperation(transformedValue);

                    if (isMatch) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private List<String> extractValuesFromTarget(String target, CachedBodyHttpServletRequest request) {
        List<String> values = new ArrayList<>();

        try {
            if (target == null || target.trim().isEmpty()) {
                return values;
            }

            String upperTarget = target.toUpperCase();


            if (target.startsWith("!")) {
                return handleExclusionTarget(target.substring(1), request);
            }

            switch (upperTarget) {

                case "ARGS_NAMES":
                    Enumeration<String> paramNames = request.getParameterNames();
                    while (paramNames.hasMoreElements()) {
                        values.add(paramNames.nextElement());
                    }
                    break;

                case "ARGS":
                    Enumeration<String> params = request.getParameterNames();
                    while (params.hasMoreElements()) {
                        String paramName = params.nextElement();
                        values.addAll((Arrays.stream(request.getParameterValues(paramName))
                                                .filter(s->!s.isEmpty())
                                                .toList()));
                    }
                    break;

                case "REQUEST_HEADERS":
                    Enumeration<String> headerNames = request.getHeaderNames();
                    while (headerNames.hasMoreElements()) {

                        String headerName = headerNames.nextElement();
                        if(headerName.toLowerCase().contains("user")){
                           // System.out.println("headerName:"+headerName+"value:"+request.getHeader(headerName));
                            values.add(request.getHeader(headerName));
                        }
                    }
                    break;

                case "REQUEST_COOKIES":
                    Cookie[] cookies = request.getCookies();
                    if (cookies != null) {
                        for (Cookie cookie : cookies) {
                            values.add(cookie.getValue());
                        }
                    }
                    break;

                case "REQUEST_COOKIES_NAMES":
                    Cookie[] cookiesForNames = request.getCookies();
                    if (cookiesForNames != null) {
                        for (Cookie cookie : cookiesForNames) {
                            values.add(cookie.getName());
                        }
                    }
                    break;

                case "REQUEST_FILENAME":
                    String requestURI = request.getRequestURI();
                    String contextPath = request.getContextPath();
                    if (contextPath != null && requestURI.startsWith(contextPath)) {
                        values.add(requestURI.substring(contextPath.length()));
                    } else {
                        values.add(requestURI);
                    }
                    break;
                case "XML:/*":
                    return handleXmlTarget(target.substring(4), request);

                case "REQUEST_BODY":
                    try {
                        String body = getRequestBody(request);
                        //System.out.println("Body:"+body+"******");
                        if (body != null && !body.trim().isEmpty()) {
                            values.add(body);
                        }
                    } catch (IOException e) {
                        logger.error("Error reading request body", e);
                    }
                    break;

                case "REQUEST_METHOD":
                    values.add(request.getMethod());
                    break;

                case "REQUEST_PROTOCOL":
                    values.add(request.getProtocol());
                    break;

                case "QUERY_STRING":
                    String queryString = request.getQueryString();
                    if (queryString != null) {
                        values.add(queryString);
                    }
                    break;

                case "REMOTE_ADDR":
                    values.add(getClientIpAddress(request));
                    break;

                case "REMOTE_HOST":
                    values.add(request.getRemoteHost());
                    break;

                case "SERVER_NAME":
                    values.add(request.getServerName());
                    break;

                case "SERVER_PORT":
                    values.add(String.valueOf(request.getServerPort()));
                    break;

                case "MATCHED_VARS":
                    Object matchedVars = request.getAttribute("OWASP_MATCHED_VARS");
                    if (matchedVars instanceof Collection) {
                        ((Collection<?>) matchedVars).forEach(item ->
                                values.add(item != null ? item.toString() : ""));
                    }
                    break;

                case "MATCHED_VARS_NAMES":
                    Object matchedVarNames = request.getAttribute("OWASP_MATCHED_VAR_NAMES");
                    if (matchedVarNames instanceof Collection) {
                        ((Collection<?>) matchedVarNames).forEach(item ->
                                values.add(item != null ? item.toString() : ""));
                    }
                    break;

                default:
                    logger.debug("Unknown target type: {}", target);
                    break;
            }
        } catch (Exception e) {
            logger.error("Error extracting values for target: {}", target, e);
        }

        return values;
    }

    private String applyTransformations(String input, List<Transformation> transformations) {
        String result = input;
        for (Transformation transformation : transformations) {
            result = transformation.transform(result);
        }
        return result;
    }

    private String getRequestBody(CachedBodyHttpServletRequest request) throws IOException {
        return request.getBody();
    }

    private void handleMaliciousRequest(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");

    }

    private List<String> handleExclusionTarget(String target, CachedBodyHttpServletRequest request) {
        List<String> values = new ArrayList<>();

        if (target.startsWith("REQUEST_COOKIES:/") && target.endsWith("/")) {
            // Extract regex pattern between slashes
            String regexPattern = target.substring(17, target.length() - 1); // "REQUEST_COOKIES:/".length()
            Pattern pattern = Pattern.compile(regexPattern);

            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (!pattern.matcher(cookie.getName()).matches()) {
                        values.add(cookie.getValue());
                    }
                }
            }
        }

        return values;
    }

    private List<String> handleXmlTarget(String xpath, CachedBodyHttpServletRequest request) {
        List<String> values = new ArrayList<>();

        try {
            String body = getRequestBody(request);
            if (body != null && !body.trim().isEmpty() && isXmlContent(request)) {
                // Parse XML and evaluate XPath
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                // Security: disable external entities to prevent XXE
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                factory.setXIncludeAware(false);
                factory.setExpandEntityReferences(false);

                DocumentBuilder builder = factory.newDocumentBuilder();
                Document document = builder.parse(new InputSource(new StringReader(body)));

                XPath xPath = XPathFactory.newInstance().newXPath();
                NodeList nodeList = (NodeList) xPath.compile(xpath).evaluate(document, XPathConstants.NODESET);

                for (int i = 0; i < nodeList.getLength(); i++) {
                    values.add(nodeList.item(i).getTextContent());
                }
            }
        } catch (Exception e) {
            logger.debug("Error processing XML target {}: {}", xpath, e.getMessage());
        }

        return values;
    }

    private boolean isXmlContent(CachedBodyHttpServletRequest request) {
        String contentType = request.getContentType();
        return contentType != null && contentType.contains("application/xml") ||
                contentType != null && contentType.contains("text/xml");
    }

    private String getClientIpAddress(CachedBodyHttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}