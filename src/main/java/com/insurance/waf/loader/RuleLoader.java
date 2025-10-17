package com.insurance.waf.loader;

import com.insurance.waf.model.Rule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class RuleLoader{

     public String ruleConfigFile;

     public void loadRuleConfig(){
             String pattern="^SecRule\\s+(.+?)\\s+\".@([^\\s\"]+)(\\s+(.*?))?\"\\s\\\\$";
             try{
                     ArrayList<String> lines= Files.readAllLines(Paths.get(ruleConfigFile)).stream().filter(line->line.startsWith("#")).collect(Collectors.toCollection(ArrayList::new));
                     for(int i=0;i<lines.size();i++)
                     {
                             if(lines.get(i).matches(pattern)){
                                     String line=lines.get(i).trim();
                                     int j=i+1;
                                     //while(lines)
                             }
                     }

             }
             catch(IOException e){
                     System.out.println("Error reading config file");
             }
     }




    /**
     * Very small parser for single-line "SecRule ... " rules from CRS.
     * It intentionally supports a useful subset: variables, @rx operator, and comma-separated actions inside quotes.
     * This is not a full ModSecurity grammar parser, but enough to load simple CRS rules for demo/testing.

    private static final Logger log = LoggerFactory.getLogger(RuleParser.class);


    private static final Pattern SEC_RULE_PATTERN = Pattern.compile(
            "SecRule\\s+([^\"]+)\\s+\"(@\\w+)\\s+([^\"]+)\"\\s+\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE);

    public List<Rule> parseLines(List<String> lines) {
                List<Rule> rules = new ArrayList<>();
                for (String l : lines) {
                    String s = l.trim();
            if (s.isEmpty() || s.startsWith("#")) continue;
            Matcher m = SEC_RULE_PATTERN.matcher(s);
            if (!m.find()) {
                continue;
            }
            try {
                String varsRaw = m.group(1).trim();
                String operator = m.group(2).trim();
                String opArg = m.group(3).trim();
                String opts = m.group(4).trim();

                List<String> variables = Arrays.stream(varsRaw.split("\\|"))
                        .map(String::trim)
                        .collect(Collectors.toList());

                Map<String,String> optMap = parseOptions(opts);

                Rule.RuleBuilder rb = Rule.builder();
                rb.variables(variables);
                rb.operator(operator);
                rb.operatorArg(unescapeModSecString(opArg));

                if (optMap.containsKey("id")) rb.id(Long.parseLong(optMap.get("id")));
                if (optMap.containsKey("phase")) rb.phase(Integer.parseInt(optMap.get("phase")));
                if (optMap.containsKey("block")) rb.block(true);
                if (optMap.containsKey("capture")) rb.capture(true);
                if (optMap.containsKey("msg")) rb.msg(stripQuotes(optMap.get("msg")));
                if (optMap.containsKey("ver")) rb.ver(stripQuotes(optMap.get("ver")));
                if (optMap.containsKey("severity")) rb.severity(stripQuotes(optMap.get("severity")));

                List<String> transforms = extractTransforms(opts);
                rb.transforms(transforms);

                List<String> tags = extractTags(opts);
                rb.tags(tags);

                Map<String,String> setvars = extractSetVar(opts);
                rb.setvars(setvars);

                rules.add(rb.build());

            } catch (Exception ex) {
                log.warn("Failed to parse rule line: {} -> {}", l, ex.getMessage());
            }
        }
        return rules;
    }

    private static String stripQuotes(String s) {
        s = s.trim();
        if (s.startsWith("'") && s.endsWith("'")) return s.substring(1, s.length() - 1);
        if (s.startsWith("\"") && s.endsWith("\"")) return s.substring(1, s.length() - 1);
        return s;
    }

    private static String unescapeModSecString(String s) {
        return stripQuotes(s);
    }

    private static Map<String,String> parseOptions(String opts) {
        Map<String,String> map = new HashMap<>();
        List<String> parts = splitOutsideQuotes(opts, ',');
        for (String p : parts) {
            p = p.trim();
            if (p.isEmpty()) continue;
            if (p.contains(":")) {
                int idx = p.indexOf(":");
                String k = p.substring(0, idx).trim();
                String v = p.substring(idx + 1).trim();
                map.put(k, v);
            } else {
                map.put(p, "");
            }
        }
        return map;
    }

    private static List<String> extractTransforms(String opts) {
        List<String> transforms = new ArrayList<>();
        // Find tokens like t:none or t:urlDecodeUni inside opts
        for (String token : opts.split(",")) {
            token = token.trim();
            if (token.startsWith("t:")) {
                transforms.add(token.substring(2));
            }
        }
        return transforms;
    }

    private static List<String> extractTags(String opts) {
        List<String> tags = new ArrayList<>();
        Pattern p = Pattern.compile("tag:\'([^']+)\'|tag:\\"([^\"]+)\\\"");
        Matcher m = p.matcher(opts);
        while (m.find()) {
            if (m.group(1) != null) tags.add(m.group(1));
            else if (m.group(2) != null) tags.add(m.group(2));
        }
        return tags;
    }

    private static Map<String,String> extractSetVar(String opts) {
        Map<String,String> out = new HashMap<>();
        Pattern p = Pattern.compile("setvar:\'([^=]+)=([^']+)\'");
        Matcher m = p.matcher(opts);
        while (m.find()) {
            out.put(m.group(1).trim(), m.group(2).trim());
        }
        return out;
    }

    private static List<String> splitOutsideQuotes(String s, char delim) {
        List<String> pieces = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inSingle = false;
        boolean inDouble = false;
        for (char c : s.toCharArray()) {
            if (c == '\\'') inSingle = !inSingle;
            else if (c == '"') inDouble = !inDouble;
            if (c == delim && !inSingle && !inDouble) {
                pieces.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) pieces.add(cur.toString());
        return pieces;
    }
}
*/
        }
