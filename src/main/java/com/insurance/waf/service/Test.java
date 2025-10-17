package com. insurance. waf. service;
import com.insurance.waf.model.transformation.transformImpl.*;
import com.insurance.waf.model.opertion.operationImpl.*;
import com.insurance.waf.model.Rule;
import com.insurance.waf.model.opertion.Operation;
import com.insurance.waf.model.transformation.*;



import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class Test {

    private final  static Pattern SECRULE_PATTERN=Pattern.compile("^SecRule\\s+(.+?)\\s+\\\"(.?@?)([^\\s\\\"]+)?\\s?(.*?)?\\\"\\s\\\"(.+)\\\"$");

    private final  static Set<String> targs=new HashSet<String>();

    public static List<Rule> parseFile(Path path) throws IOException {

        List<String> rawLines = Files.readAllLines(path);
        List<String> logical = joinContinuationsAndStripComments(rawLines);

        List<Rule> rules = new ArrayList<>();

        for (int i = 0; i < logical.size(); i++) {
            String ln = logical.get(i).trim();

            if (ln.isEmpty())
                continue;

            if (ln.startsWith("SecRule")) {
                Rule r = parseSecRuleLine(ln);
                if (r != null && r.isChained())
                    {
                    if (i + 1 < logical.size())
                    {
                        String next = logical.get(i + 1).trim();
                        if (next.startsWith("SecRule"))
                        {
                            Rule chained = parseSecRuleLine(next);
                            r.setChainedRule(chained);
                            i++;
                        }
                    }
                }
                if (r != null)
                    rules.add(r);
            }
        }
        //rules.forEach(System.out::println);

        return rules;
    }

    private static List<String> joinContinuationsAndStripComments(List<String> rawLines) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();

        for (String raw : rawLines) {
            String line = raw;
            String trimmed = line.trim();
            if (trimmed.startsWith("#") || trimmed.isEmpty()) {
                continue;
            }

            if (line.matches("(?s).*\\\\\\s*$")) {

                line = line.replaceFirst("\\\\\\s*$", "");
                if (cur.length() > 0) cur.append(" ");
                cur.append(line.trim());

                continue;
            } else {
                if (cur.length() > 0) {
                    cur.append(" ");
                    cur.append(line.trim());
                    out.add(cur.toString().trim());
                    cur.setLength(0);
                }
                else {
                    out.add(line.trim());
                }
            }
        }
        if (cur.length() > 0) {
            out.add(cur.toString().trim());
        }

        return out;
    }

    private static Rule parseSecRuleLine(String ln) {
        Matcher m = SECRULE_PATTERN.matcher(ln);

        if(m.find()){
            Rule rule = new Rule();

            String targets=m.group(1);
            String negation=m.group(2);
            String operator=m.group(3);
            String operand=m.group(4)!=null?m.group(4):"";
            String actions=m.group(5);

            rule.setTargets(parseTargets(targets));
            rule.setOperation(matchOperation(operator,operand,negation));
            parseActionsTokens(actions,rule);

            return rule;
        }
        return null;
    }

    private static Operation matchOperation(String operator, String operand,String negation) {
        Operation o;
        boolean flag=true;

        if(negation.startsWith("!"))
            flag=false;

        switch (operator){
            case "rx":
                o=new RxOperation(operand,flag);
                break;
            case "lt":
                o=new LtOperation(operand,flag);
                break;
            case "gt":
                o=new GtOperation(operand,flag);
                break;
            case "contains":
                o=new CntOperation(operand,flag);
                break;
            case "streq":
                o=new EqOperation(operand,flag);
                break;
            case "detectXSS":
                o=new BodyOperation();
                break;
            default:
                System.out.println("Operator doesnt exist:"+ operator);
                o=null;
        }
        return o;
    }

    private static List<String> parseTargets(String src) {
        return Arrays.stream(src.trim().split("\\|"))
                .map(String::trim)
                .map(s->s.split(":")[0])
                .filter(t->!t.isEmpty())
                .collect(Collectors.toList());
    }

    private static void parseActionsTokens(String actions, Rule r) {
        List<String> tokens = splitRespectingSingleQuotes(actions);
        for (String rawTok : tokens) {
            String tok = rawTok.trim();
            if (tok.isEmpty())
                continue;

            if (tok.contains(":")) {
                String key = tok.substring(0, tok.indexOf(':')).trim();
                String val = tok.substring(tok.indexOf(':') + 1).trim();
                val = stripQuotes(val);

                switch (key) {
                    case "id":
                        r.setId(val);
                        break;
                    case "phase":
                        try { r.setPhase(Integer.parseInt(val)); } catch (NumberFormatException ignored) {}
                        break;
                    case "t": {
                        List<String> trans= Arrays.stream(val.split(","))
                                                  .filter(s->!s.isEmpty())
                                                  .map(String::trim).toList();

                        for(String transformation:trans) {
                            r.getTransforms().add(matchTransformation(transformation));
                        }
                        break;
                    }
                    case "logdata":
                        r.setLogData(val);
                        break;
                    case "msg":
                        r.setMsg(val);
                        break;
                    case "tag":
                        r.getTags().add(val);
                        break;
                    case "severity":
                        r.setSeverity(val);
                        break;
                    case "setvar":
                        r.getSetvar().add(val);
                        break;
                    case "ctl":
                    case "skipAfter":
                    case "ver":
                        r.getOther().put(key, val);
                        break;
                    default:
                        r.getOther().put(key, val);
                        break;
                }
            } else {
                String flag = tok.toLowerCase(Locale.ROOT);
                switch (flag) {
                    case "block":
                    case "pass":
                        r.setAction(flag);
                        break;
                    case "capture":
                        r.setCapture(true);
                        break;
                    case "nolog":
                        r.getOther().put("nolog", "true");
                        break;
                    case "chain":
                        r.setChained(true);
                        break;
                    default:
                            r.getOther().put(flag, "true");

                }
            }
        }
    }

    private static Transformation matchTransformation(String val) {
        val=val.toUpperCase();
        return  switch (val) {
            case "NONE"->new NoTransformation();
            case "UTF8TOUNICODE"-> new Utf8ToUnicodeTransformation();
            case "URLDECODEUNI"-> new UrlDecodeUniTransforamtion();
            case "HTMLENTITYDECODE"-> new HtmlEntityDecodeTransformation();
            case "JSDECODE"->new JsDecodeTransformation();
            case "CSSDECODE"-> new CssDecodeTransformation();
            case "REMOVENULLS"->new RemoveNullsTransformation();
            case "REMOVEWHITESPACE"-> new RemoveWhitespaceTransformation();
            case "LOWERCASE"-> new LowerCaseTransformation();
            case "COMPRESSWHITESPACE"-> new CompressWhitespaceTransformation();
            default -> input ->"";
        };
    }

    private static List<String> splitRespectingSingleQuotes(String s) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inSingle = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\'') {
                inSingle = !inSingle;
                cur.append(c);
            } else if (c == ',' && !inSingle) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out.stream().map(String::trim).collect(Collectors.toList());
    }

    private static String stripQuotes(String v) {
        if (v == null) return null;
        v = v.trim();
        if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith("\"") && v.endsWith("\""))) {
            if (v.length() >= 2) return v.substring(1, v.length() - 1);
        }
        return v;
    }

    public static void main(String[] args) throws Exception {

        Path p = Paths.get("C:\\Users\\User\\Downloads\\REQUEST-941-APPLICATION-ATTACK-XSS.conf");
        List<Rule> rules = parseFile(p);
        System.out.println("Parsed rules: " + rules.size());

        for (int i = 0; i < rules.size(); i++) {
            if(rules.get(i).getOperation()!=null&&rules.get(i).getOperation().isFlag()==false)
                System.out.println("[" + i + "] " + rules.get(i).getOperation());
        }

        for(String s: targs){
            System.out.println(s);
        }

    }

}
