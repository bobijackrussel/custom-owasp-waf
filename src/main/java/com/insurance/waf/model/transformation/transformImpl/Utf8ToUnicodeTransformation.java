package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.apache.commons.text.StringEscapeUtils;
;

public class Utf8ToUnicodeTransformation implements Transformation {

    @Override
    public String transform(String input) {
        return StringEscapeUtils.unescapeJava(input);
    }


    @Override
    public String toString(){
        return this.getClass().getName();
    }
}


// s = java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
