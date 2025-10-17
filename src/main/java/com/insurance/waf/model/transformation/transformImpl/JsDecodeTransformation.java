package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.unbescape.html.HtmlEscape;
import org.unbescape.javascript.JavaScriptEscape;

public class JsDecodeTransformation implements Transformation {

    @Override
    public String transform(String input) {
        return JavaScriptEscape.unescapeJavaScript(input);
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}