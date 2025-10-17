package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.unbescape.html.HtmlEscape;

public class HtmlEntityDecodeTransformation implements Transformation {

    @Override
    public String transform(String input) {
        return HtmlEscape.unescapeHtml(input);
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}
