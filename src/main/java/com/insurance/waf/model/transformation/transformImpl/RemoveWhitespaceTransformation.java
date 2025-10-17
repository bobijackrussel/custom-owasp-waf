package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.unbescape.javascript.JavaScriptEscape;

public class RemoveWhitespaceTransformation implements Transformation {

    @Override
    public String transform(String input) {
        return input.replaceAll("\\s+", " ");
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}
