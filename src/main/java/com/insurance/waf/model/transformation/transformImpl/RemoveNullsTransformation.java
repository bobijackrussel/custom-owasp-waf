package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.unbescape.javascript.JavaScriptEscape;

public class RemoveNullsTransformation implements Transformation {

    @Override
    public String transform(String input) {
        return input.replace("\u0000","");
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}