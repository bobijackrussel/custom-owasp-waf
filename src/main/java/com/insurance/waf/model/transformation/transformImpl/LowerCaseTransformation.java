package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;

public class LowerCaseTransformation implements Transformation {
    @Override
    public String transform(String input) {
        return input.toLowerCase();
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}