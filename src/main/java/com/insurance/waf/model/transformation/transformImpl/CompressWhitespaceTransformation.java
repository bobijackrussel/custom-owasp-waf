package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.apache.commons.lang3.StringUtils;

public class CompressWhitespaceTransformation implements Transformation {
    @Override
    public String transform(String input) {
        return StringUtils.normalizeSpace(input);
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}
