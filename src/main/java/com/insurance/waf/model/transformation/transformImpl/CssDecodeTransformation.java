package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.unbescape.css.CssEscape;

public class CssDecodeTransformation  implements Transformation {

    @Override
    public String transform(String input) {
        return CssEscape.unescapeCss(input);
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}
