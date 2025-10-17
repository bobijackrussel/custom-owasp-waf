package com.insurance.waf.model.transformation.transformImpl;

import com.insurance.waf.model.transformation.Transformation;
import org.unbescape.uri.UriEscape;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class UrlDecodeUniTransforamtion implements Transformation {

    @Override
    public String transform(String input){
       try {
           return URLDecoder.decode(input, StandardCharsets.UTF_8.name());
       }
       catch (Exception e){
        System.out.println("Something went wrong while decoding!");
           return input;
       }
        //return UriEscape.unescapeUriQueryParam(input);
    }

    @Override
    public String toString(){
        return this.getClass().getName();
    }
}
