package com.insurance.waf.model.opertion.operationImpl;

import com.insurance.waf.model.opertion.Operation;

import java.util.regex.Pattern;

public class RxOperation extends Operation {

    public RxOperation(String operand,boolean flag) {
        super(operand,flag);
    }

    @Override
    public  boolean performOperation(Object parametar) {
      //  if(Pattern.compile(getOperand()).matcher((String) parametar).find() & super.isFlag()) System.out.println(parametar+":"+getOperand());
        return Pattern.compile(getOperand()).matcher((String) parametar).find() & super.isFlag();
        }
    }