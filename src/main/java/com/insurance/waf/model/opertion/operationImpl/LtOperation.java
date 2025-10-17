package com.insurance.waf.model.opertion.operationImpl;

import com.insurance.waf.model.opertion.Operation;

public class LtOperation extends Operation {

    public LtOperation(String operand,boolean flag) {
        super(operand,flag);
    }

    @Override
    public boolean performOperation(Object parameter) {
        System.out.println(getOperand()+"<"+parameter);
        return Integer.valueOf(getOperand())<(Integer)parameter & isFlag();
    }
}
