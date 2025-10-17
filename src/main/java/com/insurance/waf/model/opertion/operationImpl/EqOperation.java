package com.insurance.waf.model.opertion.operationImpl;

import com.insurance.waf.model.opertion.Operation;

public class EqOperation  extends Operation {

    public EqOperation(String operand,boolean flag) {
        super(operand,flag);
    }

    @Override
    public boolean performOperation(Object parameter) {
        return getOperand().equals((String)parameter) & isFlag();
    }


}
