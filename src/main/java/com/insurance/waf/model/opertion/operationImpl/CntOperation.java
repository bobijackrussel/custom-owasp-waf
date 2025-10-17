package com.insurance.waf.model.opertion.operationImpl;

import com.insurance.waf.model.opertion.Operation;

public class CntOperation extends Operation {

    public CntOperation(String operand,boolean flag) {
        super(operand,flag);
    }

    @Override
    public boolean performOperation(Object parameter) {
        return getOperand().contains((String)parameter) & isFlag();
    }


}
