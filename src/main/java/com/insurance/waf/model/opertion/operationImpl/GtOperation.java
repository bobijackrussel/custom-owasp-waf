package com.insurance.waf.model.opertion.operationImpl;

import com.insurance.waf.model.opertion.Operation;

public class GtOperation extends Operation {
    public GtOperation(String operand,boolean flag) {
        super(operand,flag);
    }


    @Override
    public boolean performOperation(Object o) {
        return  Integer.valueOf(getOperand())>(Integer)o & isFlag();
    }
}
