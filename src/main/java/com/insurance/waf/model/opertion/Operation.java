package com.insurance.waf.model.opertion;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public abstract class Operation {
    private String operand;
    private boolean flag;

    public abstract boolean performOperation(Object o);

    @Override
    public String toString(){
        return this.getClass().getName()+" operand:"+operand+" flag: "+flag;
    }
}
