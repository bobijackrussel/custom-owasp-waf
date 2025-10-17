package com.insurance.waf.model.opertion.operationImpl;

import com.insurance.waf.model.opertion.Operation;

import java.util.List;

public class BodyOperation extends Operation {

    List<Operation> operations;

    public BodyOperation(){
        super("",true);
    }

    @Override
    public boolean performOperation(Object o) {

        for (Operation operation : operations) {
            if(operation.performOperation(o)){
                return true;
            }
        }
        return false;
    }

    public void setOperations(List<Operation> ops){
        operations=ops;
    }
}
