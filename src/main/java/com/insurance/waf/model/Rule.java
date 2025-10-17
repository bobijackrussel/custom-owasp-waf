package com.insurance.waf.model;

import com.insurance.waf.model.opertion.Operation;
import com.insurance.waf.model.transformation.Transformation;
import lombok.Getter;
import lombok.Setter;
import java.util.*;

@Getter
@Setter
public class Rule {

    private String id;
    private Integer phase;

    private List<String> targets = new ArrayList<>();
    private Operation operation;
    private String action;
    private List<Transformation> transforms = new ArrayList<>();

    private boolean capture;
    private boolean chained;

    private String msg;
    private String logData;
    private List<String> tags = new ArrayList<>();
    private String ver;
    private String severity;
    private List<String> setvar = new ArrayList<>();
    private Map<String, String> other = new LinkedHashMap<>();

    private Rule chainedRule;

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Rule{")
                .append("id='").append(id).append('\'')
                .append(", phase=").append(phase)
                .append(", targets=").append(targets)
                .append(", operation=").append(operation)
                .append(", action='").append(action).append('\'')
                .append(", transforms=").append(transforms)
                .append(", capture=").append(capture)
                .append(", chained=").append(chained)
                .append(", msg='").append(msg).append('\'')
                .append(", logData='").append(logData).append('\'')
                .append(", tags=").append(tags)
                .append(", ver='").append(ver).append('\'')
                .append(", severity='").append(severity).append('\'')
                .append(", setvar=").append(setvar)
                .append(", other=").append(other);

        if (chainedRule != null) {
            sb.append(", chainedRule=").append(chainedRule.id != null ? "Rule(id=" + chainedRule.id + ")" : "Rule");
        }

        sb.append('}');
        return sb.toString();
    }

}