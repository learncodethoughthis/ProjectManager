package com.ProjectManagement.ProjectManagement.Mailing;

import lombok.Data;
import java.util.*;
@Data
public abstract class AbstractEmailContext {
    private String from;
    private String to;
    private String subject;
    private String templateLocation;
    private Map<String, Object> context;

    public AbstractEmailContext() {
        this.context = new HashMap<>();
    }

    public <T> void init(T context) {
    }

    public Object put(String key, Object value) {
        return context.put(key, value);
    }
}
