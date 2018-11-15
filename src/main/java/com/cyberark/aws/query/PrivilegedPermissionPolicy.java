package com.cyberark.aws.query;

import java.util.Date;

public class PrivilegedPermissionPolicy {
    private String name;
    private Date version;
    private String sid;
    private String action;
    private String resource;


    public PrivilegedPermissionPolicy(String name, Date version, String sid, String action, String resource) {
        this.version = version;
        this.sid = sid;
        this.action = action;
        this.resource = resource;
    }



}
