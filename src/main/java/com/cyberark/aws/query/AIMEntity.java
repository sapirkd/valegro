package com.cyberark.aws.query;

import com.amazonaws.services.identitymanagement.model.EntityType;

public class AIMEntity {

    private String name;
//    private String arn;
    private EntityType type;
//    private String privilegeType;
    private String policyName;
//    private boolean isPrivileged;
//    private PrivilegedPermissionPolicy privilegedPermissionPolicy;

    public AIMEntity()
    {

    }



    public AIMEntity(String name, String arn, EntityType type, String privilegeType, String policyName, boolean isPrivileged,
                     PrivilegedPermissionPolicy privilegedPermissionPolicy)
    {
        this.name = name;
//        this.arn = arn;
        this.type = type;
//        this.privilegeType = privilegeType;
        this.policyName = policyName;
//        this.isPrivileged = isPrivileged;
//        this.privilegedPermissionPolicy = privilegedPermissionPolicy;
    }


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }


    public EntityType getType() {
        return type;
    }

    public void setType(EntityType type) {
        this.type = type;
    }



    public String getPolicyName() {
        return policyName;
    }

    public void setPolicyName(String policyName) {
        this.policyName = policyName;
    }

}
