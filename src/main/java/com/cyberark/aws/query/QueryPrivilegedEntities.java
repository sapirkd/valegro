package com.cyberark.aws.query;

import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class QueryPrivilegedEntities {

    //Map<String, PrivilegedPermissionPolicy> privilegedPoliciesMap = new HashMap<>();
    private static Map<String, List<AIMEntity>> privilegedPolicyEntities = new HashMap<>();


    /**
     * Gets an IAM policy's details
     */
    public static void main(String[] args) {

        final String USAGE =
                "To run this example, supply a policy arn\n" +
                        "Ex: GetPolicy <policy-arn>\n";

//            if (args.length != 1) {
//                System.out.println(USAGE);
//                System.exit(1);
//            }

//            String policy_arn = args[0];
        String policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess";

        final AmazonIdentityManagement iam =
                AmazonIdentityManagementClientBuilder.standard().withRegion("us-east-1").build();

//        GetPolicyRequest request = new GetPolicyRequest()
//                .withPolicyArn(policy_arn);
//
//        GetPolicyResult response = iam.getPolicy(request);
//
//        System.out.format("Successfully retrieved policy %s", response.getPolicy().getPolicyName());
//        System.out.format("Successfully retrieved policy %s", response.getPolicy());

        //Query managed policies

        List<Policy> managedPolicies = queryManagedPolicies(iam);

        //query inline policies


        List<Policy> privilegedPolicies = extractPrivilegedPolicies(managedPolicies);


        privilegedPolicies.forEach(policy -> extractPrivilegedPolicyUsers(iam, policy));
        privilegedPolicies.forEach(policy -> extractPrivilegedPolicyGroups(iam, policy));
        privilegedPolicies.forEach(policy -> extractPrivilegedPolicyRoles(iam, policy));


//        privilegedPolicies.forEach(policy -> listUsersForPolicy(iam, policy));
//        privilegedPolicies.forEach(policy -> listGroupsForPolicy(iam, policy));
//        privilegedPolicies.forEach(policy -> listRolesForPolicy(iam, policy));

        privilegedPolicyEntities.forEach((policy, entities) -> System.out.println(policy +  entities ));
        System.out.println(privilegedPolicyEntities.entrySet().stream().mapToInt(entry ->  entry.getValue().size()).sum());




//        AtomicInteger totalEntities = new AtomicInteger();
////        System.out.println("Total entities found: [" + privilegedPolicyEntities.forEach((policy, entities) -> {
////
////        }
//        );

    }


    private static void extractPrivilegedPolicyUsers(AmazonIdentityManagement aim , Policy privilegedPolicy)
    {
        System.out.println("extracting users for: ["+ privilegedPolicy.getPolicyName() +"]");
        List<AIMEntity> entities = listUsersForPolicy(aim, privilegedPolicy).stream()
                .map(policyUser -> buildUserEntityData(policyUser, privilegedPolicy))
                .collect(Collectors.toList());
        privilegedPolicyEntities.put(privilegedPolicy.getPolicyName(), entities);

    }

    private static AIMEntity buildUserEntityData(PolicyUser user, Policy policy)
    {
        AIMEntity entity = new AIMEntity();
        entity.setName(user.getUserName());
        entity.setPolicyName(policy.getPolicyName());
        entity.setType(EntityType.User);
        return entity;
    }


    private static void extractPrivilegedPolicyGroups(AmazonIdentityManagement aim , Policy privilegedPolicy)
    {
        System.out.println("extracting groups for: ["+ privilegedPolicy.getPolicyName() +"]");
        List<AIMEntity> entities = listGroupsForPolicy(aim, privilegedPolicy).stream()
                .map(policyGroup -> buildGroupEntityData(policyGroup, privilegedPolicy))
                .collect(Collectors.toList());
        privilegedPolicyEntities.put(privilegedPolicy.getPolicyName(), entities);

    }

    private static AIMEntity buildGroupEntityData(PolicyGroup group, Policy policy)
    {
        AIMEntity entity = new AIMEntity();
        entity.setName(group.getGroupName());
        entity.setPolicyName(policy.getPolicyName());
        entity.setType(EntityType.Group);
        return entity;
    }


    private static void extractPrivilegedPolicyRoles(AmazonIdentityManagement aim , Policy privilegedPolicy)
    {
        System.out.println("extracting roles for: ["+ privilegedPolicy.getPolicyName() +"]");
        List<AIMEntity> entities = listRolesForPolicy(aim, privilegedPolicy).stream()
                .map(policyRole -> buildRoleEntityData(policyRole, privilegedPolicy))
                .collect(Collectors.toList());
        privilegedPolicyEntities.put(privilegedPolicy.getPolicyName(), entities);
    }

    private static AIMEntity buildRoleEntityData(PolicyRole role, Policy policy)
    {
        AIMEntity entity = new AIMEntity();
        entity.setName(role.getRoleName());
        entity.setPolicyName(policy.getPolicyName());
        entity.setType(EntityType.Role);
        return entity;
    }




    private static List<PolicyUser> listUsersForPolicy(AmazonIdentityManagement iam, Policy policy) {
//        System.out.println("Users for policy: [" + policy.getPolicyName() + "]");
        ListEntitiesForPolicyRequest listEntitiesForPolicyRequest = createListEntitiesForPolicyRequest(policy, EntityType.User);
        ListEntitiesForPolicyResult listEntitiesForPolicyResult = iam.listEntitiesForPolicy(listEntitiesForPolicyRequest);
//        listEntitiesForPolicyResult.getPolicyUsers().forEach(user -> System.out.println(user.getUserName()));
        return listEntitiesForPolicyResult.getPolicyUsers();
    }




    private static List<PolicyGroup> listGroupsForPolicy(AmazonIdentityManagement iam, Policy policy) {
//        System.out.println("Groups for policy: [" + policy.getPolicyName() + "]");
        ListEntitiesForPolicyRequest listEntitiesForPolicyRequest = createListEntitiesForPolicyRequest(policy, EntityType.Group);
        ListEntitiesForPolicyResult listEntitiesForPolicyResult = iam.listEntitiesForPolicy(listEntitiesForPolicyRequest);
//        listEntitiesForPolicyResult.getPolicyGroups().forEach(policyGroup -> System.out.println(policyGroup.getGroupName()));
        return listEntitiesForPolicyResult.getPolicyGroups();
    }

    private static List<PolicyRole> listRolesForPolicy(AmazonIdentityManagement iam, Policy policy) {
//        System.out.println("Roles for policy: [" + policy.getPolicyName() + "]");
        ListEntitiesForPolicyRequest listEntitiesForPolicyRequest = createListEntitiesForPolicyRequest(policy, EntityType.Role);
        ListEntitiesForPolicyResult listEntitiesForPolicyResult = iam.listEntitiesForPolicy(listEntitiesForPolicyRequest);
//        listEntitiesForPolicyResult.getPolicyRoles().forEach(policyRole -> System.out.println(policyRole.getRoleName()));
        return listEntitiesForPolicyResult.getPolicyRoles();
    }


    private static ListEntitiesForPolicyRequest createListEntitiesForPolicyRequest(Policy policy, EntityType entityType) {
        ListEntitiesForPolicyRequest listEntitiesForPolicyRequest = new ListEntitiesForPolicyRequest();
        listEntitiesForPolicyRequest.withPolicyArn(policy.getArn());
        listEntitiesForPolicyRequest.setEntityFilter(entityType);
        return listEntitiesForPolicyRequest;
    }


    private static List<Policy> queryManagedPolicies(AmazonIdentityManagement iam) {
        ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
        listPoliciesRequest.setOnlyAttached(true);

        ListPoliciesResult listPoliciesResult = iam.listPolicies();
        return listPoliciesResult.getPolicies();
    }

    private static List<Policy> extractPrivilegedPolicies(List<Policy> allPolicies) {
        return allPolicies.stream().filter(policy -> isPolicyPrivileged(policy)).collect(Collectors.toList());

    }


    private static boolean isPolicyPrivileged(Policy policy) {
//       First, checking for the built-in privileged job functions policies:
//       Privileged built-in job functions:
//       AdministratorAccess - Provides full access to AWS services and resources - FullAWSAdmin
//       Billing - Grants permissions for billing and cost management. This includes viewing account ussage and viewing and modifying budgets and payment methods.
//       NetworkAdministrator - Grants full access permissions to AWS services and actions required to set up and configure AWS network resources.
//       DatabaseAdministrator - Grants full access permissions to AWS services and actions required to set up and configure AWS database services.
//       PowerUserAccess - Provides full access to AWS services and resources, but does not allow management of Users and groups.
//       SystemAdministrator - Grants full access permissions necessary for resources required for application and development operations.

        if(policy.getPolicyName().equals("AdministratorAccess"))
        {
            return true;
        }

        if(policy.getPolicyName().equals("NetworkAdministrator"))
        {
            return true;
        }

        if (policy.getPolicyName().equals("PSMP_Installation_Access_Policy"))
        {
            return true;
        }

        if (policy.getPolicyName().equals("StartStopEC2Instances"))
        {
            return true;
        }

        if (policy.getPolicyName().equals("AmazonEC2FullAccess"))
        {
            return true;
        }

        return false;
    }


}
