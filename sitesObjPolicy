# Role-based Access Control (ABAC)
# --------------------------------
#
# This example defines an ABAC model for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a classic Role-based Access Control model where users are assigned to roles and
# roles are granted the ability to perform some action(s) on some type of resource.
#

package policies.tenanta.app_patientapp.object_sitesobj
import future.keywords.in
default allow = false

allow {
    action_is_create
    is_rbac_based
permission_based
}

is_rbac_based {
    some i
    input.roles[_] == data.permissions[input.ccsname][input.appId][input.objectId].roleGrants[i].roleName
    input.permissions[k] == data.permissions[input.ccsname][input.appId][input.objectId].roleGrants[i].allowedGlobalActions[j]
}

allow {
    input.permissions[k] in {"UPDATE_STATUS","READ"}
    input.data.assignee == input.ocp_userid   
}

allow {
    input.permissions[k] in {"DELETE","READ","UPDATE"}
    input.data.createdBy == input.ocp_userid
}

action_is_create{
   input.permissions[k] == "CREATE"
}

permission_based {
some i
input.permissions[k] == data.permissions[input.ccsname][input.appId][input.objectId].roleGrants[i].allowedGlobalActions[j]
}
