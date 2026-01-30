<#
    .SYNOPSIS
    Helper functions used by the main flow or by the different sub-modules
#>

############################## Static variables ########################

$global:GLOBALMainTableDetailsHEAD = @'
<div id="mainTableContainer">
  <label>
    <select id="pageSize">
      <option value="1000">1000</option>
      <option value="5000">5000</option>
      <option value="10000">10000</option>
    </select>
  </label>
  <div id="tableWrapper"></div>
  <div id="paginationControls"></div>
</div>
<script id="mainTableData" type="application/json">
'@

# JavaScript for improved HTML table output
$global:GLOBALJavaScript_Table = @'
    <script>
        // Predefined Views
        const predefinedViews = {
            "User": [
                {
                    label: "Inactive Users",
                    filters: {
                        Inactive: "=true",
                        Enabled: "=true"
                    },
                    columns: ["UPN", "Enabled", "UserType", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                },
                {
                    label: "Users with Roles (Entra ID / Azure)",
                    filters: {
                        AzureRoles: "or_>0",
                        EntraRoles: "or_>0",
                        Warnings: "or_EntraRoles||AzureRoles"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "OnPrem", "EntraRoles", "AzureRoles", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Users with Roles (Entra ID only)",
                    filters: {
                        EntraRoles: "or_>0",
                        Warnings: "or_EntraRoles"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "OnPrem", "EntraRoles", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Users Without MFA Methods",
                    filters: {
                        MfaCap: "=false",
                    }
                },
                {
                    label: "Privileged Unprotected Users",
                    filters: {
                        Protected: "=false",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        AppRegOwn: "or_>0",
                        SPOwn: "or_>0"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "EntraRoles", "AzureRoles", "Inactive", "AppRegOwn", "SPOwn", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "New Users",
                    columns: ["UPN", "Enabled", "UserType", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "CreatedDays", direction: "asc" }
                },
                {
                    label: "Guest Users",
                    filters: {
                        UserType: "=Guest"
                    },
                    columns: ["UPN", "Enabled", "UserType", "GrpMem", "GrpOwn", "AppRegOwn", "SpOwn", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                  {
                    label: "User Owning Applications",
                    filters: {
                        AppRegOwn: "or_>0",
                        SPOwn: "or_>0"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "AppRegOwn", "SpOwn", "Inactive", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Entra Connect Accounts",
                    filters: {
                        UPN: "^Sync_||^ADToAADSyncServiceAccount"
                    },
                    columns: ["UPN", "Enabled", "GrpMem", "GrpOwn", "AppRegOwn", "SpOwn", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                }
            ],
            "Groups": [
                {
                    label: "Groups Tier-0",
                    filters: { Warnings: "tier0" },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "AuUnits", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Public M365 Groups",
                    filters: { Visibility: "=Public", Type: "=M365 Group", Dynamic: "=false" },
                    columns: ["DisplayName", "Type", "SecurityEnabled", "Visibility", "Users", "AzureRoles", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Dynamic Groups",
                    filters: { Dynamic: "=true"},
                    columns: ["DisplayName", "Type", "Dynamic", "SecurityEnabled", "Visibility", "Users", "Devices", "AzureRoles", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Privileged Unprotected Groups",
                    filters: {
                        Protected: "=false",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        CAPs: "or_>0",
                        Warnings: "or_Eligible"
                    },
                    columns: ["DisplayName", "Type", "Dynamic", "Protected", "SecurityEnabled", "Visibility", "Users", "Devices", "AzureRoles", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Groups Used in CAPs",
                    filters: {
                        CAPs: "or_>0",
                        Warnings: "or_used in CAP"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "Visibility", "Users", "Devices", "NestedGroups", "NestedInGroups", "CAPs", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Groups Owned by Guests",
                    filters: {
                        Warnings: "Guest as owner"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "Users", "AzureRoles", "EntraRoles", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Groups Onboarded to PIM",
                    filters: { PIM: "=true" },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "PIM for Groups PrivEsc",
                    filters: {
                        PIM: "=true",
                        Protected: "=true",
                        Warnings: "contains unprotected groups"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "AuUnits", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Interesting Groups by Keywords",
                    filters: {
                        DisplayName: "admin||subscription||owner||contributor||secret||geheim||keyvault||passwor"
                    },
                    columns: ["DisplayName", "Type", "Dynamic", "DirectOwners", "PIM", "NestedOwners", "Protected", "SecurityEnabled", "Visibility", "Users", "Guests", "SPCount", "Devices", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                }

            ],
            "Enterprise Apps": [
                {
                    label: "Foreign Apps: Privileged",
                    filters: { 
                        Foreign: "=True", 
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_delegated API permission||through group"
                    },
                    columns: ["DisplayName", "PublisherName", "Enabled", "Inactive", "Foreign", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Foreign Apps: Extensive API Privs (Application)",
                    filters: { 
                        Foreign: "=True", 
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Foreign Apps: Extensive API Privs (Delegated)",
                    filters: { 
                        Foreign: "=True", 
                        ApiDelegated: ">0",
                        Warnings: "delegated API permission"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Foreign Apps: With Roles",
                    filters: { 
                        Foreign: "=True", 
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Internal Apps: Privileged",
                    filters: { 
                        Foreign: "=False", 
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_delegated API permission||through group"
                    },
                    columns: ["DisplayName", "Foreign", "Enabled", "Inactive", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Apps with Credentials (Excludes SAML)",
                    filters: {
                        Credentials: ">0",
                        SAML: "=false",
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "SAML", "Credentials", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Apps with Owners",
                    filters: {
                        Owners: ">0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Owners", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Inactive Apps",
                    filters: {
                        Inactive: "=true",
                        Enabled: "=true"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "LastSignInDays", "CreationInDays", "Owners", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                },
                {
                    label: "Entra Connect Application",
                    filters: { 
                        DisplayName: "^ConnectSyncProvisioning_"
                    },
                    columns: ["DisplayName", "Enabled", "Inactive", "Owners", "Credentials", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                }
            ],
            "Managed Identities": [
                {
                    label: "Privileged Managed Identities",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_through group"
                    }
                },
                {
                    label: "Managed Identities: Extensive API Privs",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0"
                    }
                },
                {
                    label: "Managed Identities: With Roles",
                    filters: {
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0"
                    }
                }
            ],
            "App Registrations": [
                {
                    label: "Apps with Owners",
                    filters: {
                        OwnerCount: ">0"
                    }
                },
                {
                    label: "Apps Controlled by App Admins",
                    filters: {
                        CloudAppAdmins: "or_>0",
                        AppAdmins: "or_>0"
                    },
                    sort: { column: "Impact", direction: "desc" }
                },
                {
                    label: "App with Secrets",
                    filters: {
                        SecretsCount: ">0"
                    }
                },
                {
                    label: "App Not Protected by AppLock",
                    filters: {
                        AppLock: "=false"
                    }
                },
                {
                    label: "Multitenant Apps",
                    filters: {
                        SignInAudience: "AzureADandPersonalMicrosoftAccount||AzureADMultipleOrgs"
                    }
                },
                {
                    label: "Entra Connect Application",
                    filters: { 
                        DisplayName: "^ConnectSyncProvisioning_"
                    }
                }

            ],
            "Conditional Access Policies": [
                {
                    label: "Enabled Policies",
                    filters: {
                        State: "=enabled"
                    }
                },
                {
                    label: "Blocking Policies",
                    filters: {
                        GrantControls: "=block"
                    }
                },
                {
                    label: "MFA Policies",
                    filters: {
                        GrantControls: "mfa"
                    }
                },
                {
                    label: "Authentication Strength Policies",
                    filters: {
                        AuthStrength: "!=empty"
                    }
                },
                {
                    label: "Device Registration Policies",
                    filters: {
                        UserActions: "urn:user:registerdevice"
                    }
                },
                {
                    label: "Security Info Registration Policies",
                    filters: {
                        UserActions: "urn:user:registersecurityinfo"
                    }
                },
                {
                    label: "Legacy Authentication Policies",
                    filters: {
                        AppTypes: "exchangeActiveSync||other"
                    }
                },                
                {
                    label: "Device Code Flow Policies",
                    filters: {
                        AuthFlow: "deviceCodeFlow"
                    }
                },                
                {
                    label: "Network Location Policies",
                    filters: {
                        IncNw: "or_!=0",
                        ExcNw: "or_!=0"
                    }
                },                
                {
                    label: "Session Control Policies",
                    filters: {
                        SessionControls: ">0"
                    }
                }
            ],
            "Role Assignments Entra ID": [
                {
                    label: "Eligible Assignments",
                    filters: {
                        AssignmentType: "=Eligible"
                    }
                },
                {
                    label: "Active Assignments",
                    filters: {
                        AssignmentType: "Active"
                    }
                },
                {
                    label: "Tier-0 Assignments",
                    filters: {
                        RoleTier: "=Tier-0"
                    }
                },
                {
                    label: "Service Principal Assignments",
                    filters: {
                        PrincipalType: "Managed Identity||Enterprise Application"
                    }
                },
                {
                    label: "Scoped Assignments",
                    filters: {
                        Scope: "!=/ (Tenant)"
                    }
                },
                {
                    label: "Custom Roles",
                    filters: {
                        RoleType: "=CustomRole"
                    }
                }
            ],
            "Role Assignments Azure IAM": [
                {
                    label: "Eligible Assignments",
                    filters: {
                        AssignmentType: "=Eligible"
                    }
                },
                {
                    label: "Active Assignments",
                    filters: {
                        AssignmentType: "Active"
                    }
                },
                {
                    label: "Additional Conditions",
                    filters: {
                        Conditions: "=true"
                    }
                },
                {
                    label: "Service Principal Assignments",
                    filters: {
                        PrincipalType: "ServicePrincipal"
                    }
                },
                {
                    label: "Custom Roles",
                    filters: {
                        RoleType: "=CustomRole"
                    }
                }
            ],
            "PIM": [
                {
                    label: "Tier 0 Roles: With Warnings",
                    filters: {
                        Tier: "=Tier-0",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                },
                {
                    label: "Tier 0 Roles: No Auth Context",
                    filters: {
                        Tier: "=Tier-0",
                        ActivationAuthContext: "=false"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "Warnings"]
                },
                {
                    label: "Tier 0 Roles: Activation Duration >4 Hours",
                    filters: {
                        Tier: "=Tier-0",
                        ActivationDuration	: ">4"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationDuration", "Warnings"]
                },
                {
                    label: "Tier 0 Roles: Only Active Assignments",
                    filters: {
                        Tier: "Tier-0",
                        Eligible: "=0",
                        Active: ">0"
                    },
                    columns: ["Role", "Tier", "Eligible", "Active"]
                },
                {
                    label: "Tier 0/1 Roles: With Warnings",
                    filters: {
                        Tier: "Tier-0 || Tier-1",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                },
                {
                    label: "Used Tier 0/1 Roles (Eligible): With Warnings",
                    filters: {
                        Eligible: ">0",
                        Tier: "Tier-0 || Tier-1",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                },
                {
                    label: "Tier 0/1 Roles: Only Active Assignments",
                    filters: {
                        Tier: "Tier-0 || Tier-1",
                        Eligible: "=0",
                        Active: ">0"
                    },
                    columns: ["Role", "Tier", "Eligible", "Active"]
                },
                {
                    label: "Used Roles (Eligible): With Warnings",
                    filters: {
                        Eligible: ">0",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                }
            ]
        };

        //Define columns which are hidden by default
        const defaultHidden = ["DeviceReg", "DeviceOwn", "LicenseStatus", "OwnersSynced", "DefaultMS", "CreationInDays", "AppRoleRequired", "SAML", "RoleAssignable", "LastSignInDays", "CreatedDays","ActiveAssignJustification","AlertAssignEligible","AlertAssignActive", "AlertActivation", "EligibleExpirationTime", "ActiveExpirationTime", "SignInFrequency", "SignInFrequencyInterval"];

        // Function to obtain the GET parameters from the URL
        function getURLParams() {
            const params = new URLSearchParams(window.location.search);
            const result = {};
            for (const [key, value] of params.entries()) {
                result[key] = value;
            }
            return result;
        }

        //Tooltips for column headers
        const columnTooltips = {
            "AuUnits": "Administrative Units",
            "Impact": "Score representing the potential impact if the object is compromised",
            "Likelihood": "Score representing the likelihood of compromise",
            "Risk": "Calculation: Impact x Likelihood",
            "OnPrem": "Objects synced from on-prem AD",
            "AzureRoles": "Directly or indirectly assigned Azure IAM roles",
            "EntraRoles": "Directly or indirectly assigned Entra ID roles",
            "SAML": "SAML as preferred SSO method",
            "CAPs": "Number of Conditional Access Policies the group is used in",
            "AppLock": "App Instance Property Lock status",
            "DeviceReg": "Devices registered by the user",
            "DeviceOwn": "Devices owned by the user",
            "AppAdmins": "App Admins scoped to tenant or app",
            "CloudAppAdmins": "Cloud App Admins scoped to tenant or app",
            "MfaCap": "User has one or more MFA methods registered",
            "Inactive": "No successful sign-in during the last 180+ days",
            "AppRoles": "Application roles assigned",
            "GrpMem": "Member of groups",
            "GrpOwn": "Owner of groups",
            "SpOwn": "Owned Service Principals",
            "AppOwn": "Owned App Registrations",
            "AppRegOwn": "Owner of App Registrations",
            "SPOwn": "Owner of ServicePrincipals",
            "ApiDeleg": "Unique consented delegated API permissions",
            "PIM": "Onboarded to PIM for Groups",
            "Protected": "Cannot be modified by low-tier admins",
            "AssignmentType": "Activated eligible assignments also appear as active",
            "Conditions": "Has additional conditions"
        };
    
        (function () {    
            const manifestEl = document.getElementById("report-manifest");
            const manifest = manifestEl && manifestEl.textContent ? JSON.parse(manifestEl.textContent) : null;
            window.__reportManifest = manifest;        

            const mainTableDataEl = document.getElementById("mainTableData");
            if (!mainTableDataEl) {
                return;
            }
                
            const container = document.getElementById("mainTableContainer");
            if (!container) {
                return;
            }
                
            let data = JSON.parse(document.getElementById("mainTableData").textContent);
            if (!Array.isArray(data)) {
                data = [data]; // wrap single object into an array
            }

            const rowLowerKeyMap = Object.keys(data[0] || {}).reduce((map, col) => {
                map[col.toLowerCase()] = col;
                return map;
            }, {});

            const columns = Object.keys(data[0] || {});
            const colIndexMap = {};
            for (let i = 0; i < columns.length; i++) {
                colIndexMap[columns[i]] = i;
            }

            const wrapper = container.querySelector("#tableWrapper");
            const pageSizeSelector = container.querySelector("#pageSize");
            const pagination = container.querySelector("#paginationControls");

            let currentPage = 1;
            let rowsPerPage = parseInt(pageSizeSelector.value);
            let filteredData = [...data];
            let currentSort = { column: null, asc: true };
            let columnFilters = {};
            let hiddenColumns = new Set();
            let filterDebounceTimer = null;

            container.addEventListener("input", (e) => {
                const input = e.target;
                if (!input || input.tagName !== "INPUT") return;

                const col = input.getAttribute("data-filter");
                if (!col) return;

                const existingKey = Object.keys(columnFilters).find(k => k.toLowerCase() === col.toLowerCase());
                columnFilters[existingKey || col] = input.value;

                if (filterDebounceTimer) window.clearTimeout(filterDebounceTimer);
                filterDebounceTimer = window.setTimeout(() => {
                    filterData();
                }, 800);
            });


            const columnSelector = document.createElement("div");
            const exportBtn = document.createElement("button");
            const infoBox = document.createElement("div");

            exportBtn.textContent = "\u{1F4BE} Export CSV";
            exportBtn.style.margin = "10px 0";
            infoBox.style.margin = "10px 0";

            exportBtn.onclick = () => {
            const csvRows = [];
            const visibleColumns = getVisibleColumns();
            const special = isRoleAssignmentsReport(window.__reportManifest);

            // ---------------------------
            // RoleAssignmentReports: just visible columns
            // ---------------------------
            if (special) {
                csvRows.push(visibleColumns.join(","));

                filteredData.forEach(row => {
                const line = [];

                visibleColumns.forEach(col => {
                    let val = row[col];

                    // Make Principal human-readable
                    if (col.toLowerCase() === "principal") {
                    val = stripHtmlToText(val);
                    }

                    line.push(`"${String(val ?? "").replace(/"/g, '""')}"`);
                });

                csvRows.push(line.join(","));
                });
            }
            // ---------------------------
            // NORMAL REPORTS: add ID + DisplayName from FIRST COLUMN LINK
            // ---------------------------
            else {
                const linkColumn = columns[0];
                const restVisible = visibleColumns.filter(c => c !== linkColumn);

                csvRows.push(["ID", "DisplayName", ...restVisible].join(","));

                filteredData.forEach(row => {
                const line = [];

                const { id, text } = extractAnchorIdAndText(row[linkColumn]);
                line.push(`"${String(id).replace(/"/g, '""')}"`);
                line.push(`"${String(text).replace(/"/g, '""')}"`);

                restVisible.forEach(col => {
                    const val = row[col];
                    line.push(`"${String(val ?? "").replace(/"/g, '""')}"`);
                });

                csvRows.push(line.join(","));
                });
            }

            // download
            const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;

            const baseName = decodeURIComponent(window.location.pathname
                .split("/")
                .pop()
                .replace(/\.[^/.]+$/, "")) || "export";

            a.download = `${baseName}_table_export.csv`;
            a.click();
            URL.revokeObjectURL(url);
            };



        function applyPredefinedView(view) {
            columnFilters = {};

            // Filters
            Object.entries(view.filters || {}).forEach(([col, val]) => {
                const match = columns.find(k => k.toLowerCase() === col.toLowerCase());
                columnFilters[match || col] = val;
            });

            // Columns
            if (Array.isArray(view.columns)) {
                const allCols = columns;
                const allowed = view.columns
                    .map(v => allCols.find(col => col.toLowerCase() === v.toLowerCase()))
                    .filter(Boolean); // Only valid column names

                if (allowed.length > 0) {
                    hiddenColumns = new Set(allCols.filter(col => !allowed.includes(col)));
                } else {
                    console.warn("No valid matching columns found in view.columns");
                }
            }

            // Sort
            if (view.sort) {
                const sortCol = columns.find(k => k.toLowerCase() === view.sort.column.toLowerCase());
                if (sortCol) {
                    currentSort.column = sortCol;
                    currentSort.asc = view.sort.direction.toLowerCase() !== "desc";
                }
            }

            filterData();
            createColumnSelector();
        }

        function getReportTypeFromManifest(manifest) {
            if (!manifest) return null;

            var key = String(manifest.currentReportKey || "").trim();
            var name = String(manifest.currentReportName || "").trim();

            if (key === "Users") return "User";
            if (key === "Groups") return "Groups";
            if (key === "EA") return "Enterprise Apps";
            if (key === "MI") return "Managed Identities";
            if (key === "AR") return "App Registrations";
            if (key === "CAP") return "Conditional Access Policies";
            if (key === "PIM") return "PIM";
            if (key === "RoleEntra") return "Role Assignments Entra ID";
            if (key === "RoleAz") return "Role Assignments Azure IAM";

            var lower = name.toLowerCase();
            if (lower.indexOf("users") !== -1) return "User";
            if (lower.indexOf("groups") !== -1) return "Groups";
            if (lower.indexOf("enterprise") !== -1) return "Enterprise Apps";
            if (lower.indexOf("managed identit") !== -1) return "Managed Identities";
            if (lower.indexOf("app registr") !== -1) return "App Registrations";
            if (lower.indexOf("conditional access") !== -1) return "Conditional Access Policies";
            if (lower.indexOf("pim") !== -1) return "PIM";
            if (lower.indexOf("role assignments entra") !== -1) return "Role Assignments Entra ID";
            if (lower.indexOf("role assignments azure") !== -1) return "Role Assignments Azure IAM";

            return null;
        }

        function isRoleAssignmentsReport(manifest) {
            var type = getReportTypeFromManifest(manifest);
            return type === "Role Assignments Entra ID" || type === "Role Assignments Azure IAM";
        }


        function stripHtmlToText(html) {
            if (html == null) return "";
            const tempDiv = document.createElement("div");
            tempDiv.innerHTML = String(html);
            return (tempDiv.textContent || tempDiv.innerText || "").trim();
            }

            // Extract GUID + visible text from "<a href=#GUID>Text</a>"
            function extractAnchorIdAndText(cellValue) {
            if (cellValue == null) return { id: "", text: "" };
            const s = String(cellValue);

            // Normal reports: <a href=#GUID>...</a>
            const m = s.match(/<a\s+href=#([a-f0-9-]{36})[^>]*>(.*?)<\/a>/i);
            if (m) return { id: m[1], text: stripHtmlToText(m[2]) };

            // Fallback: treat as plain text
            return { id: "", text: stripHtmlToText(s) };
        }

        function createPresetFilterModal(manifest) {
            var type = getReportTypeFromManifest(manifest);
            if (!type) return;

            var views = predefinedViews[type];
            if (!views || !views.length) return;

            const presetBtn = document.createElement("button");
            presetBtn.textContent = "\uD83E\uDDF0 Preset Views";
            presetBtn.style.margin = "10px 0px";

            const resetViewBtn = document.createElement("button");
            resetViewBtn.textContent = "\uD83D\uDD01 Reset View";
            resetViewBtn.style.margin = "10px 0px";

            const toolbarLeft = document.querySelector(".toolbar .left-section");
            if (toolbarLeft) {
				toolbarLeft.appendChild(presetBtn);
				toolbarLeft.appendChild(resetViewBtn);
			}

            //Resetview button
            resetViewBtn.addEventListener("click", () => {
                columnFilters = {};
                hiddenColumns = new Set();
                defaultHidden.forEach(col => hiddenColumns.add(col));
                currentSort = { column: "Risk", asc: false };
                filterData();
                createColumnSelector();
            });

            const modal = document.createElement("div");
            modal.className = "preset-modal hidden";
            modal.innerHTML = `
                <div class="preset-modal-content">
                    <h3>Preset Views for ${type}</h3>
                    ${views.map(v => `<button class="preset-btn" data-label="${v.label}">${v.label}</button>`).join("")}
                            <button class="close-preset-modal" style="margin-top: 20px;">\u2716 Close</button>
                </div>
            `;
            document.body.appendChild(modal);

            // Toggle visibility
            presetBtn.onclick = () => modal.classList.toggle("hidden");

            // Apply view
            modal.querySelectorAll(".preset-btn").forEach(btn => {
                btn.addEventListener("click", () => {
                    const view = views.find(v => v.label === btn.dataset.label);
                    if (view) applyPredefinedView(view);
                    modal.classList.add("hidden");
                });
            });


            // Close on outside click
            document.addEventListener("click", (e) => {
                const isInside = modal.contains(e.target);
                const isButton = e.target === presetBtn;
                if (!isInside && !isButton) {
                    modal.classList.add("hidden");
                }
            });

            // Close on
            modal.querySelector(".close-preset-modal").addEventListener("click", () => {
                modal.classList.add("hidden");
            });
        }

        // Top toolbar
        function createToolbar() {
            const toolbar = document.createElement("div");
            toolbar.className = "toolbar";

            const leftSection = document.createElement("div");
            leftSection.className = "left-section";

            const rightSection = document.createElement("div");
            rightSection.className = "right-section";

            // Page size selector
            const pageSizeLabel = document.createElement("label");
            pageSizeLabel.textContent = "Rows per page:";
            pageSizeLabel.style.fontSize = "14px";
            pageSizeLabel.appendChild(pageSizeSelector);
            leftSection.appendChild(pageSizeLabel);

            // Column toggle menu
            const columnWrapper = document.createElement("div");
            columnWrapper.appendChild(columnSelector);
            leftSection.appendChild(columnWrapper);

            // Export button
            leftSection.appendChild(exportBtn);
            const shareBtn = document.createElement("button");
            shareBtn.textContent = "\u{1F441} Share View";
            shareBtn.style.margin = "10px 0px";
            leftSection.appendChild(shareBtn);

            // Info box ("Showing entries")
            infoBox.className = "info-box";
            rightSection.appendChild(infoBox);

            toolbar.appendChild(leftSection);
            toolbar.appendChild(rightSection);

            container.insertBefore(toolbar, wrapper);

            shareBtn.onclick = () => {
                const url = new URL(window.location.href);
                url.search = "";

                // Add filters
                Object.entries(columnFilters).forEach(([key, val]) => {
                    if (!val.trim()) return;

                    const match = val.match(/^(or_|group\d+_)(.+)$/i);
                    if (match) {
                        const [_, groupPrefix, realVal] = match;
                        url.searchParams.set(`${groupPrefix}${key}`, realVal);
                    } else {
                        url.searchParams.set(key, val.trim());
                    }
                });

                // Add visible columns
                const visibleCols = getVisibleColumns();
                url.searchParams.set("columns", visibleCols.join(","));

                // Add sort info
                if (currentSort.column) {
                    url.searchParams.set("sort", currentSort.column);
                    url.searchParams.set("sortDir", currentSort.asc ? "asc" : "desc");
                }

                // Copy to clipboard
                navigator.clipboard.writeText(url.toString()).then(() => {
                    showToast("View (Filter, Columns, Sorting) link copied to clipboard");
                }).catch(err => {
                    console.error("Clipboard write failed", err);
                    showToast("\u{26A0} Failed to copy URL", 4000);
                });
            };

        }

        function getVisibleColumns() {
            return columns.filter(col => !hiddenColumns.has(col));
        }
        
        // Renders main table
        function renderTable() {
            let start = (currentPage - 1) * rowsPerPage;
            let end = start + rowsPerPage;
            let pageData = filteredData.slice(start, end);

            if (pageData.length === 0 && currentPage > 1) {
                currentPage = 1;
                return renderTable();
            }

            const visibleCols = getVisibleColumns();

            //Capture active input to re-apply after filtering
            const activeElement = document.activeElement;
            let activeFilter = null;
            let caretPos = null;

            if (activeElement && activeElement.tagName === "INPUT" && activeElement.dataset.filter) {
                activeFilter = activeElement.dataset.filter;
                caretPos = activeElement.selectionStart;
            }

            let html = '<table class="overview-table"><thead><tr>';
            visibleCols.forEach(col => {
                const tooltip = columnTooltips[col] || "";
                const isSorted = currentSort.column === col;
                const sortIcon = isSorted
                    ? `<span style="font-size: 12px;"> ${currentSort.asc ? "\u{25B2}" : "\u{25BC}"}</span>`
                    : "";
                html += `<th data-col="${col}" title="${tooltip}">${col}${sortIcon}</th>`;
            });
            html += '</tr><tr>';
            visibleCols.forEach(col => {
                const val = Object.entries(columnFilters).find(([k]) => k.toLowerCase() === col.toLowerCase())?.[1] || '';
                html += `<th><input data-filter="${col}" value="${val}" placeholder="Filter..." style="width: 90%;" /></th>`;
            });
            html += '</tr></thead><tbody>';

            pageData.forEach(row => {
                html += '<tr>';
                visibleCols.forEach(col => {
                    const val = row[col];
                    const columnHeader = columns[colIndexMap[col]];
                    const columnHeaderLower = (columnHeader || "").toLowerCase();

                    const isLeftAligned =
                        columnHeader === undefined || // no matching header (cell without header)
                        columnHeaderLower.includes("displayname") ||
                        columnHeaderLower.includes("warnings") ||
                        columnHeaderLower === "role" ||
                        columnHeaderLower === "principal" ||
                        columnHeaderLower === "scope" ||
                        columnHeaderLower === "namelink" ||
                        columnHeaderLower === "apipermissiondescription" ||
                        columnHeaderLower.startsWith("upn") ||
                        columnHeaderLower.includes("scoperesolved");

                    const cellClass = isLeftAligned ? "left-align" : "";
                    html += `<td class="${cellClass}">${val}</td>`;
                });
                html += '</tr>';
            });

            html += '</tbody></table>';
            wrapper.innerHTML = html;

            // Sorting
            container.querySelectorAll("thead tr:first-child th").forEach(th => {
                th.onclick = () => {
                    const col = th.getAttribute("data-col");
                    if (currentSort.column === col) {
                        currentSort.asc = !currentSort.asc;
                    } else {
                        currentSort.column = col;
                        currentSort.asc = false;
                    }
                    sortData();
                    renderTable();
                };
            });

            renderPagination();
            renderInfo(start, end);

            const pageIds = pageData
                .map(row => extractAnchorIdAndText(row[columns[0]]).id)
                .filter(Boolean);
            if (window.__syncDetailsForCurrentPage) {
                window.__syncDetailsForCurrentPage(pageIds);
            } else {
                window.__pendingDetailIds = pageIds;
            }

            const table = wrapper.querySelector("table");
            if (table) {
                const headerCells = table.querySelectorAll("thead tr:first-child th");
                const headers = Array.prototype.map.call(headerCells, th => th.getAttribute("data-col") || (th.textContent || "").trim());
                window.requestAnimationFrame(() => colorCells(table, headers));
            }

            //Re-apply filter to focus
            if (activeFilter) {
                const newInput = container.querySelector(`input[data-filter="${activeFilter}"]`);
                if (newInput) {
                    newInput.focus();
                    if (caretPos !== null) {
                        newInput.setSelectionRange(caretPos, caretPos);
                    }
                }
            }        
        }

        
        //Pagination for the main table
        function renderPagination() {
            const totalPages = Math.max(1, Math.ceil(filteredData.length / rowsPerPage));
            let html = '';

            if (currentPage > 1) {
                html += `<button onclick="goToPage(${currentPage - 1})">Previous</button>`;
            }
            html += `<span> Page ${Math.min(currentPage, totalPages)} of ${totalPages} </span>`;

            if (currentPage < totalPages) {
                html += `<button onclick="goToPage(${currentPage + 1})">Next</button>`;
            }
            pagination.innerHTML = html;
        }

        
        // Displays how many entries are shown (e.g., "Showing 1-10 of 50 entries")
        function renderInfo(start, end) {
            const shownStart = filteredData.length === 0 ? 0 : start + 1;
            const shownEnd = Math.min(end, filteredData.length);
            infoBox.textContent = `Showing ${shownStart}-${shownEnd} of ${filteredData.length} entries`;
        }

        window.goToPage = function (page) {
            currentPage = page;
            renderTable();
        };
        
        //MainTable sort function (special handling of cells containing links)
        function sortData() {
            const { column, asc } = currentSort;
            if (!column) return;

            function extractText(val) {
                if (typeof val === "string") {
                    // Extract text inside anchor if present
                    const match = val.match(/<a[^>]*>(.*?)<\/a>/i);
                    return match ? match[1] : val;
                }
                return val ?? '';
            }

            filteredData.sort((a, b) => {
                const valA = extractText(a[column]);
                const valB = extractText(b[column]);

                const numA = parseFloat(valA);
                const numB = parseFloat(valB);
                const isNumA = !isNaN(numA);
                const isNumB = !isNaN(numB);

                let result;
                if (isNumA && isNumB) {
                    result = numA - numB;
                } else {
                    result = String(valA).localeCompare(String(valB), undefined, { numeric: true, sensitivity: 'base' });
                }

                return asc ? result : -result;
            });
        }
        function parseOperatorFilter(input, rawValue) {
            // Extract visible text only (e.g., from anchor tags)
            function extractText(html) {
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = html;
                return tempDiv.textContent || tempDiv.innerText || '';
            }

            // Support simple OR: "value1 || value2"
            if (input.includes('||')) {
                return input.split('||').some(part => parseOperatorFilter(part.trim(), rawValue));
            }
            const visibleText = extractText(rawValue).trim();
            const valStr = visibleText.toLowerCase();
            const rawStr = String(rawValue).toLowerCase(); // includes HTML
            const lowerInput = input.toLowerCase();

            // Handle "=empty" and "!=empty"
            if (input.trim().toLowerCase() === "=empty") {
                return !rawStr || rawStr === "";
            }
            if (input.trim().toLowerCase() === "!=empty") {
                return !!rawStr && rawStr !== "";
            }

            // Match standard operators: =, >, <, >=, <=, ^, $, plus negated versions: !=, !^, !$
            const operatorMatch = input.match(/^(!?)([<>]=?|=|\^|\$)\s*(.+)$/);
            if (operatorMatch) {
                const [, negate, op, rawFilter] = operatorMatch;
                const num = parseFloat(rawFilter);
                const isNumeric = !isNaN(num);
                const filterStr = rawFilter.toLowerCase();

                let result = false;

                switch (op) {
                    case '=':
                        if (isNumeric && !isNaN(parseFloat(visibleText))) {
                            result = parseFloat(visibleText) === num;
                        } else {
                            result = valStr === filterStr;
                        }
                        break;
                    case '<':
                        result = isNumeric && parseFloat(visibleText) < num;
                        break;
                    case '<=':
                        result = isNumeric && parseFloat(visibleText) <= num;
                        break;
                    case '>':
                        result = isNumeric && parseFloat(visibleText) > num;
                        break;
                    case '>=':
                        result = isNumeric && parseFloat(visibleText) >= num;
                        break;
                    case '^':
                        result = valStr.startsWith(filterStr);
                        break;
                    case '$':
                        result = valStr.endsWith(filterStr);
                        break;
                }

                return negate ? !result : result;
            }

            // Handle general "does not contain" (!value with no operator)
            if (lowerInput.startsWith('!')) {
                const negatedFilter = lowerInput.slice(1);
                return !rawStr.includes(negatedFilter);
            }

            // Default: contains → search raw HTML (so href/id is searchable)
            return rawStr.includes(lowerInput);
        }

        
        // Applies per-column filters
        function filterData() {
            const groups = {}; // { groupName: [ { col, input } ] }

            Object.entries(columnFilters).forEach(([colKey, input]) => {
                if (!input.trim()) return;

                const match = input.match(/^(or_|group\d+_)(.+)$/i); // match prefix inside input
                if (match) {
                    const [, groupPrefix, innerInput] = match;
                    const groupName = groupPrefix.slice(0, -1); // remove trailing _
                    if (!groups[groupName]) groups[groupName] = [];
                    groups[groupName].push({ col: colKey, input: innerInput });
                } else {
                    if (!groups.default) groups.default = [];
                    groups.default.push({ col: colKey, input });
                }
            });

            filteredData = data.filter(row => {
                const defaultPass = (groups.default || []).every(f => {
                    const colMatch = rowLowerKeyMap[String(f.col || "").toLowerCase()];
                    if (!colMatch) return false;
                    return parseOperatorFilter(f.input.trim(), row[colMatch]);
                });

                if (!defaultPass) return false;

                const orGroups = Object.entries(groups).filter(([g]) => g !== "default");
                for (const [groupName, filters] of orGroups) {
                    const groupPass = filters.some(f => {
                        const colMatch = rowLowerKeyMap[String(f.col || "").toLowerCase()];
                        if (!colMatch) return false;
                        return parseOperatorFilter(f.input.trim(), row[colMatch]);
                    });
                    if (!groupPass) return false;
                }

                return true;
            });

            currentPage = 1;
            sortData();
            renderTable();

            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) loadingOverlay.style.display = 'none';
        }

        function updateColumnCountLabel(button, allCols) {
            const visibleCount = allCols.filter(col => !hiddenColumns.has(col)).length;
            button.textContent = `\u2699\uFE0F Columns (${visibleCount}/${allCols.length}) \u25BC`;
        }

        // Dropdown for toggling column visibility
        function createColumnSelector() {
            const wrapperDiv = document.createElement("div");
            wrapperDiv.className = "column-toggle-wrapper";

            const toggleButton = document.createElement("button");
            toggleButton.className = "column-toggle-button";

            const allColumns = columns;
            updateColumnCountLabel(toggleButton, allColumns); // INITIAL count

            wrapperDiv.appendChild(toggleButton);

            const menu = document.createElement("div");
            menu.className = "column-toggle-menu";

            const checkboxes = {};

            // Select/Deselect All
            const toggleAllCheckbox = document.createElement("input");
            toggleAllCheckbox.type = "checkbox";
            toggleAllCheckbox.checked = allColumns.every(c => !hiddenColumns.has(c));
            toggleAllCheckbox.onchange = () => {
                const checked = toggleAllCheckbox.checked;
                allColumns.forEach(col => {
                    checkboxes[col].checked = checked;
                    if (checked) hiddenColumns.delete(col);
                    else hiddenColumns.add(col);
                });
                updateColumnCountLabel(toggleButton, allColumns);
                renderTable();
            };

            const toggleAllWrapper = document.createElement("label");
            toggleAllWrapper.appendChild(toggleAllCheckbox);
            toggleAllWrapper.appendChild(document.createTextNode(" Select All"));
            menu.appendChild(toggleAllWrapper);
            menu.appendChild(document.createElement("hr"));

            // Individual columns
            allColumns.forEach(col => {
                const checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.checked = !hiddenColumns.has(col);
                checkboxes[col] = checkbox;

                checkbox.onchange = () => {
                    if (!checkbox.checked) hiddenColumns.add(col);
                    else hiddenColumns.delete(col);
                    updateColumnCountLabel(toggleButton, allColumns);
                    renderTable();
                    toggleAllCheckbox.checked = allColumns.every(c => checkboxes[c].checked);
                };

                const label = document.createElement("label");
                label.appendChild(checkbox);
                label.appendChild(document.createTextNode(" " + col));
                label.style.display = "block";
                label.style.margin = "4px 0";
                menu.appendChild(label);
            });

            wrapperDiv.appendChild(menu);
            columnSelector.innerHTML = "";
            columnSelector.appendChild(wrapperDiv);

            toggleButton.addEventListener("click", () => {
                wrapperDiv.classList.toggle("show");
            });

            document.addEventListener("click", (e) => {
                if (!wrapperDiv.contains(e.target)) {
                    wrapperDiv.classList.remove("show");
                }
            });
        }



        // Event: Page size change
        pageSizeSelector.addEventListener("change", () => {
            rowsPerPage = parseInt(pageSizeSelector.value);
            currentPage = 1;
            renderTable();
        });

        //Apply columns selection based on GET parameters
        const urlParams = getURLParams();

        // Only apply defaultHidden if no `columns` param is present
        if (!urlParams.columns) {
            defaultHidden.forEach(col => hiddenColumns.add(col));
        }

        const columnParam = urlParams.columns;
        if (columnParam) {
            const allowedCols = columnParam.split(',').map(c => c.trim().toLowerCase());
            const allCols = columns;

            allCols.forEach(col => {
                if (!allowedCols.includes(col.toLowerCase())) {
                    hiddenColumns.add(col);
                }
            });
        }

        //Apply filters based on GET parameters
        const lowerKeys = rowLowerKeyMap;

        Object.entries(urlParams).forEach(([key, value]) => {
            const match = key.match(/^(or|group\d+)_(.+)$/i);
            if (match) {
                const [, groupName, column] = match;
                const colKey = lowerKeys[column.toLowerCase()] || column;

                // Add prefix into value so input shows or_>0, etc.
                const operatorMatch = value.match(/^(=|!=|<=|>=|<|>|\^|\$|!)/);
                const operator = operatorMatch ? '' : '=';

                columnFilters[colKey] = `${groupName}_${operator}${value}`;
            } else {
                const colKey = lowerKeys[key.toLowerCase()];
                if (colKey) {
                    columnFilters[colKey] = value;
                }
            }
        });

        //Apply sort based on GET parameters
        if (urlParams.sort) {
            const sortCol = lowerKeys[urlParams.sort.toLowerCase()];
            const sortDir = (urlParams.sortDir || "asc").toLowerCase();

            if (sortCol) {
                currentSort.column = sortCol;
                currentSort.asc = sortDir !== "desc";
            }
        } else {
            //Default sort: Risk (descending)
            currentSort.column = "Risk";
            currentSort.asc = false;
        }
 
        // Init
        createColumnSelector();
        createToolbar();
        createPresetFilterModal(manifest);

        filterData();
        })();

        // ###################################### SECTION for DETAILS ######################################
        const objectDataEl = document.getElementById('object-data');
        let objects = [];

        if (objectDataEl && objectDataEl.textContent.trim()) {
            try {
                const parsedJson = JSON.parse(objectDataEl.textContent);
                objects = Array.isArray(parsedJson) ? parsedJson : [parsedJson];
            } catch (e) {
                console.warn("JSON parsing failed for object-data:", e);
                objects = [];
            }
        }

        const objectContainer = document.getElementById('object-container');

        if (objectContainer) {
            objectContainer.innerHTML = '';

            const updateDetailsInfo = () => {
                const infoEl = document.getElementById('details-info');
                if (!infoEl) return;
                const total = objectContainer.querySelectorAll('details').length;
                const shownStart = total === 0 ? 0 : 1;
                const shownEnd = total;
                infoEl.textContent = `Showing ${shownStart}-${shownEnd} of ${total} entries`;
            };

            const objectsById = new Map();
            objects.forEach(obj => {
                const objectId = obj["Object ID"] || obj["ObjectId"] || obj["Id"];
                if (objectId) {
                    objectsById.set(String(objectId), obj);
                }
            });
            window.__objectsById = objectsById;

            const renderDetailsTable = (title, data) => {
                const section = document.createElement('div');
                const heading = document.createElement('h3');
                heading.textContent = title;
                section.appendChild(heading);

                const table = document.createElement('table');
                table.className = 'property-table';

                const header = table.insertRow();
                Object.keys(data[0]).forEach(key => {
                    const th = document.createElement('th');
                    th.textContent = key;
                    header.appendChild(th);
                });

                data.forEach(obj => {
                    const row = table.insertRow();
                    Object.values(obj).forEach(value => {
                        const cell = row.insertCell();
                        cell.innerHTML = typeof value === 'string' && value.startsWith('<a') ? value : value ?? '';
                    });
                });

                section.appendChild(table);
                return section;
            };

            const renderDetailsContent = (detailsEl, obj) => {
                if (!detailsEl || !obj || detailsEl.dataset.rendered === "true") return;

                for (let [key, value] of Object.entries(obj)) {
                    key = key.trim();
                    if (!value || (Array.isArray(value) && value.length === 0)) continue;

                    if (Array.isArray(value)) {
                        const allStrings = value.every(v => typeof v === 'string');
                        const objectsOnly = value.filter(v => typeof v === 'object');

                        if (objectsOnly.length) {
                            detailsEl.appendChild(renderDetailsTable(key, objectsOnly));
                        } else if (allStrings) {
                            detailsEl.appendChild(renderPreBlock(key, value));
                        }
                    } else if (typeof value === 'object') {
                        if (key === "General Information") {
                            detailsEl.appendChild(renderVerticalTable(key, value));
                        } else {
                            detailsEl.appendChild(renderDetailsTable(key, [value]));
                        }
                    }
                }

                detailsEl.dataset.rendered = "true";
            };
            window.__renderDetailsContent = renderDetailsContent;

            // Render vertical table
            const renderVerticalTable = (title, obj) => {
                const section = document.createElement('div');
                const heading = document.createElement('h3');
                heading.textContent = title;
                section.appendChild(heading);

                const table = document.createElement('table');
                table.className = 'property-table';

                for (const [key, value] of Object.entries(obj)) {
                    const row = table.insertRow();
                    const keyCell = row.insertCell();
                    keyCell.textContent = key;

                    const valueCell = row.insertCell();
                    valueCell.innerHTML = typeof value === 'string' && value.startsWith('<a') ? value : value ?? '';
                }

                section.appendChild(table);
                return section;
            };

            const createDetailsShell = (obj) => {
                const details = document.createElement('details');
                const objectId = obj["Object ID"] || obj["ObjectId"] || obj["Id"];
                details.id = objectId;
                const summary = document.createElement('summary');
                summary.textContent = obj["Object Name"] || objectId;
                details.appendChild(summary);

                details.addEventListener('toggle', () => {
                    if (details.open) {
                        renderDetailsContent(details, obj);
                    }
                });

                return details;
            };

            window.__syncDetailsForCurrentPage = (ids) => {
                const uniqueIds = Array.isArray(ids) ? Array.from(new Set(ids.map(String))) : [];
                objectContainer.innerHTML = '';

                uniqueIds.forEach(id => {
                    const obj = objectsById.get(id);
                    if (!obj) return;
                    const details = createDetailsShell(obj);
                    objectContainer.appendChild(details);
                });

                if (window.location.hash) {
                    const targetId = window.location.hash.replace('#', '');
                    if (targetId && !uniqueIds.includes(targetId) && objectsById.has(targetId)) {
                        const obj = objectsById.get(targetId);
                        const details = createDetailsShell(obj);
                        objectContainer.appendChild(details);
                    }
                }

                updateDetailsInfo();
            };

            if (window.__pendingDetailIds) {
                window.__syncDetailsForCurrentPage(window.__pendingDetailIds);
                delete window.__pendingDetailIds;
            }


        } else {
            console.warn("Element with id 'object-container' does not exist.");
        }


        function scrollToObjectByHash() {
            const targetId = window.location.hash.replace('#', '');
            if (!targetId) return;

            let targetElement = document.getElementById(targetId);
            if (!targetElement && window.__syncDetailsForCurrentPage) {
                window.__syncDetailsForCurrentPage([targetId]);
                targetElement = document.getElementById(targetId);
            }

            if (targetElement) {
                if (targetElement.dataset.rendered !== "true" && window.__renderDetailsContent && window.__objectsById) {
                    const obj = window.__objectsById.get(targetId);
                    if (obj) {
                        window.__renderDetailsContent(targetElement, obj);
                    }
                }

                targetElement.open = true;
                setTimeout(() => {
                    targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            }
        }
        
        //YAML rendering CAP
        function renderPreBlock(title, lines) {
            const section = document.createElement('div');
            const heading = document.createElement('h3');
            heading.textContent = title;
            section.appendChild(heading);

            const pre = document.createElement('pre');
            pre.className = 'yaml-block';

            // Join lines with newlines — keep them raw so links render
            pre.innerHTML = lines.join('\n');

            section.appendChild(pre);
            return section;
        }

        window.addEventListener('DOMContentLoaded', scrollToObjectByHash);
        window.addEventListener('hashchange', scrollToObjectByHash);

        let expandedState = false; // false = collapsed, true = expanded

        function toggleAll() {
            const allDetails = document.querySelectorAll('details');

            if (!expandedState && allDetails.length >= 2000) {
                const confirmExpand = confirm(
                    `Warning: Expanding ${allDetails.length} objects at once may slow down the page.\n\nDo you want to continue?`
                );
                if (!confirmExpand) return;
            }

            allDetails.forEach(d => d.open = !expandedState);
            expandedState = !expandedState;

            // Update button label
            const btn = document.getElementById('toggle-expand');
            btn.textContent = expandedState ? 'Collapse All' : 'Expand All';
        }

        document.addEventListener("DOMContentLoaded", () => {
            const toggleExpandBtn = document.getElementById('toggle-expand');
            if (toggleExpandBtn) {
                toggleExpandBtn.addEventListener('click', toggleAll);
            }
        });

        //Toast displayed when copy the current view
        function showToast(message, duration = 3000) {
            const toast = document.createElement("div");
            toast.textContent = message;
            toast.style.position = "fixed";
            toast.style.bottom = "30px";
            toast.style.right = "30px";
            toast.style.padding = "10px 16px";
            toast.style.background = "#333";
            toast.style.color = "#fff";
            toast.style.borderRadius = "8px";
            toast.style.boxShadow = "0 2px 6px rgba(0, 0, 0, 0.4)";
            toast.style.fontSize = "14px";
            toast.style.opacity = "0";
            toast.style.transition = "opacity 0.3s ease";

            document.body.appendChild(toast);
            requestAnimationFrame(() => toast.style.opacity = "1");

            setTimeout(() => {
                toast.style.opacity = "0";
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }


        // Coloring cells
        function colorCells(table, headers) {
            const rows = table && table.rows;
            if (!rows || rows.length < 3) return;

            const isDark = document.body.classList.contains("dark-mode");

            const redIfTrueHeaders = new Set(['Foreign', 'Inactive', 'PIM', 'Dynamic', 'SecurityEnabled', 'OnPrem', 'Conditions', 'IsBuiltIn', 'IsPrivileged', 'SAML']);
            const redIfFalseHeaders = new Set(['AppLock', 'MfaCap', 'Protected', 'Enabled', 'RoleAssignable', 'ActivationMFA', 'ActivationAuthContext', 'ActivationApproval', 'ActiveAssignMFA', 'EligibleExpiration', 'ActiveExpiration', 'ActivationJustification', 'ActivationTicketing', 'ActiveAssignJustification', 'AlertAssignEligible', 'AlertAssignActive', 'AlertActivation']);
            const redIfContent = new Set(['all', 'alltrusted', 'report-only', 'disabled', 'public', 'guest', 'customrole', 'active']);
            const redIfContentHeaders = new Set(['IncUsers', 'IncResources', 'IncNw', 'ExcNw', 'IncPlatforms', 'State', 'Visibility', 'UserType', 'RoleType', 'AssignmentType']);

            const redColor = isDark ? "#800000" : "#FFB6C1";
            const greenColor = isDark ? "#005f00" : "#98FB98";

            // If headers weren't passed, build once (fallback)
            if (!headers || !headers.length) {
                const headerCells = table.querySelectorAll("thead tr:first-child th");
                headers = Array.prototype.map.call(headerCells, th => th.getAttribute("data-col") || (th.textContent || "").trim());
            }


            for (let i = 2; i < rows.length; i++) {
                const cells = rows[i].cells;

                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    const columnHeader = headers[j] || "";

                    let bg = "";

                    // Fast path: boolean columns or numeric columns
                    if (redIfTrueHeaders.has(columnHeader) || redIfFalseHeaders.has(columnHeader)) {
                        const text = (cell.textContent || "").trim().toLowerCase();
                        if (text === "true" || text === "false") {
                            const boolVal = text === "true";
                            if (redIfTrueHeaders.has(columnHeader)) bg = boolVal ? redColor : greenColor;
                            if (redIfFalseHeaders.has(columnHeader)) bg = boolVal ? greenColor : redColor;
                        }
                    } else if (redIfContentHeaders.has(columnHeader)) {
                        const text = (cell.textContent || "").trim().toLowerCase();
                        bg = redIfContent.has(text) ? redColor : greenColor;
                    } else {
                        // Numeric heuristic: only attempt parse when it looks like a number
                        const raw = (cell.textContent || "").trim();
                        if (raw && raw.length < 32) {
                            const n = Number(raw);
                            if (!Number.isNaN(n)) {
                                bg = n === 0 ? greenColor : redColor;
                            }
                        }
                    }

                    // Fix stale colors: clear when no longer applicable
                    const current = cell.style.backgroundColor || "";
                    if (bg) {
                        if (current !== bg) cell.style.backgroundColor = bg;
                    } else {
                        if (current) cell.style.backgroundColor = "";
                    }
                }
            }
        }
        window.colorCells = colorCells;

    </script>
'@

$global:GLOBALJavaScript_Chart = @'

/*!
 * Chart.js v3.9.1
 * https://www.chartjs.org
 * (c) 2022 Chart.js Contributors
 * Released under the MIT License
 */
!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?module.exports=e():"function"==typeof define&&define.amd?define(e):(t="undefined"!=typeof globalThis?globalThis:t||self).Chart=e()}(this,(function(){"use strict";function t(){}const e=function(){let t=0;return function(){return t++}}();function i(t){return null==t}function s(t){if(Array.isArray&&Array.isArray(t))return!0;const e=Object.prototype.toString.call(t);return"[object"===e.slice(0,7)&&"Array]"===e.slice(-6)}function n(t){return null!==t&&"[object Object]"===Object.prototype.toString.call(t)}const o=t=>("number"==typeof t||t instanceof Number)&&isFinite(+t);function a(t,e){return o(t)?t:e}function r(t,e){return void 0===t?e:t}const l=(t,e)=>"string"==typeof t&&t.endsWith("%")?parseFloat(t)/100:t/e,h=(t,e)=>"string"==typeof t&&t.endsWith("%")?parseFloat(t)/100*e:+t;function c(t,e,i){if(t&&"function"==typeof t.call)return t.apply(i,e)}function d(t,e,i,o){let a,r,l;if(s(t))if(r=t.length,o)for(a=r-1;a>=0;a--)e.call(i,t[a],a);else for(a=0;a<r;a++)e.call(i,t[a],a);else if(n(t))for(l=Object.keys(t),r=l.length,a=0;a<r;a++)e.call(i,t[l[a]],l[a])}function u(t,e){let i,s,n,o;if(!t||!e||t.length!==e.length)return!1;for(i=0,s=t.length;i<s;++i)if(n=t[i],o=e[i],n.datasetIndex!==o.datasetIndex||n.index!==o.index)return!1;return!0}function f(t){if(s(t))return t.map(f);if(n(t)){const e=Object.create(null),i=Object.keys(t),s=i.length;let n=0;for(;n<s;++n)e[i[n]]=f(t[i[n]]);return e}return t}function g(t){return-1===["__proto__","prototype","constructor"].indexOf(t)}function p(t,e,i,s){if(!g(t))return;const o=e[t],a=i[t];n(o)&&n(a)?m(o,a,s):e[t]=f(a)}function m(t,e,i){const o=s(e)?e:[e],a=o.length;if(!n(t))return t;const r=(i=i||{}).merger||p;for(let s=0;s<a;++s){if(!n(e=o[s]))continue;const a=Object.keys(e);for(let s=0,n=a.length;s<n;++s)r(a[s],t,e,i)}return t}function b(t,e){return m(t,e,{merger:x})}function x(t,e,i){if(!g(t))return;const s=e[t],o=i[t];n(s)&&n(o)?b(s,o):Object.prototype.hasOwnProperty.call(e,t)||(e[t]=f(o))}const _={"":t=>t,x:t=>t.x,y:t=>t.y};function y(t,e){const i=_[e]||(_[e]=function(t){const e=v(t);return t=>{for(const i of e){if(""===i)break;t=t&&t[i]}return t}}(e));return i(t)}function v(t){const e=t.split("."),i=[];let s="";for(const t of e)s+=t,s.endsWith("\\")?s=s.slice(0,-1)+".":(i.push(s),s="");return i}function w(t){return t.charAt(0).toUpperCase()+t.slice(1)}const M=t=>void 0!==t,k=t=>"function"==typeof t,S=(t,e)=>{if(t.size!==e.size)return!1;for(const i of t)if(!e.has(i))return!1;return!0};function P(t){return"mouseup"===t.type||"click"===t.type||"contextmenu"===t.type}const D=Math.PI,O=2*D,C=O+D,A=Number.POSITIVE_INFINITY,T=D/180,L=D/2,E=D/4,R=2*D/3,I=Math.log10,z=Math.sign;function F(t){const e=Math.round(t);t=N(t,e,t/1e3)?e:t;const i=Math.pow(10,Math.floor(I(t))),s=t/i;return(s<=1?1:s<=2?2:s<=5?5:10)*i}function V(t){const e=[],i=Math.sqrt(t);let s;for(s=1;s<i;s++)t%s==0&&(e.push(s),e.push(t/s));return i===(0|i)&&e.push(i),e.sort(((t,e)=>t-e)).pop(),e}function B(t){return!isNaN(parseFloat(t))&&isFinite(t)}function N(t,e,i){return Math.abs(t-e)<i}function W(t,e){const i=Math.round(t);return i-e<=t&&i+e>=t}function j(t,e,i){let s,n,o;for(s=0,n=t.length;s<n;s++)o=t[s][i],isNaN(o)||(e.min=Math.min(e.min,o),e.max=Math.max(e.max,o))}function H(t){return t*(D/180)}function $(t){return t*(180/D)}function Y(t){if(!o(t))return;let e=1,i=0;for(;Math.round(t*e)/e!==t;)e*=10,i++;return i}function U(t,e){const i=e.x-t.x,s=e.y-t.y,n=Math.sqrt(i*i+s*s);let o=Math.atan2(s,i);return o<-.5*D&&(o+=O),{angle:o,distance:n}}function X(t,e){return Math.sqrt(Math.pow(e.x-t.x,2)+Math.pow(e.y-t.y,2))}function q(t,e){return(t-e+C)%O-D}function K(t){return(t%O+O)%O}function G(t,e,i,s){const n=K(t),o=K(e),a=K(i),r=K(o-n),l=K(a-n),h=K(n-o),c=K(n-a);return n===o||n===a||s&&o===a||r>l&&h<c}function Z(t,e,i){return Math.max(e,Math.min(i,t))}function J(t){return Z(t,-32768,32767)}function Q(t,e,i,s=1e-6){return t>=Math.min(e,i)-s&&t<=Math.max(e,i)+s}function tt(t,e,i){i=i||(i=>t[i]<e);let s,n=t.length-1,o=0;for(;n-o>1;)s=o+n>>1,i(s)?o=s:n=s;return{lo:o,hi:n}}const et=(t,e,i,s)=>tt(t,i,s?s=>t[s][e]<=i:s=>t[s][e]<i),it=(t,e,i)=>tt(t,i,(s=>t[s][e]>=i));function st(t,e,i){let s=0,n=t.length;for(;s<n&&t[s]<e;)s++;for(;n>s&&t[n-1]>i;)n--;return s>0||n<t.length?t.slice(s,n):t}const nt=["push","pop","shift","splice","unshift"];function ot(t,e){t._chartjs?t._chartjs.listeners.push(e):(Object.defineProperty(t,"_chartjs",{configurable:!0,enumerable:!1,value:{listeners:[e]}}),nt.forEach((e=>{const i="_onData"+w(e),s=t[e];Object.defineProperty(t,e,{configurable:!0,enumerable:!1,value(...e){const n=s.apply(this,e);return t._chartjs.listeners.forEach((t=>{"function"==typeof t[i]&&t[i](...e)})),n}})})))}function at(t,e){const i=t._chartjs;if(!i)return;const s=i.listeners,n=s.indexOf(e);-1!==n&&s.splice(n,1),s.length>0||(nt.forEach((e=>{delete t[e]})),delete t._chartjs)}function rt(t){const e=new Set;let i,s;for(i=0,s=t.length;i<s;++i)e.add(t[i]);return e.size===s?t:Array.from(e)}const lt="undefined"==typeof window?function(t){return t()}:window.requestAnimationFrame;function ht(t,e,i){const s=i||(t=>Array.prototype.slice.call(t));let n=!1,o=[];return function(...i){o=s(i),n||(n=!0,lt.call(window,(()=>{n=!1,t.apply(e,o)})))}}function ct(t,e){let i;return function(...s){return e?(clearTimeout(i),i=setTimeout(t,e,s)):t.apply(this,s),e}}const dt=t=>"start"===t?"left":"end"===t?"right":"center",ut=(t,e,i)=>"start"===t?e:"end"===t?i:(e+i)/2,ft=(t,e,i,s)=>t===(s?"left":"right")?i:"center"===t?(e+i)/2:e;function gt(t,e,i){const s=e.length;let n=0,o=s;if(t._sorted){const{iScale:a,_parsed:r}=t,l=a.axis,{min:h,max:c,minDefined:d,maxDefined:u}=a.getUserBounds();d&&(n=Z(Math.min(et(r,a.axis,h).lo,i?s:et(e,l,a.getPixelForValue(h)).lo),0,s-1)),o=u?Z(Math.max(et(r,a.axis,c,!0).hi+1,i?0:et(e,l,a.getPixelForValue(c),!0).hi+1),n,s)-n:s-n}return{start:n,count:o}}function pt(t){const{xScale:e,yScale:i,_scaleRanges:s}=t,n={xmin:e.min,xmax:e.max,ymin:i.min,ymax:i.max};if(!s)return t._scaleRanges=n,!0;const o=s.xmin!==e.min||s.xmax!==e.max||s.ymin!==i.min||s.ymax!==i.max;return Object.assign(s,n),o}var mt=new class{constructor(){this._request=null,this._charts=new Map,this._running=!1,this._lastDate=void 0}_notify(t,e,i,s){const n=e.listeners[s],o=e.duration;n.forEach((s=>s({chart:t,initial:e.initial,numSteps:o,currentStep:Math.min(i-e.start,o)})))}_refresh(){this._request||(this._running=!0,this._request=lt.call(window,(()=>{this._update(),this._request=null,this._running&&this._refresh()})))}_update(t=Date.now()){let e=0;this._charts.forEach(((i,s)=>{if(!i.running||!i.items.length)return;const n=i.items;let o,a=n.length-1,r=!1;for(;a>=0;--a)o=n[a],o._active?(o._total>i.duration&&(i.duration=o._total),o.tick(t),r=!0):(n[a]=n[n.length-1],n.pop());r&&(s.draw(),this._notify(s,i,t,"progress")),n.length||(i.running=!1,this._notify(s,i,t,"complete"),i.initial=!1),e+=n.length})),this._lastDate=t,0===e&&(this._running=!1)}_getAnims(t){const e=this._charts;let i=e.get(t);return i||(i={running:!1,initial:!0,items:[],listeners:{complete:[],progress:[]}},e.set(t,i)),i}listen(t,e,i){this._getAnims(t).listeners[e].push(i)}add(t,e){e&&e.length&&this._getAnims(t).items.push(...e)}has(t){return this._getAnims(t).items.length>0}start(t){const e=this._charts.get(t);e&&(e.running=!0,e.start=Date.now(),e.duration=e.items.reduce(((t,e)=>Math.max(t,e._duration)),0),this._refresh())}running(t){if(!this._running)return!1;const e=this._charts.get(t);return!!(e&&e.running&&e.items.length)}stop(t){const e=this._charts.get(t);if(!e||!e.items.length)return;const i=e.items;let s=i.length-1;for(;s>=0;--s)i[s].cancel();e.items=[],this._notify(t,e,Date.now(),"complete")}remove(t){return this._charts.delete(t)}};
/*!
 * @kurkle/color v0.2.1
 * https://github.com/kurkle/color#readme
 * (c) 2022 Jukka Kurkela
 * Released under the MIT License
 */
function bt(t){return t+.5|0}const xt=(t,e,i)=>Math.max(Math.min(t,i),e);function _t(t){return xt(bt(2.55*t),0,255)}function yt(t){return xt(bt(255*t),0,255)}function vt(t){return xt(bt(t/2.55)/100,0,1)}function wt(t){return xt(bt(100*t),0,100)}const Mt={0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,A:10,B:11,C:12,D:13,E:14,F:15,a:10,b:11,c:12,d:13,e:14,f:15},kt=[..."0123456789ABCDEF"],St=t=>kt[15&t],Pt=t=>kt[(240&t)>>4]+kt[15&t],Dt=t=>(240&t)>>4==(15&t);function Ot(t){var e=(t=>Dt(t.r)&&Dt(t.g)&&Dt(t.b)&&Dt(t.a))(t)?St:Pt;return t?"#"+e(t.r)+e(t.g)+e(t.b)+((t,e)=>t<255?e(t):"")(t.a,e):void 0}const Ct=/^(hsla?|hwb|hsv)\(\s*([-+.e\d]+)(?:deg)?[\s,]+([-+.e\d]+)%[\s,]+([-+.e\d]+)%(?:[\s,]+([-+.e\d]+)(%)?)?\s*\)$/;function At(t,e,i){const s=e*Math.min(i,1-i),n=(e,n=(e+t/30)%12)=>i-s*Math.max(Math.min(n-3,9-n,1),-1);return[n(0),n(8),n(4)]}function Tt(t,e,i){const s=(s,n=(s+t/60)%6)=>i-i*e*Math.max(Math.min(n,4-n,1),0);return[s(5),s(3),s(1)]}function Lt(t,e,i){const s=At(t,1,.5);let n;for(e+i>1&&(n=1/(e+i),e*=n,i*=n),n=0;n<3;n++)s[n]*=1-e-i,s[n]+=e;return s}function Et(t){const e=t.r/255,i=t.g/255,s=t.b/255,n=Math.max(e,i,s),o=Math.min(e,i,s),a=(n+o)/2;let r,l,h;return n!==o&&(h=n-o,l=a>.5?h/(2-n-o):h/(n+o),r=function(t,e,i,s,n){return t===n?(e-i)/s+(e<i?6:0):e===n?(i-t)/s+2:(t-e)/s+4}(e,i,s,h,n),r=60*r+.5),[0|r,l||0,a]}function Rt(t,e,i,s){return(Array.isArray(e)?t(e[0],e[1],e[2]):t(e,i,s)).map(yt)}function It(t,e,i){return Rt(At,t,e,i)}function zt(t){return(t%360+360)%360}function Ft(t){const e=Ct.exec(t);let i,s=255;if(!e)return;e[5]!==i&&(s=e[6]?_t(+e[5]):yt(+e[5]));const n=zt(+e[2]),o=+e[3]/100,a=+e[4]/100;return i="hwb"===e[1]?function(t,e,i){return Rt(Lt,t,e,i)}(n,o,a):"hsv"===e[1]?function(t,e,i){return Rt(Tt,t,e,i)}(n,o,a):It(n,o,a),{r:i[0],g:i[1],b:i[2],a:s}}const Vt={x:"dark",Z:"light",Y:"re",X:"blu",W:"gr",V:"medium",U:"slate",A:"ee",T:"ol",S:"or",B:"ra",C:"lateg",D:"ights",R:"in",Q:"turquois",E:"hi",P:"ro",O:"al",N:"le",M:"de",L:"yello",F:"en",K:"ch",G:"arks",H:"ea",I:"ightg",J:"wh"},Bt={OiceXe:"f0f8ff",antiquewEte:"faebd7",aqua:"ffff",aquamarRe:"7fffd4",azuY:"f0ffff",beige:"f5f5dc",bisque:"ffe4c4",black:"0",blanKedOmond:"ffebcd",Xe:"ff",XeviTet:"8a2be2",bPwn:"a52a2a",burlywood:"deb887",caMtXe:"5f9ea0",KartYuse:"7fff00",KocTate:"d2691e",cSO:"ff7f50",cSnflowerXe:"6495ed",cSnsilk:"fff8dc",crimson:"dc143c",cyan:"ffff",xXe:"8b",xcyan:"8b8b",xgTMnPd:"b8860b",xWay:"a9a9a9",xgYF:"6400",xgYy:"a9a9a9",xkhaki:"bdb76b",xmagFta:"8b008b",xTivegYF:"556b2f",xSange:"ff8c00",xScEd:"9932cc",xYd:"8b0000",xsOmon:"e9967a",xsHgYF:"8fbc8f",xUXe:"483d8b",xUWay:"2f4f4f",xUgYy:"2f4f4f",xQe:"ced1",xviTet:"9400d3",dAppRk:"ff1493",dApskyXe:"bfff",dimWay:"696969",dimgYy:"696969",dodgerXe:"1e90ff",fiYbrick:"b22222",flSOwEte:"fffaf0",foYstWAn:"228b22",fuKsia:"ff00ff",gaRsbSo:"dcdcdc",ghostwEte:"f8f8ff",gTd:"ffd700",gTMnPd:"daa520",Way:"808080",gYF:"8000",gYFLw:"adff2f",gYy:"808080",honeyMw:"f0fff0",hotpRk:"ff69b4",RdianYd:"cd5c5c",Rdigo:"4b0082",ivSy:"fffff0",khaki:"f0e68c",lavFMr:"e6e6fa",lavFMrXsh:"fff0f5",lawngYF:"7cfc00",NmoncEffon:"fffacd",ZXe:"add8e6",ZcSO:"f08080",Zcyan:"e0ffff",ZgTMnPdLw:"fafad2",ZWay:"d3d3d3",ZgYF:"90ee90",ZgYy:"d3d3d3",ZpRk:"ffb6c1",ZsOmon:"ffa07a",ZsHgYF:"20b2aa",ZskyXe:"87cefa",ZUWay:"778899",ZUgYy:"778899",ZstAlXe:"b0c4de",ZLw:"ffffe0",lime:"ff00",limegYF:"32cd32",lRF:"faf0e6",magFta:"ff00ff",maPon:"800000",VaquamarRe:"66cdaa",VXe:"cd",VScEd:"ba55d3",VpurpN:"9370db",VsHgYF:"3cb371",VUXe:"7b68ee",VsprRggYF:"fa9a",VQe:"48d1cc",VviTetYd:"c71585",midnightXe:"191970",mRtcYam:"f5fffa",mistyPse:"ffe4e1",moccasR:"ffe4b5",navajowEte:"ffdead",navy:"80",Tdlace:"fdf5e6",Tive:"808000",TivedBb:"6b8e23",Sange:"ffa500",SangeYd:"ff4500",ScEd:"da70d6",pOegTMnPd:"eee8aa",pOegYF:"98fb98",pOeQe:"afeeee",pOeviTetYd:"db7093",papayawEp:"ffefd5",pHKpuff:"ffdab9",peru:"cd853f",pRk:"ffc0cb",plum:"dda0dd",powMrXe:"b0e0e6",purpN:"800080",YbeccapurpN:"663399",Yd:"ff0000",Psybrown:"bc8f8f",PyOXe:"4169e1",saddNbPwn:"8b4513",sOmon:"fa8072",sandybPwn:"f4a460",sHgYF:"2e8b57",sHshell:"fff5ee",siFna:"a0522d",silver:"c0c0c0",skyXe:"87ceeb",UXe:"6a5acd",UWay:"708090",UgYy:"708090",snow:"fffafa",sprRggYF:"ff7f",stAlXe:"4682b4",tan:"d2b48c",teO:"8080",tEstN:"d8bfd8",tomato:"ff6347",Qe:"40e0d0",viTet:"ee82ee",JHt:"f5deb3",wEte:"ffffff",wEtesmoke:"f5f5f5",Lw:"ffff00",LwgYF:"9acd32"};let Nt;function Wt(t){Nt||(Nt=function(){const t={},e=Object.keys(Bt),i=Object.keys(Vt);let s,n,o,a,r;for(s=0;s<e.length;s++){for(a=r=e[s],n=0;n<i.length;n++)o=i[n],r=r.replace(o,Vt[o]);o=parseInt(Bt[a],16),t[r]=[o>>16&255,o>>8&255,255&o]}return t}(),Nt.transparent=[0,0,0,0]);const e=Nt[t.toLowerCase()];return e&&{r:e[0],g:e[1],b:e[2],a:4===e.length?e[3]:255}}const jt=/^rgba?\(\s*([-+.\d]+)(%)?[\s,]+([-+.e\d]+)(%)?[\s,]+([-+.e\d]+)(%)?(?:[\s,/]+([-+.e\d]+)(%)?)?\s*\)$/;const Ht=t=>t<=.0031308?12.92*t:1.055*Math.pow(t,1/2.4)-.055,$t=t=>t<=.04045?t/12.92:Math.pow((t+.055)/1.055,2.4);function Yt(t,e,i){if(t){let s=Et(t);s[e]=Math.max(0,Math.min(s[e]+s[e]*i,0===e?360:1)),s=It(s),t.r=s[0],t.g=s[1],t.b=s[2]}}function Ut(t,e){return t?Object.assign(e||{},t):t}function Xt(t){var e={r:0,g:0,b:0,a:255};return Array.isArray(t)?t.length>=3&&(e={r:t[0],g:t[1],b:t[2],a:255},t.length>3&&(e.a=yt(t[3]))):(e=Ut(t,{r:0,g:0,b:0,a:1})).a=yt(e.a),e}function qt(t){return"r"===t.charAt(0)?function(t){const e=jt.exec(t);let i,s,n,o=255;if(e){if(e[7]!==i){const t=+e[7];o=e[8]?_t(t):xt(255*t,0,255)}return i=+e[1],s=+e[3],n=+e[5],i=255&(e[2]?_t(i):xt(i,0,255)),s=255&(e[4]?_t(s):xt(s,0,255)),n=255&(e[6]?_t(n):xt(n,0,255)),{r:i,g:s,b:n,a:o}}}(t):Ft(t)}class Kt{constructor(t){if(t instanceof Kt)return t;const e=typeof t;let i;var s,n,o;"object"===e?i=Xt(t):"string"===e&&(o=(s=t).length,"#"===s[0]&&(4===o||5===o?n={r:255&17*Mt[s[1]],g:255&17*Mt[s[2]],b:255&17*Mt[s[3]],a:5===o?17*Mt[s[4]]:255}:7!==o&&9!==o||(n={r:Mt[s[1]]<<4|Mt[s[2]],g:Mt[s[3]]<<4|Mt[s[4]],b:Mt[s[5]]<<4|Mt[s[6]],a:9===o?Mt[s[7]]<<4|Mt[s[8]]:255})),i=n||Wt(t)||qt(t)),this._rgb=i,this._valid=!!i}get valid(){return this._valid}get rgb(){var t=Ut(this._rgb);return t&&(t.a=vt(t.a)),t}set rgb(t){this._rgb=Xt(t)}rgbString(){return this._valid?(t=this._rgb)&&(t.a<255?`rgba(${t.r}, ${t.g}, ${t.b}, ${vt(t.a)})`:`rgb(${t.r}, ${t.g}, ${t.b})`):void 0;var t}hexString(){return this._valid?Ot(this._rgb):void 0}hslString(){return this._valid?function(t){if(!t)return;const e=Et(t),i=e[0],s=wt(e[1]),n=wt(e[2]);return t.a<255?`hsla(${i}, ${s}%, ${n}%, ${vt(t.a)})`:`hsl(${i}, ${s}%, ${n}%)`}(this._rgb):void 0}mix(t,e){if(t){const i=this.rgb,s=t.rgb;let n;const o=e===n?.5:e,a=2*o-1,r=i.a-s.a,l=((a*r==-1?a:(a+r)/(1+a*r))+1)/2;n=1-l,i.r=255&l*i.r+n*s.r+.5,i.g=255&l*i.g+n*s.g+.5,i.b=255&l*i.b+n*s.b+.5,i.a=o*i.a+(1-o)*s.a,this.rgb=i}return this}interpolate(t,e){return t&&(this._rgb=function(t,e,i){const s=$t(vt(t.r)),n=$t(vt(t.g)),o=$t(vt(t.b));return{r:yt(Ht(s+i*($t(vt(e.r))-s))),g:yt(Ht(n+i*($t(vt(e.g))-n))),b:yt(Ht(o+i*($t(vt(e.b))-o))),a:t.a+i*(e.a-t.a)}}(this._rgb,t._rgb,e)),this}clone(){return new Kt(this.rgb)}alpha(t){return this._rgb.a=yt(t),this}clearer(t){return this._rgb.a*=1-t,this}greyscale(){const t=this._rgb,e=bt(.3*t.r+.59*t.g+.11*t.b);return t.r=t.g=t.b=e,this}opaquer(t){return this._rgb.a*=1+t,this}negate(){const t=this._rgb;return t.r=255-t.r,t.g=255-t.g,t.b=255-t.b,this}lighten(t){return Yt(this._rgb,2,t),this}darken(t){return Yt(this._rgb,2,-t),this}saturate(t){return Yt(this._rgb,1,t),this}desaturate(t){return Yt(this._rgb,1,-t),this}rotate(t){return function(t,e){var i=Et(t);i[0]=zt(i[0]+e),i=It(i),t.r=i[0],t.g=i[1],t.b=i[2]}(this._rgb,t),this}}function Gt(t){return new Kt(t)}function Zt(t){if(t&&"object"==typeof t){const e=t.toString();return"[object CanvasPattern]"===e||"[object CanvasGradient]"===e}return!1}function Jt(t){return Zt(t)?t:Gt(t)}function Qt(t){return Zt(t)?t:Gt(t).saturate(.5).darken(.1).hexString()}const te=Object.create(null),ee=Object.create(null);function ie(t,e){if(!e)return t;const i=e.split(".");for(let e=0,s=i.length;e<s;++e){const s=i[e];t=t[s]||(t[s]=Object.create(null))}return t}function se(t,e,i){return"string"==typeof e?m(ie(t,e),i):m(ie(t,""),e)}var ne=new class{constructor(t){this.animation=void 0,this.backgroundColor="rgba(0,0,0,0.1)",this.borderColor="rgba(0,0,0,0.1)",this.color="#666",this.datasets={},this.devicePixelRatio=t=>t.chart.platform.getDevicePixelRatio(),this.elements={},this.events=["mousemove","mouseout","click","touchstart","touchmove"],this.font={family:"'Helvetica Neue', 'Helvetica', 'Arial', sans-serif",size:12,style:"normal",lineHeight:1.2,weight:null},this.hover={},this.hoverBackgroundColor=(t,e)=>Qt(e.backgroundColor),this.hoverBorderColor=(t,e)=>Qt(e.borderColor),this.hoverColor=(t,e)=>Qt(e.color),this.indexAxis="x",this.interaction={mode:"nearest",intersect:!0,includeInvisible:!1},this.maintainAspectRatio=!0,this.onHover=null,this.onClick=null,this.parsing=!0,this.plugins={},this.responsive=!0,this.scale=void 0,this.scales={},this.showLine=!0,this.drawActiveElementsOnTop=!0,this.describe(t)}set(t,e){return se(this,t,e)}get(t){return ie(this,t)}describe(t,e){return se(ee,t,e)}override(t,e){return se(te,t,e)}route(t,e,i,s){const o=ie(this,t),a=ie(this,i),l="_"+e;Object.defineProperties(o,{[l]:{value:o[e],writable:!0},[e]:{enumerable:!0,get(){const t=this[l],e=a[s];return n(t)?Object.assign({},e,t):r(t,e)},set(t){this[l]=t}}})}}({_scriptable:t=>!t.startsWith("on"),_indexable:t=>"events"!==t,hover:{_fallback:"interaction"},interaction:{_scriptable:!1,_indexable:!1}});function oe(){return"undefined"!=typeof window&&"undefined"!=typeof document}function ae(t){let e=t.parentNode;return e&&"[object ShadowRoot]"===e.toString()&&(e=e.host),e}function re(t,e,i){let s;return"string"==typeof t?(s=parseInt(t,10),-1!==t.indexOf("%")&&(s=s/100*e.parentNode[i])):s=t,s}const le=t=>window.getComputedStyle(t,null);function he(t,e){return le(t).getPropertyValue(e)}const ce=["top","right","bottom","left"];function de(t,e,i){const s={};i=i?"-"+i:"";for(let n=0;n<4;n++){const o=ce[n];s[o]=parseFloat(t[e+"-"+o+i])||0}return s.width=s.left+s.right,s.height=s.top+s.bottom,s}function ue(t,e){if("native"in t)return t;const{canvas:i,currentDevicePixelRatio:s}=e,n=le(i),o="border-box"===n.boxSizing,a=de(n,"padding"),r=de(n,"border","width"),{x:l,y:h,box:c}=function(t,e){const i=t.touches,s=i&&i.length?i[0]:t,{offsetX:n,offsetY:o}=s;let a,r,l=!1;if(((t,e,i)=>(t>0||e>0)&&(!i||!i.shadowRoot))(n,o,t.target))a=n,r=o;else{const t=e.getBoundingClientRect();a=s.clientX-t.left,r=s.clientY-t.top,l=!0}return{x:a,y:r,box:l}}(t,i),d=a.left+(c&&r.left),u=a.top+(c&&r.top);let{width:f,height:g}=e;return o&&(f-=a.width+r.width,g-=a.height+r.height),{x:Math.round((l-d)/f*i.width/s),y:Math.round((h-u)/g*i.height/s)}}const fe=t=>Math.round(10*t)/10;function ge(t,e,i,s){const n=le(t),o=de(n,"margin"),a=re(n.maxWidth,t,"clientWidth")||A,r=re(n.maxHeight,t,"clientHeight")||A,l=function(t,e,i){let s,n;if(void 0===e||void 0===i){const o=ae(t);if(o){const t=o.getBoundingClientRect(),a=le(o),r=de(a,"border","width"),l=de(a,"padding");e=t.width-l.width-r.width,i=t.height-l.height-r.height,s=re(a.maxWidth,o,"clientWidth"),n=re(a.maxHeight,o,"clientHeight")}else e=t.clientWidth,i=t.clientHeight}return{width:e,height:i,maxWidth:s||A,maxHeight:n||A}}(t,e,i);let{width:h,height:c}=l;if("content-box"===n.boxSizing){const t=de(n,"border","width"),e=de(n,"padding");h-=e.width+t.width,c-=e.height+t.height}return h=Math.max(0,h-o.width),c=Math.max(0,s?Math.floor(h/s):c-o.height),h=fe(Math.min(h,a,l.maxWidth)),c=fe(Math.min(c,r,l.maxHeight)),h&&!c&&(c=fe(h/2)),{width:h,height:c}}function pe(t,e,i){const s=e||1,n=Math.floor(t.height*s),o=Math.floor(t.width*s);t.height=n/s,t.width=o/s;const a=t.canvas;return a.style&&(i||!a.style.height&&!a.style.width)&&(a.style.height=`${t.height}px`,a.style.width=`${t.width}px`),(t.currentDevicePixelRatio!==s||a.height!==n||a.width!==o)&&(t.currentDevicePixelRatio=s,a.height=n,a.width=o,t.ctx.setTransform(s,0,0,s,0,0),!0)}const me=function(){let t=!1;try{const e={get passive(){return t=!0,!1}};window.addEventListener("test",null,e),window.removeEventListener("test",null,e)}catch(t){}return t}();function be(t,e){const i=he(t,e),s=i&&i.match(/^(\d+)(\.\d+)?px$/);return s?+s[1]:void 0}function xe(t){return!t||i(t.size)||i(t.family)?null:(t.style?t.style+" ":"")+(t.weight?t.weight+" ":"")+t.size+"px "+t.family}function _e(t,e,i,s,n){let o=e[n];return o||(o=e[n]=t.measureText(n).width,i.push(n)),o>s&&(s=o),s}function ye(t,e,i,n){let o=(n=n||{}).data=n.data||{},a=n.garbageCollect=n.garbageCollect||[];n.font!==e&&(o=n.data={},a=n.garbageCollect=[],n.font=e),t.save(),t.font=e;let r=0;const l=i.length;let h,c,d,u,f;for(h=0;h<l;h++)if(u=i[h],null!=u&&!0!==s(u))r=_e(t,o,a,r,u);else if(s(u))for(c=0,d=u.length;c<d;c++)f=u[c],null==f||s(f)||(r=_e(t,o,a,r,f));t.restore();const g=a.length/2;if(g>i.length){for(h=0;h<g;h++)delete o[a[h]];a.splice(0,g)}return r}function ve(t,e,i){const s=t.currentDevicePixelRatio,n=0!==i?Math.max(i/2,.5):0;return Math.round((e-n)*s)/s+n}function we(t,e){(e=e||t.getContext("2d")).save(),e.resetTransform(),e.clearRect(0,0,t.width,t.height),e.restore()}function Me(t,e,i,s){ke(t,e,i,s,null)}function ke(t,e,i,s,n){let o,a,r,l,h,c;const d=e.pointStyle,u=e.rotation,f=e.radius;let g=(u||0)*T;if(d&&"object"==typeof d&&(o=d.toString(),"[object HTMLImageElement]"===o||"[object HTMLCanvasElement]"===o))return t.save(),t.translate(i,s),t.rotate(g),t.drawImage(d,-d.width/2,-d.height/2,d.width,d.height),void t.restore();if(!(isNaN(f)||f<=0)){switch(t.beginPath(),d){default:n?t.ellipse(i,s,n/2,f,0,0,O):t.arc(i,s,f,0,O),t.closePath();break;case"triangle":t.moveTo(i+Math.sin(g)*f,s-Math.cos(g)*f),g+=R,t.lineTo(i+Math.sin(g)*f,s-Math.cos(g)*f),g+=R,t.lineTo(i+Math.sin(g)*f,s-Math.cos(g)*f),t.closePath();break;case"rectRounded":h=.516*f,l=f-h,a=Math.cos(g+E)*l,r=Math.sin(g+E)*l,t.arc(i-a,s-r,h,g-D,g-L),t.arc(i+r,s-a,h,g-L,g),t.arc(i+a,s+r,h,g,g+L),t.arc(i-r,s+a,h,g+L,g+D),t.closePath();break;case"rect":if(!u){l=Math.SQRT1_2*f,c=n?n/2:l,t.rect(i-c,s-l,2*c,2*l);break}g+=E;case"rectRot":a=Math.cos(g)*f,r=Math.sin(g)*f,t.moveTo(i-a,s-r),t.lineTo(i+r,s-a),t.lineTo(i+a,s+r),t.lineTo(i-r,s+a),t.closePath();break;case"crossRot":g+=E;case"cross":a=Math.cos(g)*f,r=Math.sin(g)*f,t.moveTo(i-a,s-r),t.lineTo(i+a,s+r),t.moveTo(i+r,s-a),t.lineTo(i-r,s+a);break;case"star":a=Math.cos(g)*f,r=Math.sin(g)*f,t.moveTo(i-a,s-r),t.lineTo(i+a,s+r),t.moveTo(i+r,s-a),t.lineTo(i-r,s+a),g+=E,a=Math.cos(g)*f,r=Math.sin(g)*f,t.moveTo(i-a,s-r),t.lineTo(i+a,s+r),t.moveTo(i+r,s-a),t.lineTo(i-r,s+a);break;case"line":a=n?n/2:Math.cos(g)*f,r=Math.sin(g)*f,t.moveTo(i-a,s-r),t.lineTo(i+a,s+r);break;case"dash":t.moveTo(i,s),t.lineTo(i+Math.cos(g)*f,s+Math.sin(g)*f)}t.fill(),e.borderWidth>0&&t.stroke()}}function Se(t,e,i){return i=i||.5,!e||t&&t.x>e.left-i&&t.x<e.right+i&&t.y>e.top-i&&t.y<e.bottom+i}function Pe(t,e){t.save(),t.beginPath(),t.rect(e.left,e.top,e.right-e.left,e.bottom-e.top),t.clip()}function De(t){t.restore()}function Oe(t,e,i,s,n){if(!e)return t.lineTo(i.x,i.y);if("middle"===n){const s=(e.x+i.x)/2;t.lineTo(s,e.y),t.lineTo(s,i.y)}else"after"===n!=!!s?t.lineTo(e.x,i.y):t.lineTo(i.x,e.y);t.lineTo(i.x,i.y)}function Ce(t,e,i,s){if(!e)return t.lineTo(i.x,i.y);t.bezierCurveTo(s?e.cp1x:e.cp2x,s?e.cp1y:e.cp2y,s?i.cp2x:i.cp1x,s?i.cp2y:i.cp1y,i.x,i.y)}function Ae(t,e,n,o,a,r={}){const l=s(e)?e:[e],h=r.strokeWidth>0&&""!==r.strokeColor;let c,d;for(t.save(),t.font=a.string,function(t,e){e.translation&&t.translate(e.translation[0],e.translation[1]);i(e.rotation)||t.rotate(e.rotation);e.color&&(t.fillStyle=e.color);e.textAlign&&(t.textAlign=e.textAlign);e.textBaseline&&(t.textBaseline=e.textBaseline)}(t,r),c=0;c<l.length;++c)d=l[c],h&&(r.strokeColor&&(t.strokeStyle=r.strokeColor),i(r.strokeWidth)||(t.lineWidth=r.strokeWidth),t.strokeText(d,n,o,r.maxWidth)),t.fillText(d,n,o,r.maxWidth),Te(t,n,o,d,r),o+=a.lineHeight;t.restore()}function Te(t,e,i,s,n){if(n.strikethrough||n.underline){const o=t.measureText(s),a=e-o.actualBoundingBoxLeft,r=e+o.actualBoundingBoxRight,l=i-o.actualBoundingBoxAscent,h=i+o.actualBoundingBoxDescent,c=n.strikethrough?(l+h)/2:h;t.strokeStyle=t.fillStyle,t.beginPath(),t.lineWidth=n.decorationWidth||2,t.moveTo(a,c),t.lineTo(r,c),t.stroke()}}function Le(t,e){const{x:i,y:s,w:n,h:o,radius:a}=e;t.arc(i+a.topLeft,s+a.topLeft,a.topLeft,-L,D,!0),t.lineTo(i,s+o-a.bottomLeft),t.arc(i+a.bottomLeft,s+o-a.bottomLeft,a.bottomLeft,D,L,!0),t.lineTo(i+n-a.bottomRight,s+o),t.arc(i+n-a.bottomRight,s+o-a.bottomRight,a.bottomRight,L,0,!0),t.lineTo(i+n,s+a.topRight),t.arc(i+n-a.topRight,s+a.topRight,a.topRight,0,-L,!0),t.lineTo(i+a.topLeft,s)}function Ee(t,e=[""],i=t,s,n=(()=>t[0])){M(s)||(s=$e("_fallback",t));const o={[Symbol.toStringTag]:"Object",_cacheable:!0,_scopes:t,_rootScopes:i,_fallback:s,_getTarget:n,override:n=>Ee([n,...t],e,i,s)};return new Proxy(o,{deleteProperty:(e,i)=>(delete e[i],delete e._keys,delete t[0][i],!0),get:(i,s)=>Ve(i,s,(()=>function(t,e,i,s){let n;for(const o of e)if(n=$e(ze(o,t),i),M(n))return Fe(t,n)?je(i,s,t,n):n}(s,e,t,i))),getOwnPropertyDescriptor:(t,e)=>Reflect.getOwnPropertyDescriptor(t._scopes[0],e),getPrototypeOf:()=>Reflect.getPrototypeOf(t[0]),has:(t,e)=>Ye(t).includes(e),ownKeys:t=>Ye(t),set(t,e,i){const s=t._storage||(t._storage=n());return t[e]=s[e]=i,delete t._keys,!0}})}function Re(t,e,i,o){const a={_cacheable:!1,_proxy:t,_context:e,_subProxy:i,_stack:new Set,_descriptors:Ie(t,o),setContext:e=>Re(t,e,i,o),override:s=>Re(t.override(s),e,i,o)};return new Proxy(a,{deleteProperty:(e,i)=>(delete e[i],delete t[i],!0),get:(t,e,i)=>Ve(t,e,(()=>function(t,e,i){const{_proxy:o,_context:a,_subProxy:r,_descriptors:l}=t;let h=o[e];k(h)&&l.isScriptable(e)&&(h=function(t,e,i,s){const{_proxy:n,_context:o,_subProxy:a,_stack:r}=i;if(r.has(t))throw new Error("Recursion detected: "+Array.from(r).join("->")+"->"+t);r.add(t),e=e(o,a||s),r.delete(t),Fe(t,e)&&(e=je(n._scopes,n,t,e));return e}(e,h,t,i));s(h)&&h.length&&(h=function(t,e,i,s){const{_proxy:o,_context:a,_subProxy:r,_descriptors:l}=i;if(M(a.index)&&s(t))e=e[a.index%e.length];else if(n(e[0])){const i=e,s=o._scopes.filter((t=>t!==i));e=[];for(const n of i){const i=je(s,o,t,n);e.push(Re(i,a,r&&r[t],l))}}return e}(e,h,t,l.isIndexable));Fe(e,h)&&(h=Re(h,a,r&&r[e],l));return h}(t,e,i))),getOwnPropertyDescriptor:(e,i)=>e._descriptors.allKeys?Reflect.has(t,i)?{enumerable:!0,configurable:!0}:void 0:Reflect.getOwnPropertyDescriptor(t,i),getPrototypeOf:()=>Reflect.getPrototypeOf(t),has:(e,i)=>Reflect.has(t,i),ownKeys:()=>Reflect.ownKeys(t),set:(e,i,s)=>(t[i]=s,delete e[i],!0)})}function Ie(t,e={scriptable:!0,indexable:!0}){const{_scriptable:i=e.scriptable,_indexable:s=e.indexable,_allKeys:n=e.allKeys}=t;return{allKeys:n,scriptable:i,indexable:s,isScriptable:k(i)?i:()=>i,isIndexable:k(s)?s:()=>s}}const ze=(t,e)=>t?t+w(e):e,Fe=(t,e)=>n(e)&&"adapters"!==t&&(null===Object.getPrototypeOf(e)||e.constructor===Object);function Ve(t,e,i){if(Object.prototype.hasOwnProperty.call(t,e))return t[e];const s=i();return t[e]=s,s}function Be(t,e,i){return k(t)?t(e,i):t}const Ne=(t,e)=>!0===t?e:"string"==typeof t?y(e,t):void 0;function We(t,e,i,s,n){for(const o of e){const e=Ne(i,o);if(e){t.add(e);const o=Be(e._fallback,i,n);if(M(o)&&o!==i&&o!==s)return o}else if(!1===e&&M(s)&&i!==s)return null}return!1}function je(t,e,i,o){const a=e._rootScopes,r=Be(e._fallback,i,o),l=[...t,...a],h=new Set;h.add(o);let c=He(h,l,i,r||i,o);return null!==c&&((!M(r)||r===i||(c=He(h,l,r,c,o),null!==c))&&Ee(Array.from(h),[""],a,r,(()=>function(t,e,i){const o=t._getTarget();e in o||(o[e]={});const a=o[e];if(s(a)&&n(i))return i;return a}(e,i,o))))}function He(t,e,i,s,n){for(;i;)i=We(t,e,i,s,n);return i}function $e(t,e){for(const i of e){if(!i)continue;const e=i[t];if(M(e))return e}}function Ye(t){let e=t._keys;return e||(e=t._keys=function(t){const e=new Set;for(const i of t)for(const t of Object.keys(i).filter((t=>!t.startsWith("_"))))e.add(t);return Array.from(e)}(t._scopes)),e}function Ue(t,e,i,s){const{iScale:n}=t,{key:o="r"}=this._parsing,a=new Array(s);let r,l,h,c;for(r=0,l=s;r<l;++r)h=r+i,c=e[h],a[r]={r:n.parse(y(c,o),h)};return a}const Xe=Number.EPSILON||1e-14,qe=(t,e)=>e<t.length&&!t[e].skip&&t[e],Ke=t=>"x"===t?"y":"x";function Ge(t,e,i,s){const n=t.skip?e:t,o=e,a=i.skip?e:i,r=X(o,n),l=X(a,o);let h=r/(r+l),c=l/(r+l);h=isNaN(h)?0:h,c=isNaN(c)?0:c;const d=s*h,u=s*c;return{previous:{x:o.x-d*(a.x-n.x),y:o.y-d*(a.y-n.y)},next:{x:o.x+u*(a.x-n.x),y:o.y+u*(a.y-n.y)}}}function Ze(t,e="x"){const i=Ke(e),s=t.length,n=Array(s).fill(0),o=Array(s);let a,r,l,h=qe(t,0);for(a=0;a<s;++a)if(r=l,l=h,h=qe(t,a+1),l){if(h){const t=h[e]-l[e];n[a]=0!==t?(h[i]-l[i])/t:0}o[a]=r?h?z(n[a-1])!==z(n[a])?0:(n[a-1]+n[a])/2:n[a-1]:n[a]}!function(t,e,i){const s=t.length;let n,o,a,r,l,h=qe(t,0);for(let c=0;c<s-1;++c)l=h,h=qe(t,c+1),l&&h&&(N(e[c],0,Xe)?i[c]=i[c+1]=0:(n=i[c]/e[c],o=i[c+1]/e[c],r=Math.pow(n,2)+Math.pow(o,2),r<=9||(a=3/Math.sqrt(r),i[c]=n*a*e[c],i[c+1]=o*a*e[c])))}(t,n,o),function(t,e,i="x"){const s=Ke(i),n=t.length;let o,a,r,l=qe(t,0);for(let h=0;h<n;++h){if(a=r,r=l,l=qe(t,h+1),!r)continue;const n=r[i],c=r[s];a&&(o=(n-a[i])/3,r[`cp1${i}`]=n-o,r[`cp1${s}`]=c-o*e[h]),l&&(o=(l[i]-n)/3,r[`cp2${i}`]=n+o,r[`cp2${s}`]=c+o*e[h])}}(t,o,e)}function Je(t,e,i){return Math.max(Math.min(t,i),e)}function Qe(t,e,i,s,n){let o,a,r,l;if(e.spanGaps&&(t=t.filter((t=>!t.skip))),"monotone"===e.cubicInterpolationMode)Ze(t,n);else{let i=s?t[t.length-1]:t[0];for(o=0,a=t.length;o<a;++o)r=t[o],l=Ge(i,r,t[Math.min(o+1,a-(s?0:1))%a],e.tension),r.cp1x=l.previous.x,r.cp1y=l.previous.y,r.cp2x=l.next.x,r.cp2y=l.next.y,i=r}e.capBezierPoints&&function(t,e){let i,s,n,o,a,r=Se(t[0],e);for(i=0,s=t.length;i<s;++i)a=o,o=r,r=i<s-1&&Se(t[i+1],e),o&&(n=t[i],a&&(n.cp1x=Je(n.cp1x,e.left,e.right),n.cp1y=Je(n.cp1y,e.top,e.bottom)),r&&(n.cp2x=Je(n.cp2x,e.left,e.right),n.cp2y=Je(n.cp2y,e.top,e.bottom)))}(t,i)}const ti=t=>0===t||1===t,ei=(t,e,i)=>-Math.pow(2,10*(t-=1))*Math.sin((t-e)*O/i),ii=(t,e,i)=>Math.pow(2,-10*t)*Math.sin((t-e)*O/i)+1,si={linear:t=>t,easeInQuad:t=>t*t,easeOutQuad:t=>-t*(t-2),easeInOutQuad:t=>(t/=.5)<1?.5*t*t:-.5*(--t*(t-2)-1),easeInCubic:t=>t*t*t,easeOutCubic:t=>(t-=1)*t*t+1,easeInOutCubic:t=>(t/=.5)<1?.5*t*t*t:.5*((t-=2)*t*t+2),easeInQuart:t=>t*t*t*t,easeOutQuart:t=>-((t-=1)*t*t*t-1),easeInOutQuart:t=>(t/=.5)<1?.5*t*t*t*t:-.5*((t-=2)*t*t*t-2),easeInQuint:t=>t*t*t*t*t,easeOutQuint:t=>(t-=1)*t*t*t*t+1,easeInOutQuint:t=>(t/=.5)<1?.5*t*t*t*t*t:.5*((t-=2)*t*t*t*t+2),easeInSine:t=>1-Math.cos(t*L),easeOutSine:t=>Math.sin(t*L),easeInOutSine:t=>-.5*(Math.cos(D*t)-1),easeInExpo:t=>0===t?0:Math.pow(2,10*(t-1)),easeOutExpo:t=>1===t?1:1-Math.pow(2,-10*t),easeInOutExpo:t=>ti(t)?t:t<.5?.5*Math.pow(2,10*(2*t-1)):.5*(2-Math.pow(2,-10*(2*t-1))),easeInCirc:t=>t>=1?t:-(Math.sqrt(1-t*t)-1),easeOutCirc:t=>Math.sqrt(1-(t-=1)*t),easeInOutCirc:t=>(t/=.5)<1?-.5*(Math.sqrt(1-t*t)-1):.5*(Math.sqrt(1-(t-=2)*t)+1),easeInElastic:t=>ti(t)?t:ei(t,.075,.3),easeOutElastic:t=>ti(t)?t:ii(t,.075,.3),easeInOutElastic(t){const e=.1125;return ti(t)?t:t<.5?.5*ei(2*t,e,.45):.5+.5*ii(2*t-1,e,.45)},easeInBack(t){const e=1.70158;return t*t*((e+1)*t-e)},easeOutBack(t){const e=1.70158;return(t-=1)*t*((e+1)*t+e)+1},easeInOutBack(t){let e=1.70158;return(t/=.5)<1?t*t*((1+(e*=1.525))*t-e)*.5:.5*((t-=2)*t*((1+(e*=1.525))*t+e)+2)},easeInBounce:t=>1-si.easeOutBounce(1-t),easeOutBounce(t){const e=7.5625,i=2.75;return t<1/i?e*t*t:t<2/i?e*(t-=1.5/i)*t+.75:t<2.5/i?e*(t-=2.25/i)*t+.9375:e*(t-=2.625/i)*t+.984375},easeInOutBounce:t=>t<.5?.5*si.easeInBounce(2*t):.5*si.easeOutBounce(2*t-1)+.5};function ni(t,e,i,s){return{x:t.x+i*(e.x-t.x),y:t.y+i*(e.y-t.y)}}function oi(t,e,i,s){return{x:t.x+i*(e.x-t.x),y:"middle"===s?i<.5?t.y:e.y:"after"===s?i<1?t.y:e.y:i>0?e.y:t.y}}function ai(t,e,i,s){const n={x:t.cp2x,y:t.cp2y},o={x:e.cp1x,y:e.cp1y},a=ni(t,n,i),r=ni(n,o,i),l=ni(o,e,i),h=ni(a,r,i),c=ni(r,l,i);return ni(h,c,i)}const ri=new Map;function li(t,e,i){return function(t,e){e=e||{};const i=t+JSON.stringify(e);let s=ri.get(i);return s||(s=new Intl.NumberFormat(t,e),ri.set(i,s)),s}(e,i).format(t)}const hi=new RegExp(/^(normal|(\d+(?:\.\d+)?)(px|em|%)?)$/),ci=new RegExp(/^(normal|italic|initial|inherit|unset|(oblique( -?[0-9]?[0-9]deg)?))$/);function di(t,e){const i=(""+t).match(hi);if(!i||"normal"===i[1])return 1.2*e;switch(t=+i[2],i[3]){case"px":return t;case"%":t/=100}return e*t}function ui(t,e){const i={},s=n(e),o=s?Object.keys(e):e,a=n(t)?s?i=>r(t[i],t[e[i]]):e=>t[e]:()=>t;for(const t of o)i[t]=+a(t)||0;return i}function fi(t){return ui(t,{top:"y",right:"x",bottom:"y",left:"x"})}function gi(t){return ui(t,["topLeft","topRight","bottomLeft","bottomRight"])}function pi(t){const e=fi(t);return e.width=e.left+e.right,e.height=e.top+e.bottom,e}function mi(t,e){t=t||{},e=e||ne.font;let i=r(t.size,e.size);"string"==typeof i&&(i=parseInt(i,10));let s=r(t.style,e.style);s&&!(""+s).match(ci)&&(console.warn('Invalid font style specified: "'+s+'"'),s="");const n={family:r(t.family,e.family),lineHeight:di(r(t.lineHeight,e.lineHeight),i),size:i,style:s,weight:r(t.weight,e.weight),string:""};return n.string=xe(n),n}function bi(t,e,i,n){let o,a,r,l=!0;for(o=0,a=t.length;o<a;++o)if(r=t[o],void 0!==r&&(void 0!==e&&"function"==typeof r&&(r=r(e),l=!1),void 0!==i&&s(r)&&(r=r[i%r.length],l=!1),void 0!==r))return n&&!l&&(n.cacheable=!1),r}function xi(t,e,i){const{min:s,max:n}=t,o=h(e,(n-s)/2),a=(t,e)=>i&&0===t?0:t+e;return{min:a(s,-Math.abs(o)),max:a(n,o)}}function _i(t,e){return Object.assign(Object.create(t),e)}function yi(t,e,i){return t?function(t,e){return{x:i=>t+t+e-i,setWidth(t){e=t},textAlign:t=>"center"===t?t:"right"===t?"left":"right",xPlus:(t,e)=>t-e,leftForLtr:(t,e)=>t-e}}(e,i):{x:t=>t,setWidth(t){},textAlign:t=>t,xPlus:(t,e)=>t+e,leftForLtr:(t,e)=>t}}function vi(t,e){let i,s;"ltr"!==e&&"rtl"!==e||(i=t.canvas.style,s=[i.getPropertyValue("direction"),i.getPropertyPriority("direction")],i.setProperty("direction",e,"important"),t.prevTextDirection=s)}function wi(t,e){void 0!==e&&(delete t.prevTextDirection,t.canvas.style.setProperty("direction",e[0],e[1]))}function Mi(t){return"angle"===t?{between:G,compare:q,normalize:K}:{between:Q,compare:(t,e)=>t-e,normalize:t=>t}}function ki({start:t,end:e,count:i,loop:s,style:n}){return{start:t%i,end:e%i,loop:s&&(e-t+1)%i==0,style:n}}function Si(t,e,i){if(!i)return[t];const{property:s,start:n,end:o}=i,a=e.length,{compare:r,between:l,normalize:h}=Mi(s),{start:c,end:d,loop:u,style:f}=function(t,e,i){const{property:s,start:n,end:o}=i,{between:a,normalize:r}=Mi(s),l=e.length;let h,c,{start:d,end:u,loop:f}=t;if(f){for(d+=l,u+=l,h=0,c=l;h<c&&a(r(e[d%l][s]),n,o);++h)d--,u--;d%=l,u%=l}return u<d&&(u+=l),{start:d,end:u,loop:f,style:t.style}}(t,e,i),g=[];let p,m,b,x=!1,_=null;const y=()=>x||l(n,b,p)&&0!==r(n,b),v=()=>!x||0===r(o,p)||l(o,b,p);for(let t=c,i=c;t<=d;++t)m=e[t%a],m.skip||(p=h(m[s]),p!==b&&(x=l(p,n,o),null===_&&y()&&(_=0===r(p,n)?t:i),null!==_&&v()&&(g.push(ki({start:_,end:t,loop:u,count:a,style:f})),_=null),i=t,b=p));return null!==_&&g.push(ki({start:_,end:d,loop:u,count:a,style:f})),g}function Pi(t,e){const i=[],s=t.segments;for(let n=0;n<s.length;n++){const o=Si(s[n],t.points,e);o.length&&i.push(...o)}return i}function Di(t,e){const i=t.points,s=t.options.spanGaps,n=i.length;if(!n)return[];const o=!!t._loop,{start:a,end:r}=function(t,e,i,s){let n=0,o=e-1;if(i&&!s)for(;n<e&&!t[n].skip;)n++;for(;n<e&&t[n].skip;)n++;for(n%=e,i&&(o+=n);o>n&&t[o%e].skip;)o--;return o%=e,{start:n,end:o}}(i,n,o,s);if(!0===s)return Oi(t,[{start:a,end:r,loop:o}],i,e);return Oi(t,function(t,e,i,s){const n=t.length,o=[];let a,r=e,l=t[e];for(a=e+1;a<=i;++a){const i=t[a%n];i.skip||i.stop?l.skip||(s=!1,o.push({start:e%n,end:(a-1)%n,loop:s}),e=r=i.stop?a:null):(r=a,l.skip&&(e=a)),l=i}return null!==r&&o.push({start:e%n,end:r%n,loop:s}),o}(i,a,r<a?r+n:r,!!t._fullLoop&&0===a&&r===n-1),i,e)}function Oi(t,e,i,s){return s&&s.setContext&&i?function(t,e,i,s){const n=t._chart.getContext(),o=Ci(t.options),{_datasetIndex:a,options:{spanGaps:r}}=t,l=i.length,h=[];let c=o,d=e[0].start,u=d;function f(t,e,s,n){const o=r?-1:1;if(t!==e){for(t+=l;i[t%l].skip;)t-=o;for(;i[e%l].skip;)e+=o;t%l!=e%l&&(h.push({start:t%l,end:e%l,loop:s,style:n}),c=n,d=e%l)}}for(const t of e){d=r?d:t.start;let e,o=i[d%l];for(u=d+1;u<=t.end;u++){const r=i[u%l];e=Ci(s.setContext(_i(n,{type:"segment",p0:o,p1:r,p0DataIndex:(u-1)%l,p1DataIndex:u%l,datasetIndex:a}))),Ai(e,c)&&f(d,u-1,t.loop,c),o=r,c=e}d<u-1&&f(d,u-1,t.loop,c)}return h}(t,e,i,s):e}function Ci(t){return{backgroundColor:t.backgroundColor,borderCapStyle:t.borderCapStyle,borderDash:t.borderDash,borderDashOffset:t.borderDashOffset,borderJoinStyle:t.borderJoinStyle,borderWidth:t.borderWidth,borderColor:t.borderColor}}function Ai(t,e){return e&&JSON.stringify(t)!==JSON.stringify(e)}var Ti=Object.freeze({__proto__:null,easingEffects:si,isPatternOrGradient:Zt,color:Jt,getHoverColor:Qt,noop:t,uid:e,isNullOrUndef:i,isArray:s,isObject:n,isFinite:o,finiteOrDefault:a,valueOrDefault:r,toPercentage:l,toDimension:h,callback:c,each:d,_elementsEqual:u,clone:f,_merger:p,merge:m,mergeIf:b,_mergerIf:x,_deprecated:function(t,e,i,s){void 0!==e&&console.warn(t+': "'+i+'" is deprecated. Please use "'+s+'" instead')},resolveObjectKey:y,_splitKey:v,_capitalize:w,defined:M,isFunction:k,setsEqual:S,_isClickEvent:P,toFontString:xe,_measureText:_e,_longestText:ye,_alignPixel:ve,clearCanvas:we,drawPoint:Me,drawPointLegend:ke,_isPointInArea:Se,clipArea:Pe,unclipArea:De,_steppedLineTo:Oe,_bezierCurveTo:Ce,renderText:Ae,addRoundedRectPath:Le,_lookup:tt,_lookupByKey:et,_rlookupByKey:it,_filterBetween:st,listenArrayEvents:ot,unlistenArrayEvents:at,_arrayUnique:rt,_createResolver:Ee,_attachContext:Re,_descriptors:Ie,_parseObjectDataRadialScale:Ue,splineCurve:Ge,splineCurveMonotone:Ze,_updateBezierControlPoints:Qe,_isDomSupported:oe,_getParentNode:ae,getStyle:he,getRelativePosition:ue,getMaximumSize:ge,retinaScale:pe,supportsEventListenerOptions:me,readUsedSize:be,fontString:function(t,e,i){return e+" "+t+"px "+i},requestAnimFrame:lt,throttled:ht,debounce:ct,_toLeftRightCenter:dt,_alignStartEnd:ut,_textX:ft,_getStartAndCountOfVisiblePoints:gt,_scaleRangesChanged:pt,_pointInLine:ni,_steppedInterpolation:oi,_bezierInterpolation:ai,formatNumber:li,toLineHeight:di,_readValueToProps:ui,toTRBL:fi,toTRBLCorners:gi,toPadding:pi,toFont:mi,resolve:bi,_addGrace:xi,createContext:_i,PI:D,TAU:O,PITAU:C,INFINITY:A,RAD_PER_DEG:T,HALF_PI:L,QUARTER_PI:E,TWO_THIRDS_PI:R,log10:I,sign:z,niceNum:F,_factorize:V,isNumber:B,almostEquals:N,almostWhole:W,_setMinAndMaxByKey:j,toRadians:H,toDegrees:$,_decimalPlaces:Y,getAngleFromPoint:U,distanceBetweenPoints:X,_angleDiff:q,_normalizeAngle:K,_angleBetween:G,_limitValue:Z,_int16Range:J,_isBetween:Q,getRtlAdapter:yi,overrideTextDirection:vi,restoreTextDirection:wi,_boundSegment:Si,_boundSegments:Pi,_computeSegments:Di});function Li(t,e,i,s){const{controller:n,data:o,_sorted:a}=t,r=n._cachedMeta.iScale;if(r&&e===r.axis&&"r"!==e&&a&&o.length){const t=r._reversePixels?it:et;if(!s)return t(o,e,i);if(n._sharedOptions){const s=o[0],n="function"==typeof s.getRange&&s.getRange(e);if(n){const s=t(o,e,i-n),a=t(o,e,i+n);return{lo:s.lo,hi:a.hi}}}}return{lo:0,hi:o.length-1}}function Ei(t,e,i,s,n){const o=t.getSortedVisibleDatasetMetas(),a=i[e];for(let t=0,i=o.length;t<i;++t){const{index:i,data:r}=o[t],{lo:l,hi:h}=Li(o[t],e,a,n);for(let t=l;t<=h;++t){const e=r[t];e.skip||s(e,i,t)}}}function Ri(t,e,i,s,n){const o=[];if(!n&&!t.isPointInArea(e))return o;return Ei(t,i,e,(function(i,a,r){(n||Se(i,t.chartArea,0))&&i.inRange(e.x,e.y,s)&&o.push({element:i,datasetIndex:a,index:r})}),!0),o}function Ii(t,e,i,s,n,o){let a=[];const r=function(t){const e=-1!==t.indexOf("x"),i=-1!==t.indexOf("y");return function(t,s){const n=e?Math.abs(t.x-s.x):0,o=i?Math.abs(t.y-s.y):0;return Math.sqrt(Math.pow(n,2)+Math.pow(o,2))}}(i);let l=Number.POSITIVE_INFINITY;return Ei(t,i,e,(function(i,h,c){const d=i.inRange(e.x,e.y,n);if(s&&!d)return;const u=i.getCenterPoint(n);if(!(!!o||t.isPointInArea(u))&&!d)return;const f=r(e,u);f<l?(a=[{element:i,datasetIndex:h,index:c}],l=f):f===l&&a.push({element:i,datasetIndex:h,index:c})})),a}function zi(t,e,i,s,n,o){return o||t.isPointInArea(e)?"r"!==i||s?Ii(t,e,i,s,n,o):function(t,e,i,s){let n=[];return Ei(t,i,e,(function(t,i,o){const{startAngle:a,endAngle:r}=t.getProps(["startAngle","endAngle"],s),{angle:l}=U(t,{x:e.x,y:e.y});G(l,a,r)&&n.push({element:t,datasetIndex:i,index:o})})),n}(t,e,i,n):[]}function Fi(t,e,i,s,n){const o=[],a="x"===i?"inXRange":"inYRange";let r=!1;return Ei(t,i,e,((t,s,l)=>{t[a](e[i],n)&&(o.push({element:t,datasetIndex:s,index:l}),r=r||t.inRange(e.x,e.y,n))})),s&&!r?[]:o}var Vi={evaluateInteractionItems:Ei,modes:{index(t,e,i,s){const n=ue(e,t),o=i.axis||"x",a=i.includeInvisible||!1,r=i.intersect?Ri(t,n,o,s,a):zi(t,n,o,!1,s,a),l=[];return r.length?(t.getSortedVisibleDatasetMetas().forEach((t=>{const e=r[0].index,i=t.data[e];i&&!i.skip&&l.push({element:i,datasetIndex:t.index,index:e})})),l):[]},dataset(t,e,i,s){const n=ue(e,t),o=i.axis||"xy",a=i.includeInvisible||!1;let r=i.intersect?Ri(t,n,o,s,a):zi(t,n,o,!1,s,a);if(r.length>0){const e=r[0].datasetIndex,i=t.getDatasetMeta(e).data;r=[];for(let t=0;t<i.length;++t)r.push({element:i[t],datasetIndex:e,index:t})}return r},point:(t,e,i,s)=>Ri(t,ue(e,t),i.axis||"xy",s,i.includeInvisible||!1),nearest(t,e,i,s){const n=ue(e,t),o=i.axis||"xy",a=i.includeInvisible||!1;return zi(t,n,o,i.intersect,s,a)},x:(t,e,i,s)=>Fi(t,ue(e,t),"x",i.intersect,s),y:(t,e,i,s)=>Fi(t,ue(e,t),"y",i.intersect,s)}};const Bi=["left","top","right","bottom"];function Ni(t,e){return t.filter((t=>t.pos===e))}function Wi(t,e){return t.filter((t=>-1===Bi.indexOf(t.pos)&&t.box.axis===e))}function ji(t,e){return t.sort(((t,i)=>{const s=e?i:t,n=e?t:i;return s.weight===n.weight?s.index-n.index:s.weight-n.weight}))}function Hi(t,e){const i=function(t){const e={};for(const i of t){const{stack:t,pos:s,stackWeight:n}=i;if(!t||!Bi.includes(s))continue;const o=e[t]||(e[t]={count:0,placed:0,weight:0,size:0});o.count++,o.weight+=n}return e}(t),{vBoxMaxWidth:s,hBoxMaxHeight:n}=e;let o,a,r;for(o=0,a=t.length;o<a;++o){r=t[o];const{fullSize:a}=r.box,l=i[r.stack],h=l&&r.stackWeight/l.weight;r.horizontal?(r.width=h?h*s:a&&e.availableWidth,r.height=n):(r.width=s,r.height=h?h*n:a&&e.availableHeight)}return i}function $i(t,e,i,s){return Math.max(t[i],e[i])+Math.max(t[s],e[s])}function Yi(t,e){t.top=Math.max(t.top,e.top),t.left=Math.max(t.left,e.left),t.bottom=Math.max(t.bottom,e.bottom),t.right=Math.max(t.right,e.right)}function Ui(t,e,i,s){const{pos:o,box:a}=i,r=t.maxPadding;if(!n(o)){i.size&&(t[o]-=i.size);const e=s[i.stack]||{size:0,count:1};e.size=Math.max(e.size,i.horizontal?a.height:a.width),i.size=e.size/e.count,t[o]+=i.size}a.getPadding&&Yi(r,a.getPadding());const l=Math.max(0,e.outerWidth-$i(r,t,"left","right")),h=Math.max(0,e.outerHeight-$i(r,t,"top","bottom")),c=l!==t.w,d=h!==t.h;return t.w=l,t.h=h,i.horizontal?{same:c,other:d}:{same:d,other:c}}function Xi(t,e){const i=e.maxPadding;function s(t){const s={left:0,top:0,right:0,bottom:0};return t.forEach((t=>{s[t]=Math.max(e[t],i[t])})),s}return s(t?["left","right"]:["top","bottom"])}function qi(t,e,i,s){const n=[];let o,a,r,l,h,c;for(o=0,a=t.length,h=0;o<a;++o){r=t[o],l=r.box,l.update(r.width||e.w,r.height||e.h,Xi(r.horizontal,e));const{same:a,other:d}=Ui(e,i,r,s);h|=a&&n.length,c=c||d,l.fullSize||n.push(r)}return h&&qi(n,e,i,s)||c}function Ki(t,e,i,s,n){t.top=i,t.left=e,t.right=e+s,t.bottom=i+n,t.width=s,t.height=n}function Gi(t,e,i,s){const n=i.padding;let{x:o,y:a}=e;for(const r of t){const t=r.box,l=s[r.stack]||{count:1,placed:0,weight:1},h=r.stackWeight/l.weight||1;if(r.horizontal){const s=e.w*h,o=l.size||t.height;M(l.start)&&(a=l.start),t.fullSize?Ki(t,n.left,a,i.outerWidth-n.right-n.left,o):Ki(t,e.left+l.placed,a,s,o),l.start=a,l.placed+=s,a=t.bottom}else{const s=e.h*h,a=l.size||t.width;M(l.start)&&(o=l.start),t.fullSize?Ki(t,o,n.top,a,i.outerHeight-n.bottom-n.top):Ki(t,o,e.top+l.placed,a,s),l.start=o,l.placed+=s,o=t.right}}e.x=o,e.y=a}ne.set("layout",{autoPadding:!0,padding:{top:0,right:0,bottom:0,left:0}});var Zi={addBox(t,e){t.boxes||(t.boxes=[]),e.fullSize=e.fullSize||!1,e.position=e.position||"top",e.weight=e.weight||0,e._layers=e._layers||function(){return[{z:0,draw(t){e.draw(t)}}]},t.boxes.push(e)},removeBox(t,e){const i=t.boxes?t.boxes.indexOf(e):-1;-1!==i&&t.boxes.splice(i,1)},configure(t,e,i){e.fullSize=i.fullSize,e.position=i.position,e.weight=i.weight},update(t,e,i,s){if(!t)return;const n=pi(t.options.layout.padding),o=Math.max(e-n.width,0),a=Math.max(i-n.height,0),r=function(t){const e=function(t){const e=[];let i,s,n,o,a,r;for(i=0,s=(t||[]).length;i<s;++i)n=t[i],({position:o,options:{stack:a,stackWeight:r=1}}=n),e.push({index:i,box:n,pos:o,horizontal:n.isHorizontal(),weight:n.weight,stack:a&&o+a,stackWeight:r});return e}(t),i=ji(e.filter((t=>t.box.fullSize)),!0),s=ji(Ni(e,"left"),!0),n=ji(Ni(e,"right")),o=ji(Ni(e,"top"),!0),a=ji(Ni(e,"bottom")),r=Wi(e,"x"),l=Wi(e,"y");return{fullSize:i,leftAndTop:s.concat(o),rightAndBottom:n.concat(l).concat(a).concat(r),chartArea:Ni(e,"chartArea"),vertical:s.concat(n).concat(l),horizontal:o.concat(a).concat(r)}}(t.boxes),l=r.vertical,h=r.horizontal;d(t.boxes,(t=>{"function"==typeof t.beforeLayout&&t.beforeLayout()}));const c=l.reduce(((t,e)=>e.box.options&&!1===e.box.options.display?t:t+1),0)||1,u=Object.freeze({outerWidth:e,outerHeight:i,padding:n,availableWidth:o,availableHeight:a,vBoxMaxWidth:o/2/c,hBoxMaxHeight:a/2}),f=Object.assign({},n);Yi(f,pi(s));const g=Object.assign({maxPadding:f,w:o,h:a,x:n.left,y:n.top},n),p=Hi(l.concat(h),u);qi(r.fullSize,g,u,p),qi(l,g,u,p),qi(h,g,u,p)&&qi(l,g,u,p),function(t){const e=t.maxPadding;function i(i){const s=Math.max(e[i]-t[i],0);return t[i]+=s,s}t.y+=i("top"),t.x+=i("left"),i("right"),i("bottom")}(g),Gi(r.leftAndTop,g,u,p),g.x+=g.w,g.y+=g.h,Gi(r.rightAndBottom,g,u,p),t.chartArea={left:g.left,top:g.top,right:g.left+g.w,bottom:g.top+g.h,height:g.h,width:g.w},d(r.chartArea,(e=>{const i=e.box;Object.assign(i,t.chartArea),i.update(g.w,g.h,{left:0,top:0,right:0,bottom:0})}))}};class Ji{acquireContext(t,e){}releaseContext(t){return!1}addEventListener(t,e,i){}removeEventListener(t,e,i){}getDevicePixelRatio(){return 1}getMaximumSize(t,e,i,s){return e=Math.max(0,e||t.width),i=i||t.height,{width:e,height:Math.max(0,s?Math.floor(e/s):i)}}isAttached(t){return!0}updateConfig(t){}}class Qi extends Ji{acquireContext(t){return t&&t.getContext&&t.getContext("2d")||null}updateConfig(t){t.options.animation=!1}}const ts={touchstart:"mousedown",touchmove:"mousemove",touchend:"mouseup",pointerenter:"mouseenter",pointerdown:"mousedown",pointermove:"mousemove",pointerup:"mouseup",pointerleave:"mouseout",pointerout:"mouseout"},es=t=>null===t||""===t;const is=!!me&&{passive:!0};function ss(t,e,i){t.canvas.removeEventListener(e,i,is)}function ns(t,e){for(const i of t)if(i===e||i.contains(e))return!0}function os(t,e,i){const s=t.canvas,n=new MutationObserver((t=>{let e=!1;for(const i of t)e=e||ns(i.addedNodes,s),e=e&&!ns(i.removedNodes,s);e&&i()}));return n.observe(document,{childList:!0,subtree:!0}),n}function as(t,e,i){const s=t.canvas,n=new MutationObserver((t=>{let e=!1;for(const i of t)e=e||ns(i.removedNodes,s),e=e&&!ns(i.addedNodes,s);e&&i()}));return n.observe(document,{childList:!0,subtree:!0}),n}const rs=new Map;let ls=0;function hs(){const t=window.devicePixelRatio;t!==ls&&(ls=t,rs.forEach(((e,i)=>{i.currentDevicePixelRatio!==t&&e()})))}function cs(t,e,i){const s=t.canvas,n=s&&ae(s);if(!n)return;const o=ht(((t,e)=>{const s=n.clientWidth;i(t,e),s<n.clientWidth&&i()}),window),a=new ResizeObserver((t=>{const e=t[0],i=e.contentRect.width,s=e.contentRect.height;0===i&&0===s||o(i,s)}));return a.observe(n),function(t,e){rs.size||window.addEventListener("resize",hs),rs.set(t,e)}(t,o),a}function ds(t,e,i){i&&i.disconnect(),"resize"===e&&function(t){rs.delete(t),rs.size||window.removeEventListener("resize",hs)}(t)}function us(t,e,i){const s=t.canvas,n=ht((e=>{null!==t.ctx&&i(function(t,e){const i=ts[t.type]||t.type,{x:s,y:n}=ue(t,e);return{type:i,chart:e,native:t,x:void 0!==s?s:null,y:void 0!==n?n:null}}(e,t))}),t,(t=>{const e=t[0];return[e,e.offsetX,e.offsetY]}));return function(t,e,i){t.addEventListener(e,i,is)}(s,e,n),n}class fs extends Ji{acquireContext(t,e){const i=t&&t.getContext&&t.getContext("2d");return i&&i.canvas===t?(function(t,e){const i=t.style,s=t.getAttribute("height"),n=t.getAttribute("width");if(t.$chartjs={initial:{height:s,width:n,style:{display:i.display,height:i.height,width:i.width}}},i.display=i.display||"block",i.boxSizing=i.boxSizing||"border-box",es(n)){const e=be(t,"width");void 0!==e&&(t.width=e)}if(es(s))if(""===t.style.height)t.height=t.width/(e||2);else{const e=be(t,"height");void 0!==e&&(t.height=e)}}(t,e),i):null}releaseContext(t){const e=t.canvas;if(!e.$chartjs)return!1;const s=e.$chartjs.initial;["height","width"].forEach((t=>{const n=s[t];i(n)?e.removeAttribute(t):e.setAttribute(t,n)}));const n=s.style||{};return Object.keys(n).forEach((t=>{e.style[t]=n[t]})),e.width=e.width,delete e.$chartjs,!0}addEventListener(t,e,i){this.removeEventListener(t,e);const s=t.$proxies||(t.$proxies={}),n={attach:os,detach:as,resize:cs}[e]||us;s[e]=n(t,e,i)}removeEventListener(t,e){const i=t.$proxies||(t.$proxies={}),s=i[e];if(!s)return;({attach:ds,detach:ds,resize:ds}[e]||ss)(t,e,s),i[e]=void 0}getDevicePixelRatio(){return window.devicePixelRatio}getMaximumSize(t,e,i,s){return ge(t,e,i,s)}isAttached(t){const e=ae(t);return!(!e||!e.isConnected)}}function gs(t){return!oe()||"undefined"!=typeof OffscreenCanvas&&t instanceof OffscreenCanvas?Qi:fs}var ps=Object.freeze({__proto__:null,_detectPlatform:gs,BasePlatform:Ji,BasicPlatform:Qi,DomPlatform:fs});const ms="transparent",bs={boolean:(t,e,i)=>i>.5?e:t,color(t,e,i){const s=Jt(t||ms),n=s.valid&&Jt(e||ms);return n&&n.valid?n.mix(s,i).hexString():e},number:(t,e,i)=>t+(e-t)*i};class xs{constructor(t,e,i,s){const n=e[i];s=bi([t.to,s,n,t.from]);const o=bi([t.from,n,s]);this._active=!0,this._fn=t.fn||bs[t.type||typeof o],this._easing=si[t.easing]||si.linear,this._start=Math.floor(Date.now()+(t.delay||0)),this._duration=this._total=Math.floor(t.duration),this._loop=!!t.loop,this._target=e,this._prop=i,this._from=o,this._to=s,this._promises=void 0}active(){return this._active}update(t,e,i){if(this._active){this._notify(!1);const s=this._target[this._prop],n=i-this._start,o=this._duration-n;this._start=i,this._duration=Math.floor(Math.max(o,t.duration)),this._total+=n,this._loop=!!t.loop,this._to=bi([t.to,e,s,t.from]),this._from=bi([t.from,s,e])}}cancel(){this._active&&(this.tick(Date.now()),this._active=!1,this._notify(!1))}tick(t){const e=t-this._start,i=this._duration,s=this._prop,n=this._from,o=this._loop,a=this._to;let r;if(this._active=n!==a&&(o||e<i),!this._active)return this._target[s]=a,void this._notify(!0);e<0?this._target[s]=n:(r=e/i%2,r=o&&r>1?2-r:r,r=this._easing(Math.min(1,Math.max(0,r))),this._target[s]=this._fn(n,a,r))}wait(){const t=this._promises||(this._promises=[]);return new Promise(((e,i)=>{t.push({res:e,rej:i})}))}_notify(t){const e=t?"res":"rej",i=this._promises||[];for(let t=0;t<i.length;t++)i[t][e]()}}ne.set("animation",{delay:void 0,duration:1e3,easing:"easeOutQuart",fn:void 0,from:void 0,loop:void 0,to:void 0,type:void 0});const _s=Object.keys(ne.animation);ne.describe("animation",{_fallback:!1,_indexable:!1,_scriptable:t=>"onProgress"!==t&&"onComplete"!==t&&"fn"!==t}),ne.set("animations",{colors:{type:"color",properties:["color","borderColor","backgroundColor"]},numbers:{type:"number",properties:["x","y","borderWidth","radius","tension"]}}),ne.describe("animations",{_fallback:"animation"}),ne.set("transitions",{active:{animation:{duration:400}},resize:{animation:{duration:0}},show:{animations:{colors:{from:"transparent"},visible:{type:"boolean",duration:0}}},hide:{animations:{colors:{to:"transparent"},visible:{type:"boolean",easing:"linear",fn:t=>0|t}}}});class ys{constructor(t,e){this._chart=t,this._properties=new Map,this.configure(e)}configure(t){if(!n(t))return;const e=this._properties;Object.getOwnPropertyNames(t).forEach((i=>{const o=t[i];if(!n(o))return;const a={};for(const t of _s)a[t]=o[t];(s(o.properties)&&o.properties||[i]).forEach((t=>{t!==i&&e.has(t)||e.set(t,a)}))}))}_animateOptions(t,e){const i=e.options,s=function(t,e){if(!e)return;let i=t.options;if(!i)return void(t.options=e);i.$shared&&(t.options=i=Object.assign({},i,{$shared:!1,$animations:{}}));return i}(t,i);if(!s)return[];const n=this._createAnimations(s,i);return i.$shared&&function(t,e){const i=[],s=Object.keys(e);for(let e=0;e<s.length;e++){const n=t[s[e]];n&&n.active()&&i.push(n.wait())}return Promise.all(i)}(t.options.$animations,i).then((()=>{t.options=i}),(()=>{})),n}_createAnimations(t,e){const i=this._properties,s=[],n=t.$animations||(t.$animations={}),o=Object.keys(e),a=Date.now();let r;for(r=o.length-1;r>=0;--r){const l=o[r];if("$"===l.charAt(0))continue;if("options"===l){s.push(...this._animateOptions(t,e));continue}const h=e[l];let c=n[l];const d=i.get(l);if(c){if(d&&c.active()){c.update(d,h,a);continue}c.cancel()}d&&d.duration?(n[l]=c=new xs(d,t,l,h),s.push(c)):t[l]=h}return s}update(t,e){if(0===this._properties.size)return void Object.assign(t,e);const i=this._createAnimations(t,e);return i.length?(mt.add(this._chart,i),!0):void 0}}function vs(t,e){const i=t&&t.options||{},s=i.reverse,n=void 0===i.min?e:0,o=void 0===i.max?e:0;return{start:s?o:n,end:s?n:o}}function ws(t,e){const i=[],s=t._getSortedDatasetMetas(e);let n,o;for(n=0,o=s.length;n<o;++n)i.push(s[n].index);return i}function Ms(t,e,i,s={}){const n=t.keys,a="single"===s.mode;let r,l,h,c;if(null!==e){for(r=0,l=n.length;r<l;++r){if(h=+n[r],h===i){if(s.all)continue;break}c=t.values[h],o(c)&&(a||0===e||z(e)===z(c))&&(e+=c)}return e}}function ks(t,e){const i=t&&t.options.stacked;return i||void 0===i&&void 0!==e.stack}function Ss(t,e,i){const s=t[e]||(t[e]={});return s[i]||(s[i]={})}function Ps(t,e,i,s){for(const n of e.getMatchingVisibleMetas(s).reverse()){const e=t[n.index];if(i&&e>0||!i&&e<0)return n.index}return null}function Ds(t,e){const{chart:i,_cachedMeta:s}=t,n=i._stacks||(i._stacks={}),{iScale:o,vScale:a,index:r}=s,l=o.axis,h=a.axis,c=function(t,e,i){return`${t.id}.${e.id}.${i.stack||i.type}`}(o,a,s),d=e.length;let u;for(let t=0;t<d;++t){const i=e[t],{[l]:o,[h]:d}=i;u=(i._stacks||(i._stacks={}))[h]=Ss(n,c,o),u[r]=d,u._top=Ps(u,a,!0,s.type),u._bottom=Ps(u,a,!1,s.type)}}function Os(t,e){const i=t.scales;return Object.keys(i).filter((t=>i[t].axis===e)).shift()}function Cs(t,e){const i=t.controller.index,s=t.vScale&&t.vScale.axis;if(s){e=e||t._parsed;for(const t of e){const e=t._stacks;if(!e||void 0===e[s]||void 0===e[s][i])return;delete e[s][i]}}}const As=t=>"reset"===t||"none"===t,Ts=(t,e)=>e?t:Object.assign({},t);class Ls{constructor(t,e){this.chart=t,this._ctx=t.ctx,this.index=e,this._cachedDataOpts={},this._cachedMeta=this.getMeta(),this._type=this._cachedMeta.type,this.options=void 0,this._parsing=!1,this._data=void 0,this._objectData=void 0,this._sharedOptions=void 0,this._drawStart=void 0,this._drawCount=void 0,this.enableOptionSharing=!1,this.supportsDecimation=!1,this.$context=void 0,this._syncList=[],this.initialize()}initialize(){const t=this._cachedMeta;this.configure(),this.linkScales(),t._stacked=ks(t.vScale,t),this.addElements()}updateIndex(t){this.index!==t&&Cs(this._cachedMeta),this.index=t}linkScales(){const t=this.chart,e=this._cachedMeta,i=this.getDataset(),s=(t,e,i,s)=>"x"===t?e:"r"===t?s:i,n=e.xAxisID=r(i.xAxisID,Os(t,"x")),o=e.yAxisID=r(i.yAxisID,Os(t,"y")),a=e.rAxisID=r(i.rAxisID,Os(t,"r")),l=e.indexAxis,h=e.iAxisID=s(l,n,o,a),c=e.vAxisID=s(l,o,n,a);e.xScale=this.getScaleForId(n),e.yScale=this.getScaleForId(o),e.rScale=this.getScaleForId(a),e.iScale=this.getScaleForId(h),e.vScale=this.getScaleForId(c)}getDataset(){return this.chart.data.datasets[this.index]}getMeta(){return this.chart.getDatasetMeta(this.index)}getScaleForId(t){return this.chart.scales[t]}_getOtherScale(t){const e=this._cachedMeta;return t===e.iScale?e.vScale:e.iScale}reset(){this._update("reset")}_destroy(){const t=this._cachedMeta;this._data&&at(this._data,this),t._stacked&&Cs(t)}_dataCheck(){const t=this.getDataset(),e=t.data||(t.data=[]),i=this._data;if(n(e))this._data=function(t){const e=Object.keys(t),i=new Array(e.length);let s,n,o;for(s=0,n=e.length;s<n;++s)o=e[s],i[s]={x:o,y:t[o]};return i}(e);else if(i!==e){if(i){at(i,this);const t=this._cachedMeta;Cs(t),t._parsed=[]}e&&Object.isExtensible(e)&&ot(e,this),this._syncList=[],this._data=e}}addElements(){const t=this._cachedMeta;this._dataCheck(),this.datasetElementType&&(t.dataset=new this.datasetElementType)}buildOrUpdateElements(t){const e=this._cachedMeta,i=this.getDataset();let s=!1;this._dataCheck();const n=e._stacked;e._stacked=ks(e.vScale,e),e.stack!==i.stack&&(s=!0,Cs(e),e.stack=i.stack),this._resyncElements(t),(s||n!==e._stacked)&&Ds(this,e._parsed)}configure(){const t=this.chart.config,e=t.datasetScopeKeys(this._type),i=t.getOptionScopes(this.getDataset(),e,!0);this.options=t.createResolver(i,this.getContext()),this._parsing=this.options.parsing,this._cachedDataOpts={}}parse(t,e){const{_cachedMeta:i,_data:o}=this,{iScale:a,_stacked:r}=i,l=a.axis;let h,c,d,u=0===t&&e===o.length||i._sorted,f=t>0&&i._parsed[t-1];if(!1===this._parsing)i._parsed=o,i._sorted=!0,d=o;else{d=s(o[t])?this.parseArrayData(i,o,t,e):n(o[t])?this.parseObjectData(i,o,t,e):this.parsePrimitiveData(i,o,t,e);const a=()=>null===c[l]||f&&c[l]<f[l];for(h=0;h<e;++h)i._parsed[h+t]=c=d[h],u&&(a()&&(u=!1),f=c);i._sorted=u}r&&Ds(this,d)}parsePrimitiveData(t,e,i,s){const{iScale:n,vScale:o}=t,a=n.axis,r=o.axis,l=n.getLabels(),h=n===o,c=new Array(s);let d,u,f;for(d=0,u=s;d<u;++d)f=d+i,c[d]={[a]:h||n.parse(l[f],f),[r]:o.parse(e[f],f)};return c}parseArrayData(t,e,i,s){const{xScale:n,yScale:o}=t,a=new Array(s);let r,l,h,c;for(r=0,l=s;r<l;++r)h=r+i,c=e[h],a[r]={x:n.parse(c[0],h),y:o.parse(c[1],h)};return a}parseObjectData(t,e,i,s){const{xScale:n,yScale:o}=t,{xAxisKey:a="x",yAxisKey:r="y"}=this._parsing,l=new Array(s);let h,c,d,u;for(h=0,c=s;h<c;++h)d=h+i,u=e[d],l[h]={x:n.parse(y(u,a),d),y:o.parse(y(u,r),d)};return l}getParsed(t){return this._cachedMeta._parsed[t]}getDataElement(t){return this._cachedMeta.data[t]}applyStack(t,e,i){const s=this.chart,n=this._cachedMeta,o=e[t.axis];return Ms({keys:ws(s,!0),values:e._stacks[t.axis]},o,n.index,{mode:i})}updateRangeFromParsed(t,e,i,s){const n=i[e.axis];let o=null===n?NaN:n;const a=s&&i._stacks[e.axis];s&&a&&(s.values=a,o=Ms(s,n,this._cachedMeta.index)),t.min=Math.min(t.min,o),t.max=Math.max(t.max,o)}getMinMax(t,e){const i=this._cachedMeta,s=i._parsed,n=i._sorted&&t===i.iScale,a=s.length,r=this._getOtherScale(t),l=((t,e,i)=>t&&!e.hidden&&e._stacked&&{keys:ws(i,!0),values:null})(e,i,this.chart),h={min:Number.POSITIVE_INFINITY,max:Number.NEGATIVE_INFINITY},{min:c,max:d}=function(t){const{min:e,max:i,minDefined:s,maxDefined:n}=t.getUserBounds();return{min:s?e:Number.NEGATIVE_INFINITY,max:n?i:Number.POSITIVE_INFINITY}}(r);let u,f;function g(){f=s[u];const e=f[r.axis];return!o(f[t.axis])||c>e||d<e}for(u=0;u<a&&(g()||(this.updateRangeFromParsed(h,t,f,l),!n));++u);if(n)for(u=a-1;u>=0;--u)if(!g()){this.updateRangeFromParsed(h,t,f,l);break}return h}getAllParsedValues(t){const e=this._cachedMeta._parsed,i=[];let s,n,a;for(s=0,n=e.length;s<n;++s)a=e[s][t.axis],o(a)&&i.push(a);return i}getMaxOverflow(){return!1}getLabelAndValue(t){const e=this._cachedMeta,i=e.iScale,s=e.vScale,n=this.getParsed(t);return{label:i?""+i.getLabelForValue(n[i.axis]):"",value:s?""+s.getLabelForValue(n[s.axis]):""}}_update(t){const e=this._cachedMeta;this.update(t||"default"),e._clip=function(t){let e,i,s,o;return n(t)?(e=t.top,i=t.right,s=t.bottom,o=t.left):e=i=s=o=t,{top:e,right:i,bottom:s,left:o,disabled:!1===t}}(r(this.options.clip,function(t,e,i){if(!1===i)return!1;const s=vs(t,i),n=vs(e,i);return{top:n.end,right:s.end,bottom:n.start,left:s.start}}(e.xScale,e.yScale,this.getMaxOverflow())))}update(t){}draw(){const t=this._ctx,e=this.chart,i=this._cachedMeta,s=i.data||[],n=e.chartArea,o=[],a=this._drawStart||0,r=this._drawCount||s.length-a,l=this.options.drawActiveElementsOnTop;let h;for(i.dataset&&i.dataset.draw(t,n,a,r),h=a;h<a+r;++h){const e=s[h];e.hidden||(e.active&&l?o.push(e):e.draw(t,n))}for(h=0;h<o.length;++h)o[h].draw(t,n)}getStyle(t,e){const i=e?"active":"default";return void 0===t&&this._cachedMeta.dataset?this.resolveDatasetElementOptions(i):this.resolveDataElementOptions(t||0,i)}getContext(t,e,i){const s=this.getDataset();let n;if(t>=0&&t<this._cachedMeta.data.length){const e=this._cachedMeta.data[t];n=e.$context||(e.$context=function(t,e,i){return _i(t,{active:!1,dataIndex:e,parsed:void 0,raw:void 0,element:i,index:e,mode:"default",type:"data"})}(this.getContext(),t,e)),n.parsed=this.getParsed(t),n.raw=s.data[t],n.index=n.dataIndex=t}else n=this.$context||(this.$context=function(t,e){return _i(t,{active:!1,dataset:void 0,datasetIndex:e,index:e,mode:"default",type:"dataset"})}(this.chart.getContext(),this.index)),n.dataset=s,n.index=n.datasetIndex=this.index;return n.active=!!e,n.mode=i,n}resolveDatasetElementOptions(t){return this._resolveElementOptions(this.datasetElementType.id,t)}resolveDataElementOptions(t,e){return this._resolveElementOptions(this.dataElementType.id,e,t)}_resolveElementOptions(t,e="default",i){const s="active"===e,n=this._cachedDataOpts,o=t+"-"+e,a=n[o],r=this.enableOptionSharing&&M(i);if(a)return Ts(a,r);const l=this.chart.config,h=l.datasetElementScopeKeys(this._type,t),c=s?[`${t}Hover`,"hover",t,""]:[t,""],d=l.getOptionScopes(this.getDataset(),h),u=Object.keys(ne.elements[t]),f=l.resolveNamedOptions(d,u,(()=>this.getContext(i,s)),c);return f.$shared&&(f.$shared=r,n[o]=Object.freeze(Ts(f,r))),f}_resolveAnimations(t,e,i){const s=this.chart,n=this._cachedDataOpts,o=`animation-${e}`,a=n[o];if(a)return a;let r;if(!1!==s.options.animation){const s=this.chart.config,n=s.datasetAnimationScopeKeys(this._type,e),o=s.getOptionScopes(this.getDataset(),n);r=s.createResolver(o,this.getContext(t,i,e))}const l=new ys(s,r&&r.animations);return r&&r._cacheable&&(n[o]=Object.freeze(l)),l}getSharedOptions(t){if(t.$shared)return this._sharedOptions||(this._sharedOptions=Object.assign({},t))}includeOptions(t,e){return!e||As(t)||this.chart._animationsDisabled}_getSharedOptions(t,e){const i=this.resolveDataElementOptions(t,e),s=this._sharedOptions,n=this.getSharedOptions(i),o=this.includeOptions(e,n)||n!==s;return this.updateSharedOptions(n,e,i),{sharedOptions:n,includeOptions:o}}updateElement(t,e,i,s){As(s)?Object.assign(t,i):this._resolveAnimations(e,s).update(t,i)}updateSharedOptions(t,e,i){t&&!As(e)&&this._resolveAnimations(void 0,e).update(t,i)}_setStyle(t,e,i,s){t.active=s;const n=this.getStyle(e,s);this._resolveAnimations(e,i,s).update(t,{options:!s&&this.getSharedOptions(n)||n})}removeHoverStyle(t,e,i){this._setStyle(t,i,"active",!1)}setHoverStyle(t,e,i){this._setStyle(t,i,"active",!0)}_removeDatasetHoverStyle(){const t=this._cachedMeta.dataset;t&&this._setStyle(t,void 0,"active",!1)}_setDatasetHoverStyle(){const t=this._cachedMeta.dataset;t&&this._setStyle(t,void 0,"active",!0)}_resyncElements(t){const e=this._data,i=this._cachedMeta.data;for(const[t,e,i]of this._syncList)this[t](e,i);this._syncList=[];const s=i.length,n=e.length,o=Math.min(n,s);o&&this.parse(0,o),n>s?this._insertElements(s,n-s,t):n<s&&this._removeElements(n,s-n)}_insertElements(t,e,i=!0){const s=this._cachedMeta,n=s.data,o=t+e;let a;const r=t=>{for(t.length+=e,a=t.length-1;a>=o;a--)t[a]=t[a-e]};for(r(n),a=t;a<o;++a)n[a]=new this.dataElementType;this._parsing&&r(s._parsed),this.parse(t,e),i&&this.updateElements(n,t,e,"reset")}updateElements(t,e,i,s){}_removeElements(t,e){const i=this._cachedMeta;if(this._parsing){const s=i._parsed.splice(t,e);i._stacked&&Cs(i,s)}i.data.splice(t,e)}_sync(t){if(this._parsing)this._syncList.push(t);else{const[e,i,s]=t;this[e](i,s)}this.chart._dataChanges.push([this.index,...t])}_onDataPush(){const t=arguments.length;this._sync(["_insertElements",this.getDataset().data.length-t,t])}_onDataPop(){this._sync(["_removeElements",this._cachedMeta.data.length-1,1])}_onDataShift(){this._sync(["_removeElements",0,1])}_onDataSplice(t,e){e&&this._sync(["_removeElements",t,e]);const i=arguments.length-2;i&&this._sync(["_insertElements",t,i])}_onDataUnshift(){this._sync(["_insertElements",0,arguments.length])}}Ls.defaults={},Ls.prototype.datasetElementType=null,Ls.prototype.dataElementType=null;class Es{constructor(){this.x=void 0,this.y=void 0,this.active=!1,this.options=void 0,this.$animations=void 0}tooltipPosition(t){const{x:e,y:i}=this.getProps(["x","y"],t);return{x:e,y:i}}hasValue(){return B(this.x)&&B(this.y)}getProps(t,e){const i=this.$animations;if(!e||!i)return this;const s={};return t.forEach((t=>{s[t]=i[t]&&i[t].active()?i[t]._to:this[t]})),s}}Es.defaults={},Es.defaultRoutes=void 0;const Rs={values:t=>s(t)?t:""+t,numeric(t,e,i){if(0===t)return"0";const s=this.chart.options.locale;let n,o=t;if(i.length>1){const e=Math.max(Math.abs(i[0].value),Math.abs(i[i.length-1].value));(e<1e-4||e>1e15)&&(n="scientific"),o=function(t,e){let i=e.length>3?e[2].value-e[1].value:e[1].value-e[0].value;Math.abs(i)>=1&&t!==Math.floor(t)&&(i=t-Math.floor(t));return i}(t,i)}const a=I(Math.abs(o)),r=Math.max(Math.min(-1*Math.floor(a),20),0),l={notation:n,minimumFractionDigits:r,maximumFractionDigits:r};return Object.assign(l,this.options.ticks.format),li(t,s,l)},logarithmic(t,e,i){if(0===t)return"0";const s=t/Math.pow(10,Math.floor(I(t)));return 1===s||2===s||5===s?Rs.numeric.call(this,t,e,i):""}};var Is={formatters:Rs};function zs(t,e){const s=t.options.ticks,n=s.maxTicksLimit||function(t){const e=t.options.offset,i=t._tickSize(),s=t._length/i+(e?0:1),n=t._maxLength/i;return Math.floor(Math.min(s,n))}(t),o=s.major.enabled?function(t){const e=[];let i,s;for(i=0,s=t.length;i<s;i++)t[i].major&&e.push(i);return e}(e):[],a=o.length,r=o[0],l=o[a-1],h=[];if(a>n)return function(t,e,i,s){let n,o=0,a=i[0];for(s=Math.ceil(s),n=0;n<t.length;n++)n===a&&(e.push(t[n]),o++,a=i[o*s])}(e,h,o,a/n),h;const c=function(t,e,i){const s=function(t){const e=t.length;let i,s;if(e<2)return!1;for(s=t[0],i=1;i<e;++i)if(t[i]-t[i-1]!==s)return!1;return s}(t),n=e.length/i;if(!s)return Math.max(n,1);const o=V(s);for(let t=0,e=o.length-1;t<e;t++){const e=o[t];if(e>n)return e}return Math.max(n,1)}(o,e,n);if(a>0){let t,s;const n=a>1?Math.round((l-r)/(a-1)):null;for(Fs(e,h,c,i(n)?0:r-n,r),t=0,s=a-1;t<s;t++)Fs(e,h,c,o[t],o[t+1]);return Fs(e,h,c,l,i(n)?e.length:l+n),h}return Fs(e,h,c),h}function Fs(t,e,i,s,n){const o=r(s,0),a=Math.min(r(n,t.length),t.length);let l,h,c,d=0;for(i=Math.ceil(i),n&&(l=n-s,i=l/Math.floor(l/i)),c=o;c<0;)d++,c=Math.round(o+d*i);for(h=Math.max(o,0);h<a;h++)h===c&&(e.push(t[h]),d++,c=Math.round(o+d*i))}ne.set("scale",{display:!0,offset:!1,reverse:!1,beginAtZero:!1,bounds:"ticks",grace:0,grid:{display:!0,lineWidth:1,drawBorder:!0,drawOnChartArea:!0,drawTicks:!0,tickLength:8,tickWidth:(t,e)=>e.lineWidth,tickColor:(t,e)=>e.color,offset:!1,borderDash:[],borderDashOffset:0,borderWidth:1},title:{display:!1,text:"",padding:{top:4,bottom:4}},ticks:{minRotation:0,maxRotation:50,mirror:!1,textStrokeWidth:0,textStrokeColor:"",padding:3,display:!0,autoSkip:!0,autoSkipPadding:3,labelOffset:0,callback:Is.formatters.values,minor:{},major:{},align:"center",crossAlign:"near",showLabelBackdrop:!1,backdropColor:"rgba(255, 255, 255, 0.75)",backdropPadding:2}}),ne.route("scale.ticks","color","","color"),ne.route("scale.grid","color","","borderColor"),ne.route("scale.grid","borderColor","","borderColor"),ne.route("scale.title","color","","color"),ne.describe("scale",{_fallback:!1,_scriptable:t=>!t.startsWith("before")&&!t.startsWith("after")&&"callback"!==t&&"parser"!==t,_indexable:t=>"borderDash"!==t&&"tickBorderDash"!==t}),ne.describe("scales",{_fallback:"scale"}),ne.describe("scale.ticks",{_scriptable:t=>"backdropPadding"!==t&&"callback"!==t,_indexable:t=>"backdropPadding"!==t});const Vs=(t,e,i)=>"top"===e||"left"===e?t[e]+i:t[e]-i;function Bs(t,e){const i=[],s=t.length/e,n=t.length;let o=0;for(;o<n;o+=s)i.push(t[Math.floor(o)]);return i}function Ns(t,e,i){const s=t.ticks.length,n=Math.min(e,s-1),o=t._startPixel,a=t._endPixel,r=1e-6;let l,h=t.getPixelForTick(n);if(!(i&&(l=1===s?Math.max(h-o,a-h):0===e?(t.getPixelForTick(1)-h)/2:(h-t.getPixelForTick(n-1))/2,h+=n<e?l:-l,h<o-r||h>a+r)))return h}function Ws(t){return t.drawTicks?t.tickLength:0}function js(t,e){if(!t.display)return 0;const i=mi(t.font,e),n=pi(t.padding);return(s(t.text)?t.text.length:1)*i.lineHeight+n.height}function Hs(t,e,i){let s=dt(t);return(i&&"right"!==e||!i&&"right"===e)&&(s=(t=>"left"===t?"right":"right"===t?"left":t)(s)),s}class $s extends Es{constructor(t){super(),this.id=t.id,this.type=t.type,this.options=void 0,this.ctx=t.ctx,this.chart=t.chart,this.top=void 0,this.bottom=void 0,this.left=void 0,this.right=void 0,this.width=void 0,this.height=void 0,this._margins={left:0,right:0,top:0,bottom:0},this.maxWidth=void 0,this.maxHeight=void 0,this.paddingTop=void 0,this.paddingBottom=void 0,this.paddingLeft=void 0,this.paddingRight=void 0,this.axis=void 0,this.labelRotation=void 0,this.min=void 0,this.max=void 0,this._range=void 0,this.ticks=[],this._gridLineItems=null,this._labelItems=null,this._labelSizes=null,this._length=0,this._maxLength=0,this._longestTextCache={},this._startPixel=void 0,this._endPixel=void 0,this._reversePixels=!1,this._userMax=void 0,this._userMin=void 0,this._suggestedMax=void 0,this._suggestedMin=void 0,this._ticksLength=0,this._borderValue=0,this._cache={},this._dataLimitsCached=!1,this.$context=void 0}init(t){this.options=t.setContext(this.getContext()),this.axis=t.axis,this._userMin=this.parse(t.min),this._userMax=this.parse(t.max),this._suggestedMin=this.parse(t.suggestedMin),this._suggestedMax=this.parse(t.suggestedMax)}parse(t,e){return t}getUserBounds(){let{_userMin:t,_userMax:e,_suggestedMin:i,_suggestedMax:s}=this;return t=a(t,Number.POSITIVE_INFINITY),e=a(e,Number.NEGATIVE_INFINITY),i=a(i,Number.POSITIVE_INFINITY),s=a(s,Number.NEGATIVE_INFINITY),{min:a(t,i),max:a(e,s),minDefined:o(t),maxDefined:o(e)}}getMinMax(t){let e,{min:i,max:s,minDefined:n,maxDefined:o}=this.getUserBounds();if(n&&o)return{min:i,max:s};const r=this.getMatchingVisibleMetas();for(let a=0,l=r.length;a<l;++a)e=r[a].controller.getMinMax(this,t),n||(i=Math.min(i,e.min)),o||(s=Math.max(s,e.max));return i=o&&i>s?s:i,s=n&&i>s?i:s,{min:a(i,a(s,i)),max:a(s,a(i,s))}}getPadding(){return{left:this.paddingLeft||0,top:this.paddingTop||0,right:this.paddingRight||0,bottom:this.paddingBottom||0}}getTicks(){return this.ticks}getLabels(){const t=this.chart.data;return this.options.labels||(this.isHorizontal()?t.xLabels:t.yLabels)||t.labels||[]}beforeLayout(){this._cache={},this._dataLimitsCached=!1}beforeUpdate(){c(this.options.beforeUpdate,[this])}update(t,e,i){const{beginAtZero:s,grace:n,ticks:o}=this.options,a=o.sampleSize;this.beforeUpdate(),this.maxWidth=t,this.maxHeight=e,this._margins=i=Object.assign({left:0,right:0,top:0,bottom:0},i),this.ticks=null,this._labelSizes=null,this._gridLineItems=null,this._labelItems=null,this.beforeSetDimensions(),this.setDimensions(),this.afterSetDimensions(),this._maxLength=this.isHorizontal()?this.width+i.left+i.right:this.height+i.top+i.bottom,this._dataLimitsCached||(this.beforeDataLimits(),this.determineDataLimits(),this.afterDataLimits(),this._range=xi(this,n,s),this._dataLimitsCached=!0),this.beforeBuildTicks(),this.ticks=this.buildTicks()||[],this.afterBuildTicks();const r=a<this.ticks.length;this._convertTicksToLabels(r?Bs(this.ticks,a):this.ticks),this.configure(),this.beforeCalculateLabelRotation(),this.calculateLabelRotation(),this.afterCalculateLabelRotation(),o.display&&(o.autoSkip||"auto"===o.source)&&(this.ticks=zs(this,this.ticks),this._labelSizes=null,this.afterAutoSkip()),r&&this._convertTicksToLabels(this.ticks),this.beforeFit(),this.fit(),this.afterFit(),this.afterUpdate()}configure(){let t,e,i=this.options.reverse;this.isHorizontal()?(t=this.left,e=this.right):(t=this.top,e=this.bottom,i=!i),this._startPixel=t,this._endPixel=e,this._reversePixels=i,this._length=e-t,this._alignToPixels=this.options.alignToPixels}afterUpdate(){c(this.options.afterUpdate,[this])}beforeSetDimensions(){c(this.options.beforeSetDimensions,[this])}setDimensions(){this.isHorizontal()?(this.width=this.maxWidth,this.left=0,this.right=this.width):(this.height=this.maxHeight,this.top=0,this.bottom=this.height),this.paddingLeft=0,this.paddingTop=0,this.paddingRight=0,this.paddingBottom=0}afterSetDimensions(){c(this.options.afterSetDimensions,[this])}_callHooks(t){this.chart.notifyPlugins(t,this.getContext()),c(this.options[t],[this])}beforeDataLimits(){this._callHooks("beforeDataLimits")}determineDataLimits(){}afterDataLimits(){this._callHooks("afterDataLimits")}beforeBuildTicks(){this._callHooks("beforeBuildTicks")}buildTicks(){return[]}afterBuildTicks(){this._callHooks("afterBuildTicks")}beforeTickToLabelConversion(){c(this.options.beforeTickToLabelConversion,[this])}generateTickLabels(t){const e=this.options.ticks;let i,s,n;for(i=0,s=t.length;i<s;i++)n=t[i],n.label=c(e.callback,[n.value,i,t],this)}afterTickToLabelConversion(){c(this.options.afterTickToLabelConversion,[this])}beforeCalculateLabelRotation(){c(this.options.beforeCalculateLabelRotation,[this])}calculateLabelRotation(){const t=this.options,e=t.ticks,i=this.ticks.length,s=e.minRotation||0,n=e.maxRotation;let o,a,r,l=s;if(!this._isVisible()||!e.display||s>=n||i<=1||!this.isHorizontal())return void(this.labelRotation=s);const h=this._getLabelSizes(),c=h.widest.width,d=h.highest.height,u=Z(this.chart.width-c,0,this.maxWidth);o=t.offset?this.maxWidth/i:u/(i-1),c+6>o&&(o=u/(i-(t.offset?.5:1)),a=this.maxHeight-Ws(t.grid)-e.padding-js(t.title,this.chart.options.font),r=Math.sqrt(c*c+d*d),l=$(Math.min(Math.asin(Z((h.highest.height+6)/o,-1,1)),Math.asin(Z(a/r,-1,1))-Math.asin(Z(d/r,-1,1)))),l=Math.max(s,Math.min(n,l))),this.labelRotation=l}afterCalculateLabelRotation(){c(this.options.afterCalculateLabelRotation,[this])}afterAutoSkip(){}beforeFit(){c(this.options.beforeFit,[this])}fit(){const t={width:0,height:0},{chart:e,options:{ticks:i,title:s,grid:n}}=this,o=this._isVisible(),a=this.isHorizontal();if(o){const o=js(s,e.options.font);if(a?(t.width=this.maxWidth,t.height=Ws(n)+o):(t.height=this.maxHeight,t.width=Ws(n)+o),i.display&&this.ticks.length){const{first:e,last:s,widest:n,highest:o}=this._getLabelSizes(),r=2*i.padding,l=H(this.labelRotation),h=Math.cos(l),c=Math.sin(l);if(a){const e=i.mirror?0:c*n.width+h*o.height;t.height=Math.min(this.maxHeight,t.height+e+r)}else{const e=i.mirror?0:h*n.width+c*o.height;t.width=Math.min(this.maxWidth,t.width+e+r)}this._calculatePadding(e,s,c,h)}}this._handleMargins(),a?(this.width=this._length=e.width-this._margins.left-this._margins.right,this.height=t.height):(this.width=t.width,this.height=this._length=e.height-this._margins.top-this._margins.bottom)}_calculatePadding(t,e,i,s){const{ticks:{align:n,padding:o},position:a}=this.options,r=0!==this.labelRotation,l="top"!==a&&"x"===this.axis;if(this.isHorizontal()){const a=this.getPixelForTick(0)-this.left,h=this.right-this.getPixelForTick(this.ticks.length-1);let c=0,d=0;r?l?(c=s*t.width,d=i*e.height):(c=i*t.height,d=s*e.width):"start"===n?d=e.width:"end"===n?c=t.width:"inner"!==n&&(c=t.width/2,d=e.width/2),this.paddingLeft=Math.max((c-a+o)*this.width/(this.width-a),0),this.paddingRight=Math.max((d-h+o)*this.width/(this.width-h),0)}else{let i=e.height/2,s=t.height/2;"start"===n?(i=0,s=t.height):"end"===n&&(i=e.height,s=0),this.paddingTop=i+o,this.paddingBottom=s+o}}_handleMargins(){this._margins&&(this._margins.left=Math.max(this.paddingLeft,this._margins.left),this._margins.top=Math.max(this.paddingTop,this._margins.top),this._margins.right=Math.max(this.paddingRight,this._margins.right),this._margins.bottom=Math.max(this.paddingBottom,this._margins.bottom))}afterFit(){c(this.options.afterFit,[this])}isHorizontal(){const{axis:t,position:e}=this.options;return"top"===e||"bottom"===e||"x"===t}isFullSize(){return this.options.fullSize}_convertTicksToLabels(t){let e,s;for(this.beforeTickToLabelConversion(),this.generateTickLabels(t),e=0,s=t.length;e<s;e++)i(t[e].label)&&(t.splice(e,1),s--,e--);this.afterTickToLabelConversion()}_getLabelSizes(){let t=this._labelSizes;if(!t){const e=this.options.ticks.sampleSize;let i=this.ticks;e<i.length&&(i=Bs(i,e)),this._labelSizes=t=this._computeLabelSizes(i,i.length)}return t}_computeLabelSizes(t,e){const{ctx:n,_longestTextCache:o}=this,a=[],r=[];let l,h,c,u,f,g,p,m,b,x,_,y=0,v=0;for(l=0;l<e;++l){if(u=t[l].label,f=this._resolveTickFontOptions(l),n.font=g=f.string,p=o[g]=o[g]||{data:{},gc:[]},m=f.lineHeight,b=x=0,i(u)||s(u)){if(s(u))for(h=0,c=u.length;h<c;++h)_=u[h],i(_)||s(_)||(b=_e(n,p.data,p.gc,b,_),x+=m)}else b=_e(n,p.data,p.gc,b,u),x=m;a.push(b),r.push(x),y=Math.max(b,y),v=Math.max(x,v)}!function(t,e){d(t,(t=>{const i=t.gc,s=i.length/2;let n;if(s>e){for(n=0;n<s;++n)delete t.data[i[n]];i.splice(0,s)}}))}(o,e);const w=a.indexOf(y),M=r.indexOf(v),k=t=>({width:a[t]||0,height:r[t]||0});return{first:k(0),last:k(e-1),widest:k(w),highest:k(M),widths:a,heights:r}}getLabelForValue(t){return t}getPixelForValue(t,e){return NaN}getValueForPixel(t){}getPixelForTick(t){const e=this.ticks;return t<0||t>e.length-1?null:this.getPixelForValue(e[t].value)}getPixelForDecimal(t){this._reversePixels&&(t=1-t);const e=this._startPixel+t*this._length;return J(this._alignToPixels?ve(this.chart,e,0):e)}getDecimalForPixel(t){const e=(t-this._startPixel)/this._length;return this._reversePixels?1-e:e}getBasePixel(){return this.getPixelForValue(this.getBaseValue())}getBaseValue(){const{min:t,max:e}=this;return t<0&&e<0?e:t>0&&e>0?t:0}getContext(t){const e=this.ticks||[];if(t>=0&&t<e.length){const i=e[t];return i.$context||(i.$context=function(t,e,i){return _i(t,{tick:i,index:e,type:"tick"})}(this.getContext(),t,i))}return this.$context||(this.$context=_i(this.chart.getContext(),{scale:this,type:"scale"}))}_tickSize(){const t=this.options.ticks,e=H(this.labelRotation),i=Math.abs(Math.cos(e)),s=Math.abs(Math.sin(e)),n=this._getLabelSizes(),o=t.autoSkipPadding||0,a=n?n.widest.width+o:0,r=n?n.highest.height+o:0;return this.isHorizontal()?r*i>a*s?a/i:r/s:r*s<a*i?r/i:a/s}_isVisible(){const t=this.options.display;return"auto"!==t?!!t:this.getMatchingVisibleMetas().length>0}_computeGridLineItems(t){const e=this.axis,i=this.chart,s=this.options,{grid:o,position:a}=s,l=o.offset,h=this.isHorizontal(),c=this.ticks.length+(l?1:0),d=Ws(o),u=[],f=o.setContext(this.getContext()),g=f.drawBorder?f.borderWidth:0,p=g/2,m=function(t){return ve(i,t,g)};let b,x,_,y,v,w,M,k,S,P,D,O;if("top"===a)b=m(this.bottom),w=this.bottom-d,k=b-p,P=m(t.top)+p,O=t.bottom;else if("bottom"===a)b=m(this.top),P=t.top,O=m(t.bottom)-p,w=b+p,k=this.top+d;else if("left"===a)b=m(this.right),v=this.right-d,M=b-p,S=m(t.left)+p,D=t.right;else if("right"===a)b=m(this.left),S=t.left,D=m(t.right)-p,v=b+p,M=this.left+d;else if("x"===e){if("center"===a)b=m((t.top+t.bottom)/2+.5);else if(n(a)){const t=Object.keys(a)[0],e=a[t];b=m(this.chart.scales[t].getPixelForValue(e))}P=t.top,O=t.bottom,w=b+p,k=w+d}else if("y"===e){if("center"===a)b=m((t.left+t.right)/2);else if(n(a)){const t=Object.keys(a)[0],e=a[t];b=m(this.chart.scales[t].getPixelForValue(e))}v=b-p,M=v-d,S=t.left,D=t.right}const C=r(s.ticks.maxTicksLimit,c),A=Math.max(1,Math.ceil(c/C));for(x=0;x<c;x+=A){const t=o.setContext(this.getContext(x)),e=t.lineWidth,s=t.color,n=t.borderDash||[],a=t.borderDashOffset,r=t.tickWidth,c=t.tickColor,d=t.tickBorderDash||[],f=t.tickBorderDashOffset;_=Ns(this,x,l),void 0!==_&&(y=ve(i,_,e),h?v=M=S=D=y:w=k=P=O=y,u.push({tx1:v,ty1:w,tx2:M,ty2:k,x1:S,y1:P,x2:D,y2:O,width:e,color:s,borderDash:n,borderDashOffset:a,tickWidth:r,tickColor:c,tickBorderDash:d,tickBorderDashOffset:f}))}return this._ticksLength=c,this._borderValue=b,u}_computeLabelItems(t){const e=this.axis,i=this.options,{position:o,ticks:a}=i,r=this.isHorizontal(),l=this.ticks,{align:h,crossAlign:c,padding:d,mirror:u}=a,f=Ws(i.grid),g=f+d,p=u?-d:g,m=-H(this.labelRotation),b=[];let x,_,y,v,w,M,k,S,P,D,O,C,A="middle";if("top"===o)M=this.bottom-p,k=this._getXAxisLabelAlignment();else if("bottom"===o)M=this.top+p,k=this._getXAxisLabelAlignment();else if("left"===o){const t=this._getYAxisLabelAlignment(f);k=t.textAlign,w=t.x}else if("right"===o){const t=this._getYAxisLabelAlignment(f);k=t.textAlign,w=t.x}else if("x"===e){if("center"===o)M=(t.top+t.bottom)/2+g;else if(n(o)){const t=Object.keys(o)[0],e=o[t];M=this.chart.scales[t].getPixelForValue(e)+g}k=this._getXAxisLabelAlignment()}else if("y"===e){if("center"===o)w=(t.left+t.right)/2-g;else if(n(o)){const t=Object.keys(o)[0],e=o[t];w=this.chart.scales[t].getPixelForValue(e)}k=this._getYAxisLabelAlignment(f).textAlign}"y"===e&&("start"===h?A="top":"end"===h&&(A="bottom"));const T=this._getLabelSizes();for(x=0,_=l.length;x<_;++x){y=l[x],v=y.label;const t=a.setContext(this.getContext(x));S=this.getPixelForTick(x)+a.labelOffset,P=this._resolveTickFontOptions(x),D=P.lineHeight,O=s(v)?v.length:1;const e=O/2,i=t.color,n=t.textStrokeColor,h=t.textStrokeWidth;let d,f=k;if(r?(w=S,"inner"===k&&(f=x===_-1?this.options.reverse?"left":"right":0===x?this.options.reverse?"right":"left":"center"),C="top"===o?"near"===c||0!==m?-O*D+D/2:"center"===c?-T.highest.height/2-e*D+D:-T.highest.height+D/2:"near"===c||0!==m?D/2:"center"===c?T.highest.height/2-e*D:T.highest.height-O*D,u&&(C*=-1)):(M=S,C=(1-O)*D/2),t.showLabelBackdrop){const e=pi(t.backdropPadding),i=T.heights[x],s=T.widths[x];let n=M+C-e.top,o=w-e.left;switch(A){case"middle":n-=i/2;break;case"bottom":n-=i}switch(k){case"center":o-=s/2;break;case"right":o-=s}d={left:o,top:n,width:s+e.width,height:i+e.height,color:t.backdropColor}}b.push({rotation:m,label:v,font:P,color:i,strokeColor:n,strokeWidth:h,textOffset:C,textAlign:f,textBaseline:A,translation:[w,M],backdrop:d})}return b}_getXAxisLabelAlignment(){const{position:t,ticks:e}=this.options;if(-H(this.labelRotation))return"top"===t?"left":"right";let i="center";return"start"===e.align?i="left":"end"===e.align?i="right":"inner"===e.align&&(i="inner"),i}_getYAxisLabelAlignment(t){const{position:e,ticks:{crossAlign:i,mirror:s,padding:n}}=this.options,o=t+n,a=this._getLabelSizes().widest.width;let r,l;return"left"===e?s?(l=this.right+n,"near"===i?r="left":"center"===i?(r="center",l+=a/2):(r="right",l+=a)):(l=this.right-o,"near"===i?r="right":"center"===i?(r="center",l-=a/2):(r="left",l=this.left)):"right"===e?s?(l=this.left+n,"near"===i?r="right":"center"===i?(r="center",l-=a/2):(r="left",l-=a)):(l=this.left+o,"near"===i?r="left":"center"===i?(r="center",l+=a/2):(r="right",l=this.right)):r="right",{textAlign:r,x:l}}_computeLabelArea(){if(this.options.ticks.mirror)return;const t=this.chart,e=this.options.position;return"left"===e||"right"===e?{top:0,left:this.left,bottom:t.height,right:this.right}:"top"===e||"bottom"===e?{top:this.top,left:0,bottom:this.bottom,right:t.width}:void 0}drawBackground(){const{ctx:t,options:{backgroundColor:e},left:i,top:s,width:n,height:o}=this;e&&(t.save(),t.fillStyle=e,t.fillRect(i,s,n,o),t.restore())}getLineWidthForValue(t){const e=this.options.grid;if(!this._isVisible()||!e.display)return 0;const i=this.ticks.findIndex((e=>e.value===t));if(i>=0){return e.setContext(this.getContext(i)).lineWidth}return 0}drawGrid(t){const e=this.options.grid,i=this.ctx,s=this._gridLineItems||(this._gridLineItems=this._computeGridLineItems(t));let n,o;const a=(t,e,s)=>{s.width&&s.color&&(i.save(),i.lineWidth=s.width,i.strokeStyle=s.color,i.setLineDash(s.borderDash||[]),i.lineDashOffset=s.borderDashOffset,i.beginPath(),i.moveTo(t.x,t.y),i.lineTo(e.x,e.y),i.stroke(),i.restore())};if(e.display)for(n=0,o=s.length;n<o;++n){const t=s[n];e.drawOnChartArea&&a({x:t.x1,y:t.y1},{x:t.x2,y:t.y2},t),e.drawTicks&&a({x:t.tx1,y:t.ty1},{x:t.tx2,y:t.ty2},{color:t.tickColor,width:t.tickWidth,borderDash:t.tickBorderDash,borderDashOffset:t.tickBorderDashOffset})}}drawBorder(){const{chart:t,ctx:e,options:{grid:i}}=this,s=i.setContext(this.getContext()),n=i.drawBorder?s.borderWidth:0;if(!n)return;const o=i.setContext(this.getContext(0)).lineWidth,a=this._borderValue;let r,l,h,c;this.isHorizontal()?(r=ve(t,this.left,n)-n/2,l=ve(t,this.right,o)+o/2,h=c=a):(h=ve(t,this.top,n)-n/2,c=ve(t,this.bottom,o)+o/2,r=l=a),e.save(),e.lineWidth=s.borderWidth,e.strokeStyle=s.borderColor,e.beginPath(),e.moveTo(r,h),e.lineTo(l,c),e.stroke(),e.restore()}drawLabels(t){if(!this.options.ticks.display)return;const e=this.ctx,i=this._computeLabelArea();i&&Pe(e,i);const s=this._labelItems||(this._labelItems=this._computeLabelItems(t));let n,o;for(n=0,o=s.length;n<o;++n){const t=s[n],i=t.font,o=t.label;t.backdrop&&(e.fillStyle=t.backdrop.color,e.fillRect(t.backdrop.left,t.backdrop.top,t.backdrop.width,t.backdrop.height)),Ae(e,o,0,t.textOffset,i,t)}i&&De(e)}drawTitle(){const{ctx:t,options:{position:e,title:i,reverse:o}}=this;if(!i.display)return;const a=mi(i.font),r=pi(i.padding),l=i.align;let h=a.lineHeight/2;"bottom"===e||"center"===e||n(e)?(h+=r.bottom,s(i.text)&&(h+=a.lineHeight*(i.text.length-1))):h+=r.top;const{titleX:c,titleY:d,maxWidth:u,rotation:f}=function(t,e,i,s){const{top:o,left:a,bottom:r,right:l,chart:h}=t,{chartArea:c,scales:d}=h;let u,f,g,p=0;const m=r-o,b=l-a;if(t.isHorizontal()){if(f=ut(s,a,l),n(i)){const t=Object.keys(i)[0],s=i[t];g=d[t].getPixelForValue(s)+m-e}else g="center"===i?(c.bottom+c.top)/2+m-e:Vs(t,i,e);u=l-a}else{if(n(i)){const t=Object.keys(i)[0],s=i[t];f=d[t].getPixelForValue(s)-b+e}else f="center"===i?(c.left+c.right)/2-b+e:Vs(t,i,e);g=ut(s,r,o),p="left"===i?-L:L}return{titleX:f,titleY:g,maxWidth:u,rotation:p}}(this,h,e,l);Ae(t,i.text,0,0,a,{color:i.color,maxWidth:u,rotation:f,textAlign:Hs(l,e,o),textBaseline:"middle",translation:[c,d]})}draw(t){this._isVisible()&&(this.drawBackground(),this.drawGrid(t),this.drawBorder(),this.drawTitle(),this.drawLabels(t))}_layers(){const t=this.options,e=t.ticks&&t.ticks.z||0,i=r(t.grid&&t.grid.z,-1);return this._isVisible()&&this.draw===$s.prototype.draw?[{z:i,draw:t=>{this.drawBackground(),this.drawGrid(t),this.drawTitle()}},{z:i+1,draw:()=>{this.drawBorder()}},{z:e,draw:t=>{this.drawLabels(t)}}]:[{z:e,draw:t=>{this.draw(t)}}]}getMatchingVisibleMetas(t){const e=this.chart.getSortedVisibleDatasetMetas(),i=this.axis+"AxisID",s=[];let n,o;for(n=0,o=e.length;n<o;++n){const o=e[n];o[i]!==this.id||t&&o.type!==t||s.push(o)}return s}_resolveTickFontOptions(t){return mi(this.options.ticks.setContext(this.getContext(t)).font)}_maxDigits(){const t=this._resolveTickFontOptions(0).lineHeight;return(this.isHorizontal()?this.width:this.height)/t}}class Ys{constructor(t,e,i){this.type=t,this.scope=e,this.override=i,this.items=Object.create(null)}isForType(t){return Object.prototype.isPrototypeOf.call(this.type.prototype,t.prototype)}register(t){const e=Object.getPrototypeOf(t);let i;(function(t){return"id"in t&&"defaults"in t})(e)&&(i=this.register(e));const s=this.items,n=t.id,o=this.scope+"."+n;if(!n)throw new Error("class does not have id: "+t);return n in s||(s[n]=t,function(t,e,i){const s=m(Object.create(null),[i?ne.get(i):{},ne.get(e),t.defaults]);ne.set(e,s),t.defaultRoutes&&function(t,e){Object.keys(e).forEach((i=>{const s=i.split("."),n=s.pop(),o=[t].concat(s).join("."),a=e[i].split("."),r=a.pop(),l=a.join(".");ne.route(o,n,l,r)}))}(e,t.defaultRoutes);t.descriptors&&ne.describe(e,t.descriptors)}(t,o,i),this.override&&ne.override(t.id,t.overrides)),o}get(t){return this.items[t]}unregister(t){const e=this.items,i=t.id,s=this.scope;i in e&&delete e[i],s&&i in ne[s]&&(delete ne[s][i],this.override&&delete te[i])}}var Us=new class{constructor(){this.controllers=new Ys(Ls,"datasets",!0),this.elements=new Ys(Es,"elements"),this.plugins=new Ys(Object,"plugins"),this.scales=new Ys($s,"scales"),this._typedRegistries=[this.controllers,this.scales,this.elements]}add(...t){this._each("register",t)}remove(...t){this._each("unregister",t)}addControllers(...t){this._each("register",t,this.controllers)}addElements(...t){this._each("register",t,this.elements)}addPlugins(...t){this._each("register",t,this.plugins)}addScales(...t){this._each("register",t,this.scales)}getController(t){return this._get(t,this.controllers,"controller")}getElement(t){return this._get(t,this.elements,"element")}getPlugin(t){return this._get(t,this.plugins,"plugin")}getScale(t){return this._get(t,this.scales,"scale")}removeControllers(...t){this._each("unregister",t,this.controllers)}removeElements(...t){this._each("unregister",t,this.elements)}removePlugins(...t){this._each("unregister",t,this.plugins)}removeScales(...t){this._each("unregister",t,this.scales)}_each(t,e,i){[...e].forEach((e=>{const s=i||this._getRegistryForType(e);i||s.isForType(e)||s===this.plugins&&e.id?this._exec(t,s,e):d(e,(e=>{const s=i||this._getRegistryForType(e);this._exec(t,s,e)}))}))}_exec(t,e,i){const s=w(t);c(i["before"+s],[],i),e[t](i),c(i["after"+s],[],i)}_getRegistryForType(t){for(let e=0;e<this._typedRegistries.length;e++){const i=this._typedRegistries[e];if(i.isForType(t))return i}return this.plugins}_get(t,e,i){const s=e.get(t);if(void 0===s)throw new Error('"'+t+'" is not a registered '+i+".");return s}};class Xs{constructor(){this._init=[]}notify(t,e,i,s){"beforeInit"===e&&(this._init=this._createDescriptors(t,!0),this._notify(this._init,t,"install"));const n=s?this._descriptors(t).filter(s):this._descriptors(t),o=this._notify(n,t,e,i);return"afterDestroy"===e&&(this._notify(n,t,"stop"),this._notify(this._init,t,"uninstall")),o}_notify(t,e,i,s){s=s||{};for(const n of t){const t=n.plugin;if(!1===c(t[i],[e,s,n.options],t)&&s.cancelable)return!1}return!0}invalidate(){i(this._cache)||(this._oldCache=this._cache,this._cache=void 0)}_descriptors(t){if(this._cache)return this._cache;const e=this._cache=this._createDescriptors(t);return this._notifyStateChanges(t),e}_createDescriptors(t,e){const i=t&&t.config,s=r(i.options&&i.options.plugins,{}),n=function(t){const e={},i=[],s=Object.keys(Us.plugins.items);for(let t=0;t<s.length;t++)i.push(Us.getPlugin(s[t]));const n=t.plugins||[];for(let t=0;t<n.length;t++){const s=n[t];-1===i.indexOf(s)&&(i.push(s),e[s.id]=!0)}return{plugins:i,localIds:e}}(i);return!1!==s||e?function(t,{plugins:e,localIds:i},s,n){const o=[],a=t.getContext();for(const r of e){const e=r.id,l=qs(s[e],n);null!==l&&o.push({plugin:r,options:Ks(t.config,{plugin:r,local:i[e]},l,a)})}return o}(t,n,s,e):[]}_notifyStateChanges(t){const e=this._oldCache||[],i=this._cache,s=(t,e)=>t.filter((t=>!e.some((e=>t.plugin.id===e.plugin.id))));this._notify(s(e,i),t,"stop"),this._notify(s(i,e),t,"start")}}function qs(t,e){return e||!1!==t?!0===t?{}:t:null}function Ks(t,{plugin:e,local:i},s,n){const o=t.pluginScopeKeys(e),a=t.getOptionScopes(s,o);return i&&e.defaults&&a.push(e.defaults),t.createResolver(a,n,[""],{scriptable:!1,indexable:!1,allKeys:!0})}function Gs(t,e){const i=ne.datasets[t]||{};return((e.datasets||{})[t]||{}).indexAxis||e.indexAxis||i.indexAxis||"x"}function Zs(t,e){return"x"===t||"y"===t?t:e.axis||("top"===(i=e.position)||"bottom"===i?"x":"left"===i||"right"===i?"y":void 0)||t.charAt(0).toLowerCase();var i}function Js(t){const e=t.options||(t.options={});e.plugins=r(e.plugins,{}),e.scales=function(t,e){const i=te[t.type]||{scales:{}},s=e.scales||{},o=Gs(t.type,e),a=Object.create(null),r=Object.create(null);return Object.keys(s).forEach((t=>{const e=s[t];if(!n(e))return console.error(`Invalid scale configuration for scale: ${t}`);if(e._proxy)return console.warn(`Ignoring resolver passed as options for scale: ${t}`);const l=Zs(t,e),h=function(t,e){return t===e?"_index_":"_value_"}(l,o),c=i.scales||{};a[l]=a[l]||t,r[t]=b(Object.create(null),[{axis:l},e,c[l],c[h]])})),t.data.datasets.forEach((i=>{const n=i.type||t.type,o=i.indexAxis||Gs(n,e),l=(te[n]||{}).scales||{};Object.keys(l).forEach((t=>{const e=function(t,e){let i=t;return"_index_"===t?i=e:"_value_"===t&&(i="x"===e?"y":"x"),i}(t,o),n=i[e+"AxisID"]||a[e]||e;r[n]=r[n]||Object.create(null),b(r[n],[{axis:e},s[n],l[t]])}))})),Object.keys(r).forEach((t=>{const e=r[t];b(e,[ne.scales[e.type],ne.scale])})),r}(t,e)}function Qs(t){return(t=t||{}).datasets=t.datasets||[],t.labels=t.labels||[],t}const tn=new Map,en=new Set;function sn(t,e){let i=tn.get(t);return i||(i=e(),tn.set(t,i),en.add(i)),i}const nn=(t,e,i)=>{const s=y(e,i);void 0!==s&&t.add(s)};class on{constructor(t){this._config=function(t){return(t=t||{}).data=Qs(t.data),Js(t),t}(t),this._scopeCache=new Map,this._resolverCache=new Map}get platform(){return this._config.platform}get type(){return this._config.type}set type(t){this._config.type=t}get data(){return this._config.data}set data(t){this._config.data=Qs(t)}get options(){return this._config.options}set options(t){this._config.options=t}get plugins(){return this._config.plugins}update(){const t=this._config;this.clearCache(),Js(t)}clearCache(){this._scopeCache.clear(),this._resolverCache.clear()}datasetScopeKeys(t){return sn(t,(()=>[[`datasets.${t}`,""]]))}datasetAnimationScopeKeys(t,e){return sn(`${t}.transition.${e}`,(()=>[[`datasets.${t}.transitions.${e}`,`transitions.${e}`],[`datasets.${t}`,""]]))}datasetElementScopeKeys(t,e){return sn(`${t}-${e}`,(()=>[[`datasets.${t}.elements.${e}`,`datasets.${t}`,`elements.${e}`,""]]))}pluginScopeKeys(t){const e=t.id;return sn(`${this.type}-plugin-${e}`,(()=>[[`plugins.${e}`,...t.additionalOptionScopes||[]]]))}_cachedScopes(t,e){const i=this._scopeCache;let s=i.get(t);return s&&!e||(s=new Map,i.set(t,s)),s}getOptionScopes(t,e,i){const{options:s,type:n}=this,o=this._cachedScopes(t,i),a=o.get(e);if(a)return a;const r=new Set;e.forEach((e=>{t&&(r.add(t),e.forEach((e=>nn(r,t,e)))),e.forEach((t=>nn(r,s,t))),e.forEach((t=>nn(r,te[n]||{},t))),e.forEach((t=>nn(r,ne,t))),e.forEach((t=>nn(r,ee,t)))}));const l=Array.from(r);return 0===l.length&&l.push(Object.create(null)),en.has(e)&&o.set(e,l),l}chartOptionScopes(){const{options:t,type:e}=this;return[t,te[e]||{},ne.datasets[e]||{},{type:e},ne,ee]}resolveNamedOptions(t,e,i,n=[""]){const o={$shared:!0},{resolver:a,subPrefixes:r}=an(this._resolverCache,t,n);let l=a;if(function(t,e){const{isScriptable:i,isIndexable:n}=Ie(t);for(const o of e){const e=i(o),a=n(o),r=(a||e)&&t[o];if(e&&(k(r)||rn(r))||a&&s(r))return!0}return!1}(a,e)){o.$shared=!1;l=Re(a,i=k(i)?i():i,this.createResolver(t,i,r))}for(const t of e)o[t]=l[t];return o}createResolver(t,e,i=[""],s){const{resolver:o}=an(this._resolverCache,t,i);return n(e)?Re(o,e,void 0,s):o}}function an(t,e,i){let s=t.get(e);s||(s=new Map,t.set(e,s));const n=i.join();let o=s.get(n);if(!o){o={resolver:Ee(e,i),subPrefixes:i.filter((t=>!t.toLowerCase().includes("hover")))},s.set(n,o)}return o}const rn=t=>n(t)&&Object.getOwnPropertyNames(t).reduce(((e,i)=>e||k(t[i])),!1);const ln=["top","bottom","left","right","chartArea"];function hn(t,e){return"top"===t||"bottom"===t||-1===ln.indexOf(t)&&"x"===e}function cn(t,e){return function(i,s){return i[t]===s[t]?i[e]-s[e]:i[t]-s[t]}}function dn(t){const e=t.chart,i=e.options.animation;e.notifyPlugins("afterRender"),c(i&&i.onComplete,[t],e)}function un(t){const e=t.chart,i=e.options.animation;c(i&&i.onProgress,[t],e)}function fn(t){return oe()&&"string"==typeof t?t=document.getElementById(t):t&&t.length&&(t=t[0]),t&&t.canvas&&(t=t.canvas),t}const gn={},pn=t=>{const e=fn(t);return Object.values(gn).filter((t=>t.canvas===e)).pop()};function mn(t,e,i){const s=Object.keys(t);for(const n of s){const s=+n;if(s>=e){const o=t[n];delete t[n],(i>0||s>e)&&(t[s+i]=o)}}}class bn{constructor(t,i){const s=this.config=new on(i),n=fn(t),o=pn(n);if(o)throw new Error("Canvas is already in use. Chart with ID '"+o.id+"' must be destroyed before the canvas with ID '"+o.canvas.id+"' can be reused.");const a=s.createResolver(s.chartOptionScopes(),this.getContext());this.platform=new(s.platform||gs(n)),this.platform.updateConfig(s);const r=this.platform.acquireContext(n,a.aspectRatio),l=r&&r.canvas,h=l&&l.height,c=l&&l.width;this.id=e(),this.ctx=r,this.canvas=l,this.width=c,this.height=h,this._options=a,this._aspectRatio=this.aspectRatio,this._layers=[],this._metasets=[],this._stacks=void 0,this.boxes=[],this.currentDevicePixelRatio=void 0,this.chartArea=void 0,this._active=[],this._lastEvent=void 0,this._listeners={},this._responsiveListeners=void 0,this._sortedMetasets=[],this.scales={},this._plugins=new Xs,this.$proxies={},this._hiddenIndices={},this.attached=!1,this._animationsDisabled=void 0,this.$context=void 0,this._doResize=ct((t=>this.update(t)),a.resizeDelay||0),this._dataChanges=[],gn[this.id]=this,r&&l?(mt.listen(this,"complete",dn),mt.listen(this,"progress",un),this._initialize(),this.attached&&this.update()):console.error("Failed to create chart: can't acquire context from the given item")}get aspectRatio(){const{options:{aspectRatio:t,maintainAspectRatio:e},width:s,height:n,_aspectRatio:o}=this;return i(t)?e&&o?o:n?s/n:null:t}get data(){return this.config.data}set data(t){this.config.data=t}get options(){return this._options}set options(t){this.config.options=t}_initialize(){return this.notifyPlugins("beforeInit"),this.options.responsive?this.resize():pe(this,this.options.devicePixelRatio),this.bindEvents(),this.notifyPlugins("afterInit"),this}clear(){return we(this.canvas,this.ctx),this}stop(){return mt.stop(this),this}resize(t,e){mt.running(this)?this._resizeBeforeDraw={width:t,height:e}:this._resize(t,e)}_resize(t,e){const i=this.options,s=this.canvas,n=i.maintainAspectRatio&&this.aspectRatio,o=this.platform.getMaximumSize(s,t,e,n),a=i.devicePixelRatio||this.platform.getDevicePixelRatio(),r=this.width?"resize":"attach";this.width=o.width,this.height=o.height,this._aspectRatio=this.aspectRatio,pe(this,a,!0)&&(this.notifyPlugins("resize",{size:o}),c(i.onResize,[this,o],this),this.attached&&this._doResize(r)&&this.render())}ensureScalesHaveIDs(){d(this.options.scales||{},((t,e)=>{t.id=e}))}buildOrUpdateScales(){const t=this.options,e=t.scales,i=this.scales,s=Object.keys(i).reduce(((t,e)=>(t[e]=!1,t)),{});let n=[];e&&(n=n.concat(Object.keys(e).map((t=>{const i=e[t],s=Zs(t,i),n="r"===s,o="x"===s;return{options:i,dposition:n?"chartArea":o?"bottom":"left",dtype:n?"radialLinear":o?"category":"linear"}})))),d(n,(e=>{const n=e.options,o=n.id,a=Zs(o,n),l=r(n.type,e.dtype);void 0!==n.position&&hn(n.position,a)===hn(e.dposition)||(n.position=e.dposition),s[o]=!0;let h=null;if(o in i&&i[o].type===l)h=i[o];else{h=new(Us.getScale(l))({id:o,type:l,ctx:this.ctx,chart:this}),i[h.id]=h}h.init(n,t)})),d(s,((t,e)=>{t||delete i[e]})),d(i,(t=>{Zi.configure(this,t,t.options),Zi.addBox(this,t)}))}_updateMetasets(){const t=this._metasets,e=this.data.datasets.length,i=t.length;if(t.sort(((t,e)=>t.index-e.index)),i>e){for(let t=e;t<i;++t)this._destroyDatasetMeta(t);t.splice(e,i-e)}this._sortedMetasets=t.slice(0).sort(cn("order","index"))}_removeUnreferencedMetasets(){const{_metasets:t,data:{datasets:e}}=this;t.length>e.length&&delete this._stacks,t.forEach(((t,i)=>{0===e.filter((e=>e===t._dataset)).length&&this._destroyDatasetMeta(i)}))}buildOrUpdateControllers(){const t=[],e=this.data.datasets;let i,s;for(this._removeUnreferencedMetasets(),i=0,s=e.length;i<s;i++){const s=e[i];let n=this.getDatasetMeta(i);const o=s.type||this.config.type;if(n.type&&n.type!==o&&(this._destroyDatasetMeta(i),n=this.getDatasetMeta(i)),n.type=o,n.indexAxis=s.indexAxis||Gs(o,this.options),n.order=s.order||0,n.index=i,n.label=""+s.label,n.visible=this.isDatasetVisible(i),n.controller)n.controller.updateIndex(i),n.controller.linkScales();else{const e=Us.getController(o),{datasetElementType:s,dataElementType:a}=ne.datasets[o];Object.assign(e.prototype,{dataElementType:Us.getElement(a),datasetElementType:s&&Us.getElement(s)}),n.controller=new e(this,i),t.push(n.controller)}}return this._updateMetasets(),t}_resetElements(){d(this.data.datasets,((t,e)=>{this.getDatasetMeta(e).controller.reset()}),this)}reset(){this._resetElements(),this.notifyPlugins("reset")}update(t){const e=this.config;e.update();const i=this._options=e.createResolver(e.chartOptionScopes(),this.getContext()),s=this._animationsDisabled=!i.animation;if(this._updateScales(),this._checkEventBindings(),this._updateHiddenIndices(),this._plugins.invalidate(),!1===this.notifyPlugins("beforeUpdate",{mode:t,cancelable:!0}))return;const n=this.buildOrUpdateControllers();this.notifyPlugins("beforeElementsUpdate");let o=0;for(let t=0,e=this.data.datasets.length;t<e;t++){const{controller:e}=this.getDatasetMeta(t),i=!s&&-1===n.indexOf(e);e.buildOrUpdateElements(i),o=Math.max(+e.getMaxOverflow(),o)}o=this._minPadding=i.layout.autoPadding?o:0,this._updateLayout(o),s||d(n,(t=>{t.reset()})),this._updateDatasets(t),this.notifyPlugins("afterUpdate",{mode:t}),this._layers.sort(cn("z","_idx"));const{_active:a,_lastEvent:r}=this;r?this._eventHandler(r,!0):a.length&&this._updateHoverStyles(a,a,!0),this.render()}_updateScales(){d(this.scales,(t=>{Zi.removeBox(this,t)})),this.ensureScalesHaveIDs(),this.buildOrUpdateScales()}_checkEventBindings(){const t=this.options,e=new Set(Object.keys(this._listeners)),i=new Set(t.events);S(e,i)&&!!this._responsiveListeners===t.responsive||(this.unbindEvents(),this.bindEvents())}_updateHiddenIndices(){const{_hiddenIndices:t}=this,e=this._getUniformDataChanges()||[];for(const{method:i,start:s,count:n}of e){mn(t,s,"_removeElements"===i?-n:n)}}_getUniformDataChanges(){const t=this._dataChanges;if(!t||!t.length)return;this._dataChanges=[];const e=this.data.datasets.length,i=e=>new Set(t.filter((t=>t[0]===e)).map(((t,e)=>e+","+t.splice(1).join(",")))),s=i(0);for(let t=1;t<e;t++)if(!S(s,i(t)))return;return Array.from(s).map((t=>t.split(","))).map((t=>({method:t[1],start:+t[2],count:+t[3]})))}_updateLayout(t){if(!1===this.notifyPlugins("beforeLayout",{cancelable:!0}))return;Zi.update(this,this.width,this.height,t);const e=this.chartArea,i=e.width<=0||e.height<=0;this._layers=[],d(this.boxes,(t=>{i&&"chartArea"===t.position||(t.configure&&t.configure(),this._layers.push(...t._layers()))}),this),this._layers.forEach(((t,e)=>{t._idx=e})),this.notifyPlugins("afterLayout")}_updateDatasets(t){if(!1!==this.notifyPlugins("beforeDatasetsUpdate",{mode:t,cancelable:!0})){for(let t=0,e=this.data.datasets.length;t<e;++t)this.getDatasetMeta(t).controller.configure();for(let e=0,i=this.data.datasets.length;e<i;++e)this._updateDataset(e,k(t)?t({datasetIndex:e}):t);this.notifyPlugins("afterDatasetsUpdate",{mode:t})}}_updateDataset(t,e){const i=this.getDatasetMeta(t),s={meta:i,index:t,mode:e,cancelable:!0};!1!==this.notifyPlugins("beforeDatasetUpdate",s)&&(i.controller._update(e),s.cancelable=!1,this.notifyPlugins("afterDatasetUpdate",s))}render(){!1!==this.notifyPlugins("beforeRender",{cancelable:!0})&&(mt.has(this)?this.attached&&!mt.running(this)&&mt.start(this):(this.draw(),dn({chart:this})))}draw(){let t;if(this._resizeBeforeDraw){const{width:t,height:e}=this._resizeBeforeDraw;this._resize(t,e),this._resizeBeforeDraw=null}if(this.clear(),this.width<=0||this.height<=0)return;if(!1===this.notifyPlugins("beforeDraw",{cancelable:!0}))return;const e=this._layers;for(t=0;t<e.length&&e[t].z<=0;++t)e[t].draw(this.chartArea);for(this._drawDatasets();t<e.length;++t)e[t].draw(this.chartArea);this.notifyPlugins("afterDraw")}_getSortedDatasetMetas(t){const e=this._sortedMetasets,i=[];let s,n;for(s=0,n=e.length;s<n;++s){const n=e[s];t&&!n.visible||i.push(n)}return i}getSortedVisibleDatasetMetas(){return this._getSortedDatasetMetas(!0)}_drawDatasets(){if(!1===this.notifyPlugins("beforeDatasetsDraw",{cancelable:!0}))return;const t=this.getSortedVisibleDatasetMetas();for(let e=t.length-1;e>=0;--e)this._drawDataset(t[e]);this.notifyPlugins("afterDatasetsDraw")}_drawDataset(t){const e=this.ctx,i=t._clip,s=!i.disabled,n=this.chartArea,o={meta:t,index:t.index,cancelable:!0};!1!==this.notifyPlugins("beforeDatasetDraw",o)&&(s&&Pe(e,{left:!1===i.left?0:n.left-i.left,right:!1===i.right?this.width:n.right+i.right,top:!1===i.top?0:n.top-i.top,bottom:!1===i.bottom?this.height:n.bottom+i.bottom}),t.controller.draw(),s&&De(e),o.cancelable=!1,this.notifyPlugins("afterDatasetDraw",o))}isPointInArea(t){return Se(t,this.chartArea,this._minPadding)}getElementsAtEventForMode(t,e,i,s){const n=Vi.modes[e];return"function"==typeof n?n(this,t,i,s):[]}getDatasetMeta(t){const e=this.data.datasets[t],i=this._metasets;let s=i.filter((t=>t&&t._dataset===e)).pop();return s||(s={type:null,data:[],dataset:null,controller:null,hidden:null,xAxisID:null,yAxisID:null,order:e&&e.order||0,index:t,_dataset:e,_parsed:[],_sorted:!1},i.push(s)),s}getContext(){return this.$context||(this.$context=_i(null,{chart:this,type:"chart"}))}getVisibleDatasetCount(){return this.getSortedVisibleDatasetMetas().length}isDatasetVisible(t){const e=this.data.datasets[t];if(!e)return!1;const i=this.getDatasetMeta(t);return"boolean"==typeof i.hidden?!i.hidden:!e.hidden}setDatasetVisibility(t,e){this.getDatasetMeta(t).hidden=!e}toggleDataVisibility(t){this._hiddenIndices[t]=!this._hiddenIndices[t]}getDataVisibility(t){return!this._hiddenIndices[t]}_updateVisibility(t,e,i){const s=i?"show":"hide",n=this.getDatasetMeta(t),o=n.controller._resolveAnimations(void 0,s);M(e)?(n.data[e].hidden=!i,this.update()):(this.setDatasetVisibility(t,i),o.update(n,{visible:i}),this.update((e=>e.datasetIndex===t?s:void 0)))}hide(t,e){this._updateVisibility(t,e,!1)}show(t,e){this._updateVisibility(t,e,!0)}_destroyDatasetMeta(t){const e=this._metasets[t];e&&e.controller&&e.controller._destroy(),delete this._metasets[t]}_stop(){let t,e;for(this.stop(),mt.remove(this),t=0,e=this.data.datasets.length;t<e;++t)this._destroyDatasetMeta(t)}destroy(){this.notifyPlugins("beforeDestroy");const{canvas:t,ctx:e}=this;this._stop(),this.config.clearCache(),t&&(this.unbindEvents(),we(t,e),this.platform.releaseContext(e),this.canvas=null,this.ctx=null),this.notifyPlugins("destroy"),delete gn[this.id],this.notifyPlugins("afterDestroy")}toBase64Image(...t){return this.canvas.toDataURL(...t)}bindEvents(){this.bindUserEvents(),this.options.responsive?this.bindResponsiveEvents():this.attached=!0}bindUserEvents(){const t=this._listeners,e=this.platform,i=(i,s)=>{e.addEventListener(this,i,s),t[i]=s},s=(t,e,i)=>{t.offsetX=e,t.offsetY=i,this._eventHandler(t)};d(this.options.events,(t=>i(t,s)))}bindResponsiveEvents(){this._responsiveListeners||(this._responsiveListeners={});const t=this._responsiveListeners,e=this.platform,i=(i,s)=>{e.addEventListener(this,i,s),t[i]=s},s=(i,s)=>{t[i]&&(e.removeEventListener(this,i,s),delete t[i])},n=(t,e)=>{this.canvas&&this.resize(t,e)};let o;const a=()=>{s("attach",a),this.attached=!0,this.resize(),i("resize",n),i("detach",o)};o=()=>{this.attached=!1,s("resize",n),this._stop(),this._resize(0,0),i("attach",a)},e.isAttached(this.canvas)?a():o()}unbindEvents(){d(this._listeners,((t,e)=>{this.platform.removeEventListener(this,e,t)})),this._listeners={},d(this._responsiveListeners,((t,e)=>{this.platform.removeEventListener(this,e,t)})),this._responsiveListeners=void 0}updateHoverStyle(t,e,i){const s=i?"set":"remove";let n,o,a,r;for("dataset"===e&&(n=this.getDatasetMeta(t[0].datasetIndex),n.controller["_"+s+"DatasetHoverStyle"]()),a=0,r=t.length;a<r;++a){o=t[a];const e=o&&this.getDatasetMeta(o.datasetIndex).controller;e&&e[s+"HoverStyle"](o.element,o.datasetIndex,o.index)}}getActiveElements(){return this._active||[]}setActiveElements(t){const e=this._active||[],i=t.map((({datasetIndex:t,index:e})=>{const i=this.getDatasetMeta(t);if(!i)throw new Error("No dataset found at index "+t);return{datasetIndex:t,element:i.data[e],index:e}}));!u(i,e)&&(this._active=i,this._lastEvent=null,this._updateHoverStyles(i,e))}notifyPlugins(t,e,i){return this._plugins.notify(this,t,e,i)}_updateHoverStyles(t,e,i){const s=this.options.hover,n=(t,e)=>t.filter((t=>!e.some((e=>t.datasetIndex===e.datasetIndex&&t.index===e.index)))),o=n(e,t),a=i?t:n(t,e);o.length&&this.updateHoverStyle(o,s.mode,!1),a.length&&s.mode&&this.updateHoverStyle(a,s.mode,!0)}_eventHandler(t,e){const i={event:t,replay:e,cancelable:!0,inChartArea:this.isPointInArea(t)},s=e=>(e.options.events||this.options.events).includes(t.native.type);if(!1===this.notifyPlugins("beforeEvent",i,s))return;const n=this._handleEvent(t,e,i.inChartArea);return i.cancelable=!1,this.notifyPlugins("afterEvent",i,s),(n||i.changed)&&this.render(),this}_handleEvent(t,e,i){const{_active:s=[],options:n}=this,o=e,a=this._getActiveElements(t,s,i,o),r=P(t),l=function(t,e,i,s){return i&&"mouseout"!==t.type?s?e:t:null}(t,this._lastEvent,i,r);i&&(this._lastEvent=null,c(n.onHover,[t,a,this],this),r&&c(n.onClick,[t,a,this],this));const h=!u(a,s);return(h||e)&&(this._active=a,this._updateHoverStyles(a,s,e)),this._lastEvent=l,h}_getActiveElements(t,e,i,s){if("mouseout"===t.type)return[];if(!i)return e;const n=this.options.hover;return this.getElementsAtEventForMode(t,n.mode,n,s)}}const xn=()=>d(bn.instances,(t=>t._plugins.invalidate())),_n=!0;function yn(){throw new Error("This method is not implemented: Check that a complete date adapter is provided.")}Object.defineProperties(bn,{defaults:{enumerable:_n,value:ne},instances:{enumerable:_n,value:gn},overrides:{enumerable:_n,value:te},registry:{enumerable:_n,value:Us},version:{enumerable:_n,value:"3.9.1"},getChart:{enumerable:_n,value:pn},register:{enumerable:_n,value:(...t)=>{Us.add(...t),xn()}},unregister:{enumerable:_n,value:(...t)=>{Us.remove(...t),xn()}}});class vn{constructor(t){this.options=t||{}}init(t){}formats(){return yn()}parse(t,e){return yn()}format(t,e){return yn()}add(t,e,i){return yn()}diff(t,e,i){return yn()}startOf(t,e,i){return yn()}endOf(t,e){return yn()}}vn.override=function(t){Object.assign(vn.prototype,t)};var wn={_date:vn};function Mn(t){const e=t.iScale,i=function(t,e){if(!t._cache.$bar){const i=t.getMatchingVisibleMetas(e);let s=[];for(let e=0,n=i.length;e<n;e++)s=s.concat(i[e].controller.getAllParsedValues(t));t._cache.$bar=rt(s.sort(((t,e)=>t-e)))}return t._cache.$bar}(e,t.type);let s,n,o,a,r=e._length;const l=()=>{32767!==o&&-32768!==o&&(M(a)&&(r=Math.min(r,Math.abs(o-a)||r)),a=o)};for(s=0,n=i.length;s<n;++s)o=e.getPixelForValue(i[s]),l();for(a=void 0,s=0,n=e.ticks.length;s<n;++s)o=e.getPixelForTick(s),l();return r}function kn(t,e,i,n){return s(t)?function(t,e,i,s){const n=i.parse(t[0],s),o=i.parse(t[1],s),a=Math.min(n,o),r=Math.max(n,o);let l=a,h=r;Math.abs(a)>Math.abs(r)&&(l=r,h=a),e[i.axis]=h,e._custom={barStart:l,barEnd:h,start:n,end:o,min:a,max:r}}(t,e,i,n):e[i.axis]=i.parse(t,n),e}function Sn(t,e,i,s){const n=t.iScale,o=t.vScale,a=n.getLabels(),r=n===o,l=[];let h,c,d,u;for(h=i,c=i+s;h<c;++h)u=e[h],d={},d[n.axis]=r||n.parse(a[h],h),l.push(kn(u,d,o,h));return l}function Pn(t){return t&&void 0!==t.barStart&&void 0!==t.barEnd}function Dn(t,e,i,s){let n=e.borderSkipped;const o={};if(!n)return void(t.borderSkipped=o);if(!0===n)return void(t.borderSkipped={top:!0,right:!0,bottom:!0,left:!0});const{start:a,end:r,reverse:l,top:h,bottom:c}=function(t){let e,i,s,n,o;return t.horizontal?(e=t.base>t.x,i="left",s="right"):(e=t.base<t.y,i="bottom",s="top"),e?(n="end",o="start"):(n="start",o="end"),{start:i,end:s,reverse:e,top:n,bottom:o}}(t);"middle"===n&&i&&(t.enableBorderRadius=!0,(i._top||0)===s?n=h:(i._bottom||0)===s?n=c:(o[On(c,a,r,l)]=!0,n=h)),o[On(n,a,r,l)]=!0,t.borderSkipped=o}function On(t,e,i,s){var n,o,a;return s?(a=i,t=Cn(t=(n=t)===(o=e)?a:n===a?o:n,i,e)):t=Cn(t,e,i),t}function Cn(t,e,i){return"start"===t?e:"end"===t?i:t}function An(t,{inflateAmount:e},i){t.inflateAmount="auto"===e?1===i?.33:0:e}class Tn extends Ls{parsePrimitiveData(t,e,i,s){return Sn(t,e,i,s)}parseArrayData(t,e,i,s){return Sn(t,e,i,s)}parseObjectData(t,e,i,s){const{iScale:n,vScale:o}=t,{xAxisKey:a="x",yAxisKey:r="y"}=this._parsing,l="x"===n.axis?a:r,h="x"===o.axis?a:r,c=[];let d,u,f,g;for(d=i,u=i+s;d<u;++d)g=e[d],f={},f[n.axis]=n.parse(y(g,l),d),c.push(kn(y(g,h),f,o,d));return c}updateRangeFromParsed(t,e,i,s){super.updateRangeFromParsed(t,e,i,s);const n=i._custom;n&&e===this._cachedMeta.vScale&&(t.min=Math.min(t.min,n.min),t.max=Math.max(t.max,n.max))}getMaxOverflow(){return 0}getLabelAndValue(t){const e=this._cachedMeta,{iScale:i,vScale:s}=e,n=this.getParsed(t),o=n._custom,a=Pn(o)?"["+o.start+", "+o.end+"]":""+s.getLabelForValue(n[s.axis]);return{label:""+i.getLabelForValue(n[i.axis]),value:a}}initialize(){this.enableOptionSharing=!0,super.initialize();this._cachedMeta.stack=this.getDataset().stack}update(t){const e=this._cachedMeta;this.updateElements(e.data,0,e.data.length,t)}updateElements(t,e,s,n){const o="reset"===n,{index:a,_cachedMeta:{vScale:r}}=this,l=r.getBasePixel(),h=r.isHorizontal(),c=this._getRuler(),{sharedOptions:d,includeOptions:u}=this._getSharedOptions(e,n);for(let f=e;f<e+s;f++){const e=this.getParsed(f),s=o||i(e[r.axis])?{base:l,head:l}:this._calculateBarValuePixels(f),g=this._calculateBarIndexPixels(f,c),p=(e._stacks||{})[r.axis],m={horizontal:h,base:s.base,enableBorderRadius:!p||Pn(e._custom)||a===p._top||a===p._bottom,x:h?s.head:g.center,y:h?g.center:s.head,height:h?g.size:Math.abs(s.size),width:h?Math.abs(s.size):g.size};u&&(m.options=d||this.resolveDataElementOptions(f,t[f].active?"active":n));const b=m.options||t[f].options;Dn(m,b,p,a),An(m,b,c.ratio),this.updateElement(t[f],f,m,n)}}_getStacks(t,e){const{iScale:s}=this._cachedMeta,n=s.getMatchingVisibleMetas(this._type).filter((t=>t.controller.options.grouped)),o=s.options.stacked,a=[],r=t=>{const s=t.controller.getParsed(e),n=s&&s[t.vScale.axis];if(i(n)||isNaN(n))return!0};for(const i of n)if((void 0===e||!r(i))&&((!1===o||-1===a.indexOf(i.stack)||void 0===o&&void 0===i.stack)&&a.push(i.stack),i.index===t))break;return a.length||a.push(void 0),a}_getStackCount(t){return this._getStacks(void 0,t).length}_getStackIndex(t,e,i){const s=this._getStacks(t,i),n=void 0!==e?s.indexOf(e):-1;return-1===n?s.length-1:n}_getRuler(){const t=this.options,e=this._cachedMeta,i=e.iScale,s=[];let n,o;for(n=0,o=e.data.length;n<o;++n)s.push(i.getPixelForValue(this.getParsed(n)[i.axis],n));const a=t.barThickness;return{min:a||Mn(e),pixels:s,start:i._startPixel,end:i._endPixel,stackCount:this._getStackCount(),scale:i,grouped:t.grouped,ratio:a?1:t.categoryPercentage*t.barPercentage}}_calculateBarValuePixels(t){const{_cachedMeta:{vScale:e,_stacked:s},options:{base:n,minBarLength:o}}=this,a=n||0,r=this.getParsed(t),l=r._custom,h=Pn(l);let c,d,u=r[e.axis],f=0,g=s?this.applyStack(e,r,s):u;g!==u&&(f=g-u,g=u),h&&(u=l.barStart,g=l.barEnd-l.barStart,0!==u&&z(u)!==z(l.barEnd)&&(f=0),f+=u);const p=i(n)||h?f:n;let m=e.getPixelForValue(p);if(c=this.chart.getDataVisibility(t)?e.getPixelForValue(f+g):m,d=c-m,Math.abs(d)<o){d=function(t,e,i){return 0!==t?z(t):(e.isHorizontal()?1:-1)*(e.min>=i?1:-1)}(d,e,a)*o,u===a&&(m-=d/2);const t=e.getPixelForDecimal(0),i=e.getPixelForDecimal(1),s=Math.min(t,i),n=Math.max(t,i);m=Math.max(Math.min(m,n),s),c=m+d}if(m===e.getPixelForValue(a)){const t=z(d)*e.getLineWidthForValue(a)/2;m+=t,d-=t}return{size:d,base:m,head:c,center:c+d/2}}_calculateBarIndexPixels(t,e){const s=e.scale,n=this.options,o=n.skipNull,a=r(n.maxBarThickness,1/0);let l,h;if(e.grouped){const s=o?this._getStackCount(t):e.stackCount,r="flex"===n.barThickness?function(t,e,i,s){const n=e.pixels,o=n[t];let a=t>0?n[t-1]:null,r=t<n.length-1?n[t+1]:null;const l=i.categoryPercentage;null===a&&(a=o-(null===r?e.end-e.start:r-o)),null===r&&(r=o+o-a);const h=o-(o-Math.min(a,r))/2*l;return{chunk:Math.abs(r-a)/2*l/s,ratio:i.barPercentage,start:h}}(t,e,n,s):function(t,e,s,n){const o=s.barThickness;let a,r;return i(o)?(a=e.min*s.categoryPercentage,r=s.barPercentage):(a=o*n,r=1),{chunk:a/n,ratio:r,start:e.pixels[t]-a/2}}(t,e,n,s),c=this._getStackIndex(this.index,this._cachedMeta.stack,o?t:void 0);l=r.start+r.chunk*c+r.chunk/2,h=Math.min(a,r.chunk*r.ratio)}else l=s.getPixelForValue(this.getParsed(t)[s.axis],t),h=Math.min(a,e.min*e.ratio);return{base:l-h/2,head:l+h/2,center:l,size:h}}draw(){const t=this._cachedMeta,e=t.vScale,i=t.data,s=i.length;let n=0;for(;n<s;++n)null!==this.getParsed(n)[e.axis]&&i[n].draw(this._ctx)}}Tn.id="bar",Tn.defaults={datasetElementType:!1,dataElementType:"bar",categoryPercentage:.8,barPercentage:.9,grouped:!0,animations:{numbers:{type:"number",properties:["x","y","base","width","height"]}}},Tn.overrides={scales:{_index_:{type:"category",offset:!0,grid:{offset:!0}},_value_:{type:"linear",beginAtZero:!0}}};class Ln extends Ls{initialize(){this.enableOptionSharing=!0,super.initialize()}parsePrimitiveData(t,e,i,s){const n=super.parsePrimitiveData(t,e,i,s);for(let t=0;t<n.length;t++)n[t]._custom=this.resolveDataElementOptions(t+i).radius;return n}parseArrayData(t,e,i,s){const n=super.parseArrayData(t,e,i,s);for(let t=0;t<n.length;t++){const s=e[i+t];n[t]._custom=r(s[2],this.resolveDataElementOptions(t+i).radius)}return n}parseObjectData(t,e,i,s){const n=super.parseObjectData(t,e,i,s);for(let t=0;t<n.length;t++){const s=e[i+t];n[t]._custom=r(s&&s.r&&+s.r,this.resolveDataElementOptions(t+i).radius)}return n}getMaxOverflow(){const t=this._cachedMeta.data;let e=0;for(let i=t.length-1;i>=0;--i)e=Math.max(e,t[i].size(this.resolveDataElementOptions(i))/2);return e>0&&e}getLabelAndValue(t){const e=this._cachedMeta,{xScale:i,yScale:s}=e,n=this.getParsed(t),o=i.getLabelForValue(n.x),a=s.getLabelForValue(n.y),r=n._custom;return{label:e.label,value:"("+o+", "+a+(r?", "+r:"")+")"}}update(t){const e=this._cachedMeta.data;this.updateElements(e,0,e.length,t)}updateElements(t,e,i,s){const n="reset"===s,{iScale:o,vScale:a}=this._cachedMeta,{sharedOptions:r,includeOptions:l}=this._getSharedOptions(e,s),h=o.axis,c=a.axis;for(let d=e;d<e+i;d++){const e=t[d],i=!n&&this.getParsed(d),u={},f=u[h]=n?o.getPixelForDecimal(.5):o.getPixelForValue(i[h]),g=u[c]=n?a.getBasePixel():a.getPixelForValue(i[c]);u.skip=isNaN(f)||isNaN(g),l&&(u.options=r||this.resolveDataElementOptions(d,e.active?"active":s),n&&(u.options.radius=0)),this.updateElement(e,d,u,s)}}resolveDataElementOptions(t,e){const i=this.getParsed(t);let s=super.resolveDataElementOptions(t,e);s.$shared&&(s=Object.assign({},s,{$shared:!1}));const n=s.radius;return"active"!==e&&(s.radius=0),s.radius+=r(i&&i._custom,n),s}}Ln.id="bubble",Ln.defaults={datasetElementType:!1,dataElementType:"point",animations:{numbers:{type:"number",properties:["x","y","borderWidth","radius"]}}},Ln.overrides={scales:{x:{type:"linear"},y:{type:"linear"}},plugins:{tooltip:{callbacks:{title:()=>""}}}};class En extends Ls{constructor(t,e){super(t,e),this.enableOptionSharing=!0,this.innerRadius=void 0,this.outerRadius=void 0,this.offsetX=void 0,this.offsetY=void 0}linkScales(){}parse(t,e){const i=this.getDataset().data,s=this._cachedMeta;if(!1===this._parsing)s._parsed=i;else{let o,a,r=t=>+i[t];if(n(i[t])){const{key:t="value"}=this._parsing;r=e=>+y(i[e],t)}for(o=t,a=t+e;o<a;++o)s._parsed[o]=r(o)}}_getRotation(){return H(this.options.rotation-90)}_getCircumference(){return H(this.options.circumference)}_getRotationExtents(){let t=O,e=-O;for(let i=0;i<this.chart.data.datasets.length;++i)if(this.chart.isDatasetVisible(i)){const s=this.chart.getDatasetMeta(i).controller,n=s._getRotation(),o=s._getCircumference();t=Math.min(t,n),e=Math.max(e,n+o)}return{rotation:t,circumference:e-t}}update(t){const e=this.chart,{chartArea:i}=e,s=this._cachedMeta,n=s.data,o=this.getMaxBorderWidth()+this.getMaxOffset(n)+this.options.spacing,a=Math.max((Math.min(i.width,i.height)-o)/2,0),r=Math.min(l(this.options.cutout,a),1),c=this._getRingWeight(this.index),{circumference:d,rotation:u}=this._getRotationExtents(),{ratioX:f,ratioY:g,offsetX:p,offsetY:m}=function(t,e,i){let s=1,n=1,o=0,a=0;if(e<O){const r=t,l=r+e,h=Math.cos(r),c=Math.sin(r),d=Math.cos(l),u=Math.sin(l),f=(t,e,s)=>G(t,r,l,!0)?1:Math.max(e,e*i,s,s*i),g=(t,e,s)=>G(t,r,l,!0)?-1:Math.min(e,e*i,s,s*i),p=f(0,h,d),m=f(L,c,u),b=g(D,h,d),x=g(D+L,c,u);s=(p-b)/2,n=(m-x)/2,o=-(p+b)/2,a=-(m+x)/2}return{ratioX:s,ratioY:n,offsetX:o,offsetY:a}}(u,d,r),b=(i.width-o)/f,x=(i.height-o)/g,_=Math.max(Math.min(b,x)/2,0),y=h(this.options.radius,_),v=(y-Math.max(y*r,0))/this._getVisibleDatasetWeightTotal();this.offsetX=p*y,this.offsetY=m*y,s.total=this.calculateTotal(),this.outerRadius=y-v*this._getRingWeightOffset(this.index),this.innerRadius=Math.max(this.outerRadius-v*c,0),this.updateElements(n,0,n.length,t)}_circumference(t,e){const i=this.options,s=this._cachedMeta,n=this._getCircumference();return e&&i.animation.animateRotate||!this.chart.getDataVisibility(t)||null===s._parsed[t]||s.data[t].hidden?0:this.calculateCircumference(s._parsed[t]*n/O)}updateElements(t,e,i,s){const n="reset"===s,o=this.chart,a=o.chartArea,r=o.options.animation,l=(a.left+a.right)/2,h=(a.top+a.bottom)/2,c=n&&r.animateScale,d=c?0:this.innerRadius,u=c?0:this.outerRadius,{sharedOptions:f,includeOptions:g}=this._getSharedOptions(e,s);let p,m=this._getRotation();for(p=0;p<e;++p)m+=this._circumference(p,n);for(p=e;p<e+i;++p){const e=this._circumference(p,n),i=t[p],o={x:l+this.offsetX,y:h+this.offsetY,startAngle:m,endAngle:m+e,circumference:e,outerRadius:u,innerRadius:d};g&&(o.options=f||this.resolveDataElementOptions(p,i.active?"active":s)),m+=e,this.updateElement(i,p,o,s)}}calculateTotal(){const t=this._cachedMeta,e=t.data;let i,s=0;for(i=0;i<e.length;i++){const n=t._parsed[i];null===n||isNaN(n)||!this.chart.getDataVisibility(i)||e[i].hidden||(s+=Math.abs(n))}return s}calculateCircumference(t){const e=this._cachedMeta.total;return e>0&&!isNaN(t)?O*(Math.abs(t)/e):0}getLabelAndValue(t){const e=this._cachedMeta,i=this.chart,s=i.data.labels||[],n=li(e._parsed[t],i.options.locale);return{label:s[t]||"",value:n}}getMaxBorderWidth(t){let e=0;const i=this.chart;let s,n,o,a,r;if(!t)for(s=0,n=i.data.datasets.length;s<n;++s)if(i.isDatasetVisible(s)){o=i.getDatasetMeta(s),t=o.data,a=o.controller;break}if(!t)return 0;for(s=0,n=t.length;s<n;++s)r=a.resolveDataElementOptions(s),"inner"!==r.borderAlign&&(e=Math.max(e,r.borderWidth||0,r.hoverBorderWidth||0));return e}getMaxOffset(t){let e=0;for(let i=0,s=t.length;i<s;++i){const t=this.resolveDataElementOptions(i);e=Math.max(e,t.offset||0,t.hoverOffset||0)}return e}_getRingWeightOffset(t){let e=0;for(let i=0;i<t;++i)this.chart.isDatasetVisible(i)&&(e+=this._getRingWeight(i));return e}_getRingWeight(t){return Math.max(r(this.chart.data.datasets[t].weight,1),0)}_getVisibleDatasetWeightTotal(){return this._getRingWeightOffset(this.chart.data.datasets.length)||1}}En.id="doughnut",En.defaults={datasetElementType:!1,dataElementType:"arc",animation:{animateRotate:!0,animateScale:!1},animations:{numbers:{type:"number",properties:["circumference","endAngle","innerRadius","outerRadius","startAngle","x","y","offset","borderWidth","spacing"]}},cutout:"50%",rotation:0,circumference:360,radius:"100%",spacing:0,indexAxis:"r"},En.descriptors={_scriptable:t=>"spacing"!==t,_indexable:t=>"spacing"!==t},En.overrides={aspectRatio:1,plugins:{legend:{labels:{generateLabels(t){const e=t.data;if(e.labels.length&&e.datasets.length){const{labels:{pointStyle:i}}=t.legend.options;return e.labels.map(((e,s)=>{const n=t.getDatasetMeta(0).controller.getStyle(s);return{text:e,fillStyle:n.backgroundColor,strokeStyle:n.borderColor,lineWidth:n.borderWidth,pointStyle:i,hidden:!t.getDataVisibility(s),index:s}}))}return[]}},onClick(t,e,i){i.chart.toggleDataVisibility(e.index),i.chart.update()}},tooltip:{callbacks:{title:()=>"",label(t){let e=t.label;const i=": "+t.formattedValue;return s(e)?(e=e.slice(),e[0]+=i):e+=i,e}}}}};class Rn extends Ls{initialize(){this.enableOptionSharing=!0,this.supportsDecimation=!0,super.initialize()}update(t){const e=this._cachedMeta,{dataset:i,data:s=[],_dataset:n}=e,o=this.chart._animationsDisabled;let{start:a,count:r}=gt(e,s,o);this._drawStart=a,this._drawCount=r,pt(e)&&(a=0,r=s.length),i._chart=this.chart,i._datasetIndex=this.index,i._decimated=!!n._decimated,i.points=s;const l=this.resolveDatasetElementOptions(t);this.options.showLine||(l.borderWidth=0),l.segment=this.options.segment,this.updateElement(i,void 0,{animated:!o,options:l},t),this.updateElements(s,a,r,t)}updateElements(t,e,s,n){const o="reset"===n,{iScale:a,vScale:r,_stacked:l,_dataset:h}=this._cachedMeta,{sharedOptions:c,includeOptions:d}=this._getSharedOptions(e,n),u=a.axis,f=r.axis,{spanGaps:g,segment:p}=this.options,m=B(g)?g:Number.POSITIVE_INFINITY,b=this.chart._animationsDisabled||o||"none"===n;let x=e>0&&this.getParsed(e-1);for(let g=e;g<e+s;++g){const e=t[g],s=this.getParsed(g),_=b?e:{},y=i(s[f]),v=_[u]=a.getPixelForValue(s[u],g),w=_[f]=o||y?r.getBasePixel():r.getPixelForValue(l?this.applyStack(r,s,l):s[f],g);_.skip=isNaN(v)||isNaN(w)||y,_.stop=g>0&&Math.abs(s[u]-x[u])>m,p&&(_.parsed=s,_.raw=h.data[g]),d&&(_.options=c||this.resolveDataElementOptions(g,e.active?"active":n)),b||this.updateElement(e,g,_,n),x=s}}getMaxOverflow(){const t=this._cachedMeta,e=t.dataset,i=e.options&&e.options.borderWidth||0,s=t.data||[];if(!s.length)return i;const n=s[0].size(this.resolveDataElementOptions(0)),o=s[s.length-1].size(this.resolveDataElementOptions(s.length-1));return Math.max(i,n,o)/2}draw(){const t=this._cachedMeta;t.dataset.updateControlPoints(this.chart.chartArea,t.iScale.axis),super.draw()}}Rn.id="line",Rn.defaults={datasetElementType:"line",dataElementType:"point",showLine:!0,spanGaps:!1},Rn.overrides={scales:{_index_:{type:"category"},_value_:{type:"linear"}}};class In extends Ls{constructor(t,e){super(t,e),this.innerRadius=void 0,this.outerRadius=void 0}getLabelAndValue(t){const e=this._cachedMeta,i=this.chart,s=i.data.labels||[],n=li(e._parsed[t].r,i.options.locale);return{label:s[t]||"",value:n}}parseObjectData(t,e,i,s){return Ue.bind(this)(t,e,i,s)}update(t){const e=this._cachedMeta.data;this._updateRadius(),this.updateElements(e,0,e.length,t)}getMinMax(){const t=this._cachedMeta,e={min:Number.POSITIVE_INFINITY,max:Number.NEGATIVE_INFINITY};return t.data.forEach(((t,i)=>{const s=this.getParsed(i).r;!isNaN(s)&&this.chart.getDataVisibility(i)&&(s<e.min&&(e.min=s),s>e.max&&(e.max=s))})),e}_updateRadius(){const t=this.chart,e=t.chartArea,i=t.options,s=Math.min(e.right-e.left,e.bottom-e.top),n=Math.max(s/2,0),o=(n-Math.max(i.cutoutPercentage?n/100*i.cutoutPercentage:1,0))/t.getVisibleDatasetCount();this.outerRadius=n-o*this.index,this.innerRadius=this.outerRadius-o}updateElements(t,e,i,s){const n="reset"===s,o=this.chart,a=o.options.animation,r=this._cachedMeta.rScale,l=r.xCenter,h=r.yCenter,c=r.getIndexAngle(0)-.5*D;let d,u=c;const f=360/this.countVisibleElements();for(d=0;d<e;++d)u+=this._computeAngle(d,s,f);for(d=e;d<e+i;d++){const e=t[d];let i=u,g=u+this._computeAngle(d,s,f),p=o.getDataVisibility(d)?r.getDistanceFromCenterForValue(this.getParsed(d).r):0;u=g,n&&(a.animateScale&&(p=0),a.animateRotate&&(i=g=c));const m={x:l,y:h,innerRadius:0,outerRadius:p,startAngle:i,endAngle:g,options:this.resolveDataElementOptions(d,e.active?"active":s)};this.updateElement(e,d,m,s)}}countVisibleElements(){const t=this._cachedMeta;let e=0;return t.data.forEach(((t,i)=>{!isNaN(this.getParsed(i).r)&&this.chart.getDataVisibility(i)&&e++})),e}_computeAngle(t,e,i){return this.chart.getDataVisibility(t)?H(this.resolveDataElementOptions(t,e).angle||i):0}}In.id="polarArea",In.defaults={dataElementType:"arc",animation:{animateRotate:!0,animateScale:!0},animations:{numbers:{type:"number",properties:["x","y","startAngle","endAngle","innerRadius","outerRadius"]}},indexAxis:"r",startAngle:0},In.overrides={aspectRatio:1,plugins:{legend:{labels:{generateLabels(t){const e=t.data;if(e.labels.length&&e.datasets.length){const{labels:{pointStyle:i}}=t.legend.options;return e.labels.map(((e,s)=>{const n=t.getDatasetMeta(0).controller.getStyle(s);return{text:e,fillStyle:n.backgroundColor,strokeStyle:n.borderColor,lineWidth:n.borderWidth,pointStyle:i,hidden:!t.getDataVisibility(s),index:s}}))}return[]}},onClick(t,e,i){i.chart.toggleDataVisibility(e.index),i.chart.update()}},tooltip:{callbacks:{title:()=>"",label:t=>t.chart.data.labels[t.dataIndex]+": "+t.formattedValue}}},scales:{r:{type:"radialLinear",angleLines:{display:!1},beginAtZero:!0,grid:{circular:!0},pointLabels:{display:!1},startAngle:0}}};class zn extends En{}zn.id="pie",zn.defaults={cutout:0,rotation:0,circumference:360,radius:"100%"};class Fn extends Ls{getLabelAndValue(t){const e=this._cachedMeta.vScale,i=this.getParsed(t);return{label:e.getLabels()[t],value:""+e.getLabelForValue(i[e.axis])}}parseObjectData(t,e,i,s){return Ue.bind(this)(t,e,i,s)}update(t){const e=this._cachedMeta,i=e.dataset,s=e.data||[],n=e.iScale.getLabels();if(i.points=s,"resize"!==t){const e=this.resolveDatasetElementOptions(t);this.options.showLine||(e.borderWidth=0);const o={_loop:!0,_fullLoop:n.length===s.length,options:e};this.updateElement(i,void 0,o,t)}this.updateElements(s,0,s.length,t)}updateElements(t,e,i,s){const n=this._cachedMeta.rScale,o="reset"===s;for(let a=e;a<e+i;a++){const e=t[a],i=this.resolveDataElementOptions(a,e.active?"active":s),r=n.getPointPositionForValue(a,this.getParsed(a).r),l=o?n.xCenter:r.x,h=o?n.yCenter:r.y,c={x:l,y:h,angle:r.angle,skip:isNaN(l)||isNaN(h),options:i};this.updateElement(e,a,c,s)}}}Fn.id="radar",Fn.defaults={datasetElementType:"line",dataElementType:"point",indexAxis:"r",showLine:!0,elements:{line:{fill:"start"}}},Fn.overrides={aspectRatio:1,scales:{r:{type:"radialLinear"}}};class Vn extends Ls{update(t){const e=this._cachedMeta,{data:i=[]}=e,s=this.chart._animationsDisabled;let{start:n,count:o}=gt(e,i,s);if(this._drawStart=n,this._drawCount=o,pt(e)&&(n=0,o=i.length),this.options.showLine){const{dataset:n,_dataset:o}=e;n._chart=this.chart,n._datasetIndex=this.index,n._decimated=!!o._decimated,n.points=i;const a=this.resolveDatasetElementOptions(t);a.segment=this.options.segment,this.updateElement(n,void 0,{animated:!s,options:a},t)}this.updateElements(i,n,o,t)}addElements(){const{showLine:t}=this.options;!this.datasetElementType&&t&&(this.datasetElementType=Us.getElement("line")),super.addElements()}updateElements(t,e,s,n){const o="reset"===n,{iScale:a,vScale:r,_stacked:l,_dataset:h}=this._cachedMeta,c=this.resolveDataElementOptions(e,n),d=this.getSharedOptions(c),u=this.includeOptions(n,d),f=a.axis,g=r.axis,{spanGaps:p,segment:m}=this.options,b=B(p)?p:Number.POSITIVE_INFINITY,x=this.chart._animationsDisabled||o||"none"===n;let _=e>0&&this.getParsed(e-1);for(let c=e;c<e+s;++c){const e=t[c],s=this.getParsed(c),p=x?e:{},y=i(s[g]),v=p[f]=a.getPixelForValue(s[f],c),w=p[g]=o||y?r.getBasePixel():r.getPixelForValue(l?this.applyStack(r,s,l):s[g],c);p.skip=isNaN(v)||isNaN(w)||y,p.stop=c>0&&Math.abs(s[f]-_[f])>b,m&&(p.parsed=s,p.raw=h.data[c]),u&&(p.options=d||this.resolveDataElementOptions(c,e.active?"active":n)),x||this.updateElement(e,c,p,n),_=s}this.updateSharedOptions(d,n,c)}getMaxOverflow(){const t=this._cachedMeta,e=t.data||[];if(!this.options.showLine){let t=0;for(let i=e.length-1;i>=0;--i)t=Math.max(t,e[i].size(this.resolveDataElementOptions(i))/2);return t>0&&t}const i=t.dataset,s=i.options&&i.options.borderWidth||0;if(!e.length)return s;const n=e[0].size(this.resolveDataElementOptions(0)),o=e[e.length-1].size(this.resolveDataElementOptions(e.length-1));return Math.max(s,n,o)/2}}Vn.id="scatter",Vn.defaults={datasetElementType:!1,dataElementType:"point",showLine:!1,fill:!1},Vn.overrides={interaction:{mode:"point"},plugins:{tooltip:{callbacks:{title:()=>"",label:t=>"("+t.label+", "+t.formattedValue+")"}}},scales:{x:{type:"linear"},y:{type:"linear"}}};var Bn=Object.freeze({__proto__:null,BarController:Tn,BubbleController:Ln,DoughnutController:En,LineController:Rn,PolarAreaController:In,PieController:zn,RadarController:Fn,ScatterController:Vn});function Nn(t,e,i){const{startAngle:s,pixelMargin:n,x:o,y:a,outerRadius:r,innerRadius:l}=e;let h=n/r;t.beginPath(),t.arc(o,a,r,s-h,i+h),l>n?(h=n/l,t.arc(o,a,l,i+h,s-h,!0)):t.arc(o,a,n,i+L,s-L),t.closePath(),t.clip()}function Wn(t,e,i,s){const n=ui(t.options.borderRadius,["outerStart","outerEnd","innerStart","innerEnd"]);const o=(i-e)/2,a=Math.min(o,s*e/2),r=t=>{const e=(i-Math.min(o,t))*s/2;return Z(t,0,Math.min(o,e))};return{outerStart:r(n.outerStart),outerEnd:r(n.outerEnd),innerStart:Z(n.innerStart,0,a),innerEnd:Z(n.innerEnd,0,a)}}function jn(t,e,i,s){return{x:i+t*Math.cos(e),y:s+t*Math.sin(e)}}function Hn(t,e,i,s,n,o){const{x:a,y:r,startAngle:l,pixelMargin:h,innerRadius:c}=e,d=Math.max(e.outerRadius+s+i-h,0),u=c>0?c+s+i+h:0;let f=0;const g=n-l;if(s){const t=((c>0?c-s:0)+(d>0?d-s:0))/2;f=(g-(0!==t?g*t/(t+s):g))/2}const p=(g-Math.max(.001,g*d-i/D)/d)/2,m=l+p+f,b=n-p-f,{outerStart:x,outerEnd:_,innerStart:y,innerEnd:v}=Wn(e,u,d,b-m),w=d-x,M=d-_,k=m+x/w,S=b-_/M,P=u+y,O=u+v,C=m+y/P,A=b-v/O;if(t.beginPath(),o){if(t.arc(a,r,d,k,S),_>0){const e=jn(M,S,a,r);t.arc(e.x,e.y,_,S,b+L)}const e=jn(O,b,a,r);if(t.lineTo(e.x,e.y),v>0){const e=jn(O,A,a,r);t.arc(e.x,e.y,v,b+L,A+Math.PI)}if(t.arc(a,r,u,b-v/u,m+y/u,!0),y>0){const e=jn(P,C,a,r);t.arc(e.x,e.y,y,C+Math.PI,m-L)}const i=jn(w,m,a,r);if(t.lineTo(i.x,i.y),x>0){const e=jn(w,k,a,r);t.arc(e.x,e.y,x,m-L,k)}}else{t.moveTo(a,r);const e=Math.cos(k)*d+a,i=Math.sin(k)*d+r;t.lineTo(e,i);const s=Math.cos(S)*d+a,n=Math.sin(S)*d+r;t.lineTo(s,n)}t.closePath()}function $n(t,e,i,s,n,o){const{options:a}=e,{borderWidth:r,borderJoinStyle:l}=a,h="inner"===a.borderAlign;r&&(h?(t.lineWidth=2*r,t.lineJoin=l||"round"):(t.lineWidth=r,t.lineJoin=l||"bevel"),e.fullCircles&&function(t,e,i){const{x:s,y:n,startAngle:o,pixelMargin:a,fullCircles:r}=e,l=Math.max(e.outerRadius-a,0),h=e.innerRadius+a;let c;for(i&&Nn(t,e,o+O),t.beginPath(),t.arc(s,n,h,o+O,o,!0),c=0;c<r;++c)t.stroke();for(t.beginPath(),t.arc(s,n,l,o,o+O),c=0;c<r;++c)t.stroke()}(t,e,h),h&&Nn(t,e,n),Hn(t,e,i,s,n,o),t.stroke())}class Yn extends Es{constructor(t){super(),this.options=void 0,this.circumference=void 0,this.startAngle=void 0,this.endAngle=void 0,this.innerRadius=void 0,this.outerRadius=void 0,this.pixelMargin=0,this.fullCircles=0,t&&Object.assign(this,t)}inRange(t,e,i){const s=this.getProps(["x","y"],i),{angle:n,distance:o}=U(s,{x:t,y:e}),{startAngle:a,endAngle:l,innerRadius:h,outerRadius:c,circumference:d}=this.getProps(["startAngle","endAngle","innerRadius","outerRadius","circumference"],i),u=this.options.spacing/2,f=r(d,l-a)>=O||G(n,a,l),g=Q(o,h+u,c+u);return f&&g}getCenterPoint(t){const{x:e,y:i,startAngle:s,endAngle:n,innerRadius:o,outerRadius:a}=this.getProps(["x","y","startAngle","endAngle","innerRadius","outerRadius","circumference"],t),{offset:r,spacing:l}=this.options,h=(s+n)/2,c=(o+a+l+r)/2;return{x:e+Math.cos(h)*c,y:i+Math.sin(h)*c}}tooltipPosition(t){return this.getCenterPoint(t)}draw(t){const{options:e,circumference:i}=this,s=(e.offset||0)/2,n=(e.spacing||0)/2,o=e.circular;if(this.pixelMargin="inner"===e.borderAlign?.33:0,this.fullCircles=i>O?Math.floor(i/O):0,0===i||this.innerRadius<0||this.outerRadius<0)return;t.save();let a=0;if(s){a=s/2;const e=(this.startAngle+this.endAngle)/2;t.translate(Math.cos(e)*a,Math.sin(e)*a),this.circumference>=D&&(a=s)}t.fillStyle=e.backgroundColor,t.strokeStyle=e.borderColor;const r=function(t,e,i,s,n){const{fullCircles:o,startAngle:a,circumference:r}=e;let l=e.endAngle;if(o){Hn(t,e,i,s,a+O,n);for(let e=0;e<o;++e)t.fill();isNaN(r)||(l=a+r%O,r%O==0&&(l+=O))}return Hn(t,e,i,s,l,n),t.fill(),l}(t,this,a,n,o);$n(t,this,a,n,r,o),t.restore()}}function Un(t,e,i=e){t.lineCap=r(i.borderCapStyle,e.borderCapStyle),t.setLineDash(r(i.borderDash,e.borderDash)),t.lineDashOffset=r(i.borderDashOffset,e.borderDashOffset),t.lineJoin=r(i.borderJoinStyle,e.borderJoinStyle),t.lineWidth=r(i.borderWidth,e.borderWidth),t.strokeStyle=r(i.borderColor,e.borderColor)}function Xn(t,e,i){t.lineTo(i.x,i.y)}function qn(t,e,i={}){const s=t.length,{start:n=0,end:o=s-1}=i,{start:a,end:r}=e,l=Math.max(n,a),h=Math.min(o,r),c=n<a&&o<a||n>r&&o>r;return{count:s,start:l,loop:e.loop,ilen:h<l&&!c?s+h-l:h-l}}function Kn(t,e,i,s){const{points:n,options:o}=e,{count:a,start:r,loop:l,ilen:h}=qn(n,i,s),c=function(t){return t.stepped?Oe:t.tension||"monotone"===t.cubicInterpolationMode?Ce:Xn}(o);let d,u,f,{move:g=!0,reverse:p}=s||{};for(d=0;d<=h;++d)u=n[(r+(p?h-d:d))%a],u.skip||(g?(t.moveTo(u.x,u.y),g=!1):c(t,f,u,p,o.stepped),f=u);return l&&(u=n[(r+(p?h:0))%a],c(t,f,u,p,o.stepped)),!!l}function Gn(t,e,i,s){const n=e.points,{count:o,start:a,ilen:r}=qn(n,i,s),{move:l=!0,reverse:h}=s||{};let c,d,u,f,g,p,m=0,b=0;const x=t=>(a+(h?r-t:t))%o,_=()=>{f!==g&&(t.lineTo(m,g),t.lineTo(m,f),t.lineTo(m,p))};for(l&&(d=n[x(0)],t.moveTo(d.x,d.y)),c=0;c<=r;++c){if(d=n[x(c)],d.skip)continue;const e=d.x,i=d.y,s=0|e;s===u?(i<f?f=i:i>g&&(g=i),m=(b*m+e)/++b):(_(),t.lineTo(e,i),u=s,b=0,f=g=i),p=i}_()}function Zn(t){const e=t.options,i=e.borderDash&&e.borderDash.length;return!(t._decimated||t._loop||e.tension||"monotone"===e.cubicInterpolationMode||e.stepped||i)?Gn:Kn}Yn.id="arc",Yn.defaults={borderAlign:"center",borderColor:"#fff",borderJoinStyle:void 0,borderRadius:0,borderWidth:2,offset:0,spacing:0,angle:void 0,circular:!0},Yn.defaultRoutes={backgroundColor:"backgroundColor"};const Jn="function"==typeof Path2D;function Qn(t,e,i,s){Jn&&!e.options.segment?function(t,e,i,s){let n=e._path;n||(n=e._path=new Path2D,e.path(n,i,s)&&n.closePath()),Un(t,e.options),t.stroke(n)}(t,e,i,s):function(t,e,i,s){const{segments:n,options:o}=e,a=Zn(e);for(const r of n)Un(t,o,r.style),t.beginPath(),a(t,e,r,{start:i,end:i+s-1})&&t.closePath(),t.stroke()}(t,e,i,s)}class to extends Es{constructor(t){super(),this.animated=!0,this.options=void 0,this._chart=void 0,this._loop=void 0,this._fullLoop=void 0,this._path=void 0,this._points=void 0,this._segments=void 0,this._decimated=!1,this._pointsUpdated=!1,this._datasetIndex=void 0,t&&Object.assign(this,t)}updateControlPoints(t,e){const i=this.options;if((i.tension||"monotone"===i.cubicInterpolationMode)&&!i.stepped&&!this._pointsUpdated){const s=i.spanGaps?this._loop:this._fullLoop;Qe(this._points,i,t,s,e),this._pointsUpdated=!0}}set points(t){this._points=t,delete this._segments,delete this._path,this._pointsUpdated=!1}get points(){return this._points}get segments(){return this._segments||(this._segments=Di(this,this.options.segment))}first(){const t=this.segments,e=this.points;return t.length&&e[t[0].start]}last(){const t=this.segments,e=this.points,i=t.length;return i&&e[t[i-1].end]}interpolate(t,e){const i=this.options,s=t[e],n=this.points,o=Pi(this,{property:e,start:s,end:s});if(!o.length)return;const a=[],r=function(t){return t.stepped?oi:t.tension||"monotone"===t.cubicInterpolationMode?ai:ni}(i);let l,h;for(l=0,h=o.length;l<h;++l){const{start:h,end:c}=o[l],d=n[h],u=n[c];if(d===u){a.push(d);continue}const f=r(d,u,Math.abs((s-d[e])/(u[e]-d[e])),i.stepped);f[e]=t[e],a.push(f)}return 1===a.length?a[0]:a}pathSegment(t,e,i){return Zn(this)(t,this,e,i)}path(t,e,i){const s=this.segments,n=Zn(this);let o=this._loop;e=e||0,i=i||this.points.length-e;for(const a of s)o&=n(t,this,a,{start:e,end:e+i-1});return!!o}draw(t,e,i,s){const n=this.options||{};(this.points||[]).length&&n.borderWidth&&(t.save(),Qn(t,this,i,s),t.restore()),this.animated&&(this._pointsUpdated=!1,this._path=void 0)}}function eo(t,e,i,s){const n=t.options,{[i]:o}=t.getProps([i],s);return Math.abs(e-o)<n.radius+n.hitRadius}to.id="line",to.defaults={borderCapStyle:"butt",borderDash:[],borderDashOffset:0,borderJoinStyle:"miter",borderWidth:3,capBezierPoints:!0,cubicInterpolationMode:"default",fill:!1,spanGaps:!1,stepped:!1,tension:0},to.defaultRoutes={backgroundColor:"backgroundColor",borderColor:"borderColor"},to.descriptors={_scriptable:!0,_indexable:t=>"borderDash"!==t&&"fill"!==t};class io extends Es{constructor(t){super(),this.options=void 0,this.parsed=void 0,this.skip=void 0,this.stop=void 0,t&&Object.assign(this,t)}inRange(t,e,i){const s=this.options,{x:n,y:o}=this.getProps(["x","y"],i);return Math.pow(t-n,2)+Math.pow(e-o,2)<Math.pow(s.hitRadius+s.radius,2)}inXRange(t,e){return eo(this,t,"x",e)}inYRange(t,e){return eo(this,t,"y",e)}getCenterPoint(t){const{x:e,y:i}=this.getProps(["x","y"],t);return{x:e,y:i}}size(t){let e=(t=t||this.options||{}).radius||0;e=Math.max(e,e&&t.hoverRadius||0);return 2*(e+(e&&t.borderWidth||0))}draw(t,e){const i=this.options;this.skip||i.radius<.1||!Se(this,e,this.size(i)/2)||(t.strokeStyle=i.borderColor,t.lineWidth=i.borderWidth,t.fillStyle=i.backgroundColor,Me(t,i,this.x,this.y))}getRange(){const t=this.options||{};return t.radius+t.hitRadius}}function so(t,e){const{x:i,y:s,base:n,width:o,height:a}=t.getProps(["x","y","base","width","height"],e);let r,l,h,c,d;return t.horizontal?(d=a/2,r=Math.min(i,n),l=Math.max(i,n),h=s-d,c=s+d):(d=o/2,r=i-d,l=i+d,h=Math.min(s,n),c=Math.max(s,n)),{left:r,top:h,right:l,bottom:c}}function no(t,e,i,s){return t?0:Z(e,i,s)}function oo(t){const e=so(t),i=e.right-e.left,s=e.bottom-e.top,o=function(t,e,i){const s=t.options.borderWidth,n=t.borderSkipped,o=fi(s);return{t:no(n.top,o.top,0,i),r:no(n.right,o.right,0,e),b:no(n.bottom,o.bottom,0,i),l:no(n.left,o.left,0,e)}}(t,i/2,s/2),a=function(t,e,i){const{enableBorderRadius:s}=t.getProps(["enableBorderRadius"]),o=t.options.borderRadius,a=gi(o),r=Math.min(e,i),l=t.borderSkipped,h=s||n(o);return{topLeft:no(!h||l.top||l.left,a.topLeft,0,r),topRight:no(!h||l.top||l.right,a.topRight,0,r),bottomLeft:no(!h||l.bottom||l.left,a.bottomLeft,0,r),bottomRight:no(!h||l.bottom||l.right,a.bottomRight,0,r)}}(t,i/2,s/2);return{outer:{x:e.left,y:e.top,w:i,h:s,radius:a},inner:{x:e.left+o.l,y:e.top+o.t,w:i-o.l-o.r,h:s-o.t-o.b,radius:{topLeft:Math.max(0,a.topLeft-Math.max(o.t,o.l)),topRight:Math.max(0,a.topRight-Math.max(o.t,o.r)),bottomLeft:Math.max(0,a.bottomLeft-Math.max(o.b,o.l)),bottomRight:Math.max(0,a.bottomRight-Math.max(o.b,o.r))}}}}function ao(t,e,i,s){const n=null===e,o=null===i,a=t&&!(n&&o)&&so(t,s);return a&&(n||Q(e,a.left,a.right))&&(o||Q(i,a.top,a.bottom))}function ro(t,e){t.rect(e.x,e.y,e.w,e.h)}function lo(t,e,i={}){const s=t.x!==i.x?-e:0,n=t.y!==i.y?-e:0,o=(t.x+t.w!==i.x+i.w?e:0)-s,a=(t.y+t.h!==i.y+i.h?e:0)-n;return{x:t.x+s,y:t.y+n,w:t.w+o,h:t.h+a,radius:t.radius}}io.id="point",io.defaults={borderWidth:1,hitRadius:1,hoverBorderWidth:1,hoverRadius:4,pointStyle:"circle",radius:3,rotation:0},io.defaultRoutes={backgroundColor:"backgroundColor",borderColor:"borderColor"};class ho extends Es{constructor(t){super(),this.options=void 0,this.horizontal=void 0,this.base=void 0,this.width=void 0,this.height=void 0,this.inflateAmount=void 0,t&&Object.assign(this,t)}draw(t){const{inflateAmount:e,options:{borderColor:i,backgroundColor:s}}=this,{inner:n,outer:o}=oo(this),a=(r=o.radius).topLeft||r.topRight||r.bottomLeft||r.bottomRight?Le:ro;var r;t.save(),o.w===n.w&&o.h===n.h||(t.beginPath(),a(t,lo(o,e,n)),t.clip(),a(t,lo(n,-e,o)),t.fillStyle=i,t.fill("evenodd")),t.beginPath(),a(t,lo(n,e)),t.fillStyle=s,t.fill(),t.restore()}inRange(t,e,i){return ao(this,t,e,i)}inXRange(t,e){return ao(this,t,null,e)}inYRange(t,e){return ao(this,null,t,e)}getCenterPoint(t){const{x:e,y:i,base:s,horizontal:n}=this.getProps(["x","y","base","horizontal"],t);return{x:n?(e+s)/2:e,y:n?i:(i+s)/2}}getRange(t){return"x"===t?this.width/2:this.height/2}}ho.id="bar",ho.defaults={borderSkipped:"start",borderWidth:0,borderRadius:0,inflateAmount:"auto",pointStyle:void 0},ho.defaultRoutes={backgroundColor:"backgroundColor",borderColor:"borderColor"};var co=Object.freeze({__proto__:null,ArcElement:Yn,LineElement:to,PointElement:io,BarElement:ho});function uo(t){if(t._decimated){const e=t._data;delete t._decimated,delete t._data,Object.defineProperty(t,"data",{value:e})}}function fo(t){t.data.datasets.forEach((t=>{uo(t)}))}var go={id:"decimation",defaults:{algorithm:"min-max",enabled:!1},beforeElementsUpdate:(t,e,s)=>{if(!s.enabled)return void fo(t);const n=t.width;t.data.datasets.forEach(((e,o)=>{const{_data:a,indexAxis:r}=e,l=t.getDatasetMeta(o),h=a||e.data;if("y"===bi([r,t.options.indexAxis]))return;if(!l.controller.supportsDecimation)return;const c=t.scales[l.xAxisID];if("linear"!==c.type&&"time"!==c.type)return;if(t.options.parsing)return;let{start:d,count:u}=function(t,e){const i=e.length;let s,n=0;const{iScale:o}=t,{min:a,max:r,minDefined:l,maxDefined:h}=o.getUserBounds();return l&&(n=Z(et(e,o.axis,a).lo,0,i-1)),s=h?Z(et(e,o.axis,r).hi+1,n,i)-n:i-n,{start:n,count:s}}(l,h);if(u<=(s.threshold||4*n))return void uo(e);let f;switch(i(a)&&(e._data=h,delete e.data,Object.defineProperty(e,"data",{configurable:!0,enumerable:!0,get:function(){return this._decimated},set:function(t){this._data=t}})),s.algorithm){case"lttb":f=function(t,e,i,s,n){const o=n.samples||s;if(o>=i)return t.slice(e,e+i);const a=[],r=(i-2)/(o-2);let l=0;const h=e+i-1;let c,d,u,f,g,p=e;for(a[l++]=t[p],c=0;c<o-2;c++){let s,n=0,o=0;const h=Math.floor((c+1)*r)+1+e,m=Math.min(Math.floor((c+2)*r)+1,i)+e,b=m-h;for(s=h;s<m;s++)n+=t[s].x,o+=t[s].y;n/=b,o/=b;const x=Math.floor(c*r)+1+e,_=Math.min(Math.floor((c+1)*r)+1,i)+e,{x:y,y:v}=t[p];for(u=f=-1,s=x;s<_;s++)f=.5*Math.abs((y-n)*(t[s].y-v)-(y-t[s].x)*(o-v)),f>u&&(u=f,d=t[s],g=s);a[l++]=d,p=g}return a[l++]=t[h],a}(h,d,u,n,s);break;case"min-max":f=function(t,e,s,n){let o,a,r,l,h,c,d,u,f,g,p=0,m=0;const b=[],x=e+s-1,_=t[e].x,y=t[x].x-_;for(o=e;o<e+s;++o){a=t[o],r=(a.x-_)/y*n,l=a.y;const e=0|r;if(e===h)l<f?(f=l,c=o):l>g&&(g=l,d=o),p=(m*p+a.x)/++m;else{const s=o-1;if(!i(c)&&!i(d)){const e=Math.min(c,d),i=Math.max(c,d);e!==u&&e!==s&&b.push({...t[e],x:p}),i!==u&&i!==s&&b.push({...t[i],x:p})}o>0&&s!==u&&b.push(t[s]),b.push(a),h=e,m=0,f=g=l,c=d=u=o}}return b}(h,d,u,n);break;default:throw new Error(`Unsupported decimation algorithm '${s.algorithm}'`)}e._decimated=f}))},destroy(t){fo(t)}};function po(t,e,i,s){if(s)return;let n=e[t],o=i[t];return"angle"===t&&(n=K(n),o=K(o)),{property:t,start:n,end:o}}function mo(t,e,i){for(;e>t;e--){const t=i[e];if(!isNaN(t.x)&&!isNaN(t.y))break}return e}function bo(t,e,i,s){return t&&e?s(t[i],e[i]):t?t[i]:e?e[i]:0}function xo(t,e){let i=[],n=!1;return s(t)?(n=!0,i=t):i=function(t,e){const{x:i=null,y:s=null}=t||{},n=e.points,o=[];return e.segments.forEach((({start:t,end:e})=>{e=mo(t,e,n);const a=n[t],r=n[e];null!==s?(o.push({x:a.x,y:s}),o.push({x:r.x,y:s})):null!==i&&(o.push({x:i,y:a.y}),o.push({x:i,y:r.y}))})),o}(t,e),i.length?new to({points:i,options:{tension:0},_loop:n,_fullLoop:n}):null}function _o(t){return t&&!1!==t.fill}function yo(t,e,i){let s=t[e].fill;const n=[e];let a;if(!i)return s;for(;!1!==s&&-1===n.indexOf(s);){if(!o(s))return s;if(a=t[s],!a)return!1;if(a.visible)return s;n.push(s),s=a.fill}return!1}function vo(t,e,i){const s=function(t){const e=t.options,i=e.fill;let s=r(i&&i.target,i);void 0===s&&(s=!!e.backgroundColor);if(!1===s||null===s)return!1;if(!0===s)return"origin";return s}(t);if(n(s))return!isNaN(s.value)&&s;let a=parseFloat(s);return o(a)&&Math.floor(a)===a?function(t,e,i,s){"-"!==t&&"+"!==t||(i=e+i);if(i===e||i<0||i>=s)return!1;return i}(s[0],e,a,i):["origin","start","end","stack","shape"].indexOf(s)>=0&&s}function wo(t,e,i){const s=[];for(let n=0;n<i.length;n++){const o=i[n],{first:a,last:r,point:l}=Mo(o,e,"x");if(!(!l||a&&r))if(a)s.unshift(l);else if(t.push(l),!r)break}t.push(...s)}function Mo(t,e,i){const s=t.interpolate(e,i);if(!s)return{};const n=s[i],o=t.segments,a=t.points;let r=!1,l=!1;for(let t=0;t<o.length;t++){const e=o[t],s=a[e.start][i],h=a[e.end][i];if(Q(n,s,h)){r=n===s,l=n===h;break}}return{first:r,last:l,point:s}}class ko{constructor(t){this.x=t.x,this.y=t.y,this.radius=t.radius}pathSegment(t,e,i){const{x:s,y:n,radius:o}=this;return e=e||{start:0,end:O},t.arc(s,n,o,e.end,e.start,!0),!i.bounds}interpolate(t){const{x:e,y:i,radius:s}=this,n=t.angle;return{x:e+Math.cos(n)*s,y:i+Math.sin(n)*s,angle:n}}}function So(t){const{chart:e,fill:i,line:s}=t;if(o(i))return function(t,e){const i=t.getDatasetMeta(e);return i&&t.isDatasetVisible(e)?i.dataset:null}(e,i);if("stack"===i)return function(t){const{scale:e,index:i,line:s}=t,n=[],o=s.segments,a=s.points,r=function(t,e){const i=[],s=t.getMatchingVisibleMetas("line");for(let t=0;t<s.length;t++){const n=s[t];if(n.index===e)break;n.hidden||i.unshift(n.dataset)}return i}(e,i);r.push(xo({x:null,y:e.bottom},s));for(let t=0;t<o.length;t++){const e=o[t];for(let t=e.start;t<=e.end;t++)wo(n,a[t],r)}return new to({points:n,options:{}})}(t);if("shape"===i)return!0;const a=function(t){if((t.scale||{}).getPointPositionForValue)return function(t){const{scale:e,fill:i}=t,s=e.options,o=e.getLabels().length,a=s.reverse?e.max:e.min,r=function(t,e,i){let s;return s="start"===t?i:"end"===t?e.options.reverse?e.min:e.max:n(t)?t.value:e.getBaseValue(),s}(i,e,a),l=[];if(s.grid.circular){const t=e.getPointPositionForValue(0,a);return new ko({x:t.x,y:t.y,radius:e.getDistanceFromCenterForValue(r)})}for(let t=0;t<o;++t)l.push(e.getPointPositionForValue(t,r));return l}(t);return function(t){const{scale:e={},fill:i}=t,s=function(t,e){let i=null;return"start"===t?i=e.bottom:"end"===t?i=e.top:n(t)?i=e.getPixelForValue(t.value):e.getBasePixel&&(i=e.getBasePixel()),i}(i,e);if(o(s)){const t=e.isHorizontal();return{x:t?s:null,y:t?null:s}}return null}(t)}(t);return a instanceof ko?a:xo(a,s)}function Po(t,e,i){const s=So(e),{line:n,scale:o,axis:a}=e,r=n.options,l=r.fill,h=r.backgroundColor,{above:c=h,below:d=h}=l||{};s&&n.points.length&&(Pe(t,i),function(t,e){const{line:i,target:s,above:n,below:o,area:a,scale:r}=e,l=i._loop?"angle":e.axis;t.save(),"x"===l&&o!==n&&(Do(t,s,a.top),Oo(t,{line:i,target:s,color:n,scale:r,property:l}),t.restore(),t.save(),Do(t,s,a.bottom));Oo(t,{line:i,target:s,color:o,scale:r,property:l}),t.restore()}(t,{line:n,target:s,above:c,below:d,area:i,scale:o,axis:a}),De(t))}function Do(t,e,i){const{segments:s,points:n}=e;let o=!0,a=!1;t.beginPath();for(const r of s){const{start:s,end:l}=r,h=n[s],c=n[mo(s,l,n)];o?(t.moveTo(h.x,h.y),o=!1):(t.lineTo(h.x,i),t.lineTo(h.x,h.y)),a=!!e.pathSegment(t,r,{move:a}),a?t.closePath():t.lineTo(c.x,i)}t.lineTo(e.first().x,i),t.closePath(),t.clip()}function Oo(t,e){const{line:i,target:s,property:n,color:o,scale:a}=e,r=function(t,e,i){const s=t.segments,n=t.points,o=e.points,a=[];for(const t of s){let{start:s,end:r}=t;r=mo(s,r,n);const l=po(i,n[s],n[r],t.loop);if(!e.segments){a.push({source:t,target:l,start:n[s],end:n[r]});continue}const h=Pi(e,l);for(const e of h){const s=po(i,o[e.start],o[e.end],e.loop),r=Si(t,n,s);for(const t of r)a.push({source:t,target:e,start:{[i]:bo(l,s,"start",Math.max)},end:{[i]:bo(l,s,"end",Math.min)}})}}return a}(i,s,n);for(const{source:e,target:l,start:h,end:c}of r){const{style:{backgroundColor:r=o}={}}=e,d=!0!==s;t.save(),t.fillStyle=r,Co(t,a,d&&po(n,h,c)),t.beginPath();const u=!!i.pathSegment(t,e);let f;if(d){u?t.closePath():Ao(t,s,c,n);const e=!!s.pathSegment(t,l,{move:u,reverse:!0});f=u&&e,f||Ao(t,s,h,n)}t.closePath(),t.fill(f?"evenodd":"nonzero"),t.restore()}}function Co(t,e,i){const{top:s,bottom:n}=e.chart.chartArea,{property:o,start:a,end:r}=i||{};"x"===o&&(t.beginPath(),t.rect(a,s,r-a,n-s),t.clip())}function Ao(t,e,i,s){const n=e.interpolate(i,s);n&&t.lineTo(n.x,n.y)}var To={id:"filler",afterDatasetsUpdate(t,e,i){const s=(t.data.datasets||[]).length,n=[];let o,a,r,l;for(a=0;a<s;++a)o=t.getDatasetMeta(a),r=o.dataset,l=null,r&&r.options&&r instanceof to&&(l={visible:t.isDatasetVisible(a),index:a,fill:vo(r,a,s),chart:t,axis:o.controller.options.indexAxis,scale:o.vScale,line:r}),o.$filler=l,n.push(l);for(a=0;a<s;++a)l=n[a],l&&!1!==l.fill&&(l.fill=yo(n,a,i.propagate))},beforeDraw(t,e,i){const s="beforeDraw"===i.drawTime,n=t.getSortedVisibleDatasetMetas(),o=t.chartArea;for(let e=n.length-1;e>=0;--e){const i=n[e].$filler;i&&(i.line.updateControlPoints(o,i.axis),s&&i.fill&&Po(t.ctx,i,o))}},beforeDatasetsDraw(t,e,i){if("beforeDatasetsDraw"!==i.drawTime)return;const s=t.getSortedVisibleDatasetMetas();for(let e=s.length-1;e>=0;--e){const i=s[e].$filler;_o(i)&&Po(t.ctx,i,t.chartArea)}},beforeDatasetDraw(t,e,i){const s=e.meta.$filler;_o(s)&&"beforeDatasetDraw"===i.drawTime&&Po(t.ctx,s,t.chartArea)},defaults:{propagate:!0,drawTime:"beforeDatasetDraw"}};const Lo=(t,e)=>{let{boxHeight:i=e,boxWidth:s=e}=t;return t.usePointStyle&&(i=Math.min(i,e),s=t.pointStyleWidth||Math.min(s,e)),{boxWidth:s,boxHeight:i,itemHeight:Math.max(e,i)}};class Eo extends Es{constructor(t){super(),this._added=!1,this.legendHitBoxes=[],this._hoveredItem=null,this.doughnutMode=!1,this.chart=t.chart,this.options=t.options,this.ctx=t.ctx,this.legendItems=void 0,this.columnSizes=void 0,this.lineWidths=void 0,this.maxHeight=void 0,this.maxWidth=void 0,this.top=void 0,this.bottom=void 0,this.left=void 0,this.right=void 0,this.height=void 0,this.width=void 0,this._margins=void 0,this.position=void 0,this.weight=void 0,this.fullSize=void 0}update(t,e,i){this.maxWidth=t,this.maxHeight=e,this._margins=i,this.setDimensions(),this.buildLabels(),this.fit()}setDimensions(){this.isHorizontal()?(this.width=this.maxWidth,this.left=this._margins.left,this.right=this.width):(this.height=this.maxHeight,this.top=this._margins.top,this.bottom=this.height)}buildLabels(){const t=this.options.labels||{};let e=c(t.generateLabels,[this.chart],this)||[];t.filter&&(e=e.filter((e=>t.filter(e,this.chart.data)))),t.sort&&(e=e.sort(((e,i)=>t.sort(e,i,this.chart.data)))),this.options.reverse&&e.reverse(),this.legendItems=e}fit(){const{options:t,ctx:e}=this;if(!t.display)return void(this.width=this.height=0);const i=t.labels,s=mi(i.font),n=s.size,o=this._computeTitleHeight(),{boxWidth:a,itemHeight:r}=Lo(i,n);let l,h;e.font=s.string,this.isHorizontal()?(l=this.maxWidth,h=this._fitRows(o,n,a,r)+10):(h=this.maxHeight,l=this._fitCols(o,n,a,r)+10),this.width=Math.min(l,t.maxWidth||this.maxWidth),this.height=Math.min(h,t.maxHeight||this.maxHeight)}_fitRows(t,e,i,s){const{ctx:n,maxWidth:o,options:{labels:{padding:a}}}=this,r=this.legendHitBoxes=[],l=this.lineWidths=[0],h=s+a;let c=t;n.textAlign="left",n.textBaseline="middle";let d=-1,u=-h;return this.legendItems.forEach(((t,f)=>{const g=i+e/2+n.measureText(t.text).width;(0===f||l[l.length-1]+g+2*a>o)&&(c+=h,l[l.length-(f>0?0:1)]=0,u+=h,d++),r[f]={left:0,top:u,row:d,width:g,height:s},l[l.length-1]+=g+a})),c}_fitCols(t,e,i,s){const{ctx:n,maxHeight:o,options:{labels:{padding:a}}}=this,r=this.legendHitBoxes=[],l=this.columnSizes=[],h=o-t;let c=a,d=0,u=0,f=0,g=0;return this.legendItems.forEach(((t,o)=>{const p=i+e/2+n.measureText(t.text).width;o>0&&u+s+2*a>h&&(c+=d+a,l.push({width:d,height:u}),f+=d+a,g++,d=u=0),r[o]={left:f,top:u,col:g,width:p,height:s},d=Math.max(d,p),u+=s+a})),c+=d,l.push({width:d,height:u}),c}adjustHitBoxes(){if(!this.options.display)return;const t=this._computeTitleHeight(),{legendHitBoxes:e,options:{align:i,labels:{padding:s},rtl:n}}=this,o=yi(n,this.left,this.width);if(this.isHorizontal()){let n=0,a=ut(i,this.left+s,this.right-this.lineWidths[n]);for(const r of e)n!==r.row&&(n=r.row,a=ut(i,this.left+s,this.right-this.lineWidths[n])),r.top+=this.top+t+s,r.left=o.leftForLtr(o.x(a),r.width),a+=r.width+s}else{let n=0,a=ut(i,this.top+t+s,this.bottom-this.columnSizes[n].height);for(const r of e)r.col!==n&&(n=r.col,a=ut(i,this.top+t+s,this.bottom-this.columnSizes[n].height)),r.top=a,r.left+=this.left+s,r.left=o.leftForLtr(o.x(r.left),r.width),a+=r.height+s}}isHorizontal(){return"top"===this.options.position||"bottom"===this.options.position}draw(){if(this.options.display){const t=this.ctx;Pe(t,this),this._draw(),De(t)}}_draw(){const{options:t,columnSizes:e,lineWidths:i,ctx:s}=this,{align:n,labels:o}=t,a=ne.color,l=yi(t.rtl,this.left,this.width),h=mi(o.font),{color:c,padding:d}=o,u=h.size,f=u/2;let g;this.drawTitle(),s.textAlign=l.textAlign("left"),s.textBaseline="middle",s.lineWidth=.5,s.font=h.string;const{boxWidth:p,boxHeight:m,itemHeight:b}=Lo(o,u),x=this.isHorizontal(),_=this._computeTitleHeight();g=x?{x:ut(n,this.left+d,this.right-i[0]),y:this.top+d+_,line:0}:{x:this.left+d,y:ut(n,this.top+_+d,this.bottom-e[0].height),line:0},vi(this.ctx,t.textDirection);const y=b+d;this.legendItems.forEach(((v,w)=>{s.strokeStyle=v.fontColor||c,s.fillStyle=v.fontColor||c;const M=s.measureText(v.text).width,k=l.textAlign(v.textAlign||(v.textAlign=o.textAlign)),S=p+f+M;let P=g.x,D=g.y;l.setWidth(this.width),x?w>0&&P+S+d>this.right&&(D=g.y+=y,g.line++,P=g.x=ut(n,this.left+d,this.right-i[g.line])):w>0&&D+y>this.bottom&&(P=g.x=P+e[g.line].width+d,g.line++,D=g.y=ut(n,this.top+_+d,this.bottom-e[g.line].height));!function(t,e,i){if(isNaN(p)||p<=0||isNaN(m)||m<0)return;s.save();const n=r(i.lineWidth,1);if(s.fillStyle=r(i.fillStyle,a),s.lineCap=r(i.lineCap,"butt"),s.lineDashOffset=r(i.lineDashOffset,0),s.lineJoin=r(i.lineJoin,"miter"),s.lineWidth=n,s.strokeStyle=r(i.strokeStyle,a),s.setLineDash(r(i.lineDash,[])),o.usePointStyle){const a={radius:m*Math.SQRT2/2,pointStyle:i.pointStyle,rotation:i.rotation,borderWidth:n},r=l.xPlus(t,p/2);ke(s,a,r,e+f,o.pointStyleWidth&&p)}else{const o=e+Math.max((u-m)/2,0),a=l.leftForLtr(t,p),r=gi(i.borderRadius);s.beginPath(),Object.values(r).some((t=>0!==t))?Le(s,{x:a,y:o,w:p,h:m,radius:r}):s.rect(a,o,p,m),s.fill(),0!==n&&s.stroke()}s.restore()}(l.x(P),D,v),P=ft(k,P+p+f,x?P+S:this.right,t.rtl),function(t,e,i){Ae(s,i.text,t,e+b/2,h,{strikethrough:i.hidden,textAlign:l.textAlign(i.textAlign)})}(l.x(P),D,v),x?g.x+=S+d:g.y+=y})),wi(this.ctx,t.textDirection)}drawTitle(){const t=this.options,e=t.title,i=mi(e.font),s=pi(e.padding);if(!e.display)return;const n=yi(t.rtl,this.left,this.width),o=this.ctx,a=e.position,r=i.size/2,l=s.top+r;let h,c=this.left,d=this.width;if(this.isHorizontal())d=Math.max(...this.lineWidths),h=this.top+l,c=ut(t.align,c,this.right-d);else{const e=this.columnSizes.reduce(((t,e)=>Math.max(t,e.height)),0);h=l+ut(t.align,this.top,this.bottom-e-t.labels.padding-this._computeTitleHeight())}const u=ut(a,c,c+d);o.textAlign=n.textAlign(dt(a)),o.textBaseline="middle",o.strokeStyle=e.color,o.fillStyle=e.color,o.font=i.string,Ae(o,e.text,u,h,i)}_computeTitleHeight(){const t=this.options.title,e=mi(t.font),i=pi(t.padding);return t.display?e.lineHeight+i.height:0}_getLegendItemAt(t,e){let i,s,n;if(Q(t,this.left,this.right)&&Q(e,this.top,this.bottom))for(n=this.legendHitBoxes,i=0;i<n.length;++i)if(s=n[i],Q(t,s.left,s.left+s.width)&&Q(e,s.top,s.top+s.height))return this.legendItems[i];return null}handleEvent(t){const e=this.options;if(!function(t,e){if(("mousemove"===t||"mouseout"===t)&&(e.onHover||e.onLeave))return!0;if(e.onClick&&("click"===t||"mouseup"===t))return!0;return!1}(t.type,e))return;const i=this._getLegendItemAt(t.x,t.y);if("mousemove"===t.type||"mouseout"===t.type){const o=this._hoveredItem,a=(n=i,null!==(s=o)&&null!==n&&s.datasetIndex===n.datasetIndex&&s.index===n.index);o&&!a&&c(e.onLeave,[t,o,this],this),this._hoveredItem=i,i&&!a&&c(e.onHover,[t,i,this],this)}else i&&c(e.onClick,[t,i,this],this);var s,n}}var Ro={id:"legend",_element:Eo,start(t,e,i){const s=t.legend=new Eo({ctx:t.ctx,options:i,chart:t});Zi.configure(t,s,i),Zi.addBox(t,s)},stop(t){Zi.removeBox(t,t.legend),delete t.legend},beforeUpdate(t,e,i){const s=t.legend;Zi.configure(t,s,i),s.options=i},afterUpdate(t){const e=t.legend;e.buildLabels(),e.adjustHitBoxes()},afterEvent(t,e){e.replay||t.legend.handleEvent(e.event)},defaults:{display:!0,position:"top",align:"center",fullSize:!0,reverse:!1,weight:1e3,onClick(t,e,i){const s=e.datasetIndex,n=i.chart;n.isDatasetVisible(s)?(n.hide(s),e.hidden=!0):(n.show(s),e.hidden=!1)},onHover:null,onLeave:null,labels:{color:t=>t.chart.options.color,boxWidth:40,padding:10,generateLabels(t){const e=t.data.datasets,{labels:{usePointStyle:i,pointStyle:s,textAlign:n,color:o}}=t.legend.options;return t._getSortedDatasetMetas().map((t=>{const a=t.controller.getStyle(i?0:void 0),r=pi(a.borderWidth);return{text:e[t.index].label,fillStyle:a.backgroundColor,fontColor:o,hidden:!t.visible,lineCap:a.borderCapStyle,lineDash:a.borderDash,lineDashOffset:a.borderDashOffset,lineJoin:a.borderJoinStyle,lineWidth:(r.width+r.height)/4,strokeStyle:a.borderColor,pointStyle:s||a.pointStyle,rotation:a.rotation,textAlign:n||a.textAlign,borderRadius:0,datasetIndex:t.index}}),this)}},title:{color:t=>t.chart.options.color,display:!1,position:"center",text:""}},descriptors:{_scriptable:t=>!t.startsWith("on"),labels:{_scriptable:t=>!["generateLabels","filter","sort"].includes(t)}}};class Io extends Es{constructor(t){super(),this.chart=t.chart,this.options=t.options,this.ctx=t.ctx,this._padding=void 0,this.top=void 0,this.bottom=void 0,this.left=void 0,this.right=void 0,this.width=void 0,this.height=void 0,this.position=void 0,this.weight=void 0,this.fullSize=void 0}update(t,e){const i=this.options;if(this.left=0,this.top=0,!i.display)return void(this.width=this.height=this.right=this.bottom=0);this.width=this.right=t,this.height=this.bottom=e;const n=s(i.text)?i.text.length:1;this._padding=pi(i.padding);const o=n*mi(i.font).lineHeight+this._padding.height;this.isHorizontal()?this.height=o:this.width=o}isHorizontal(){const t=this.options.position;return"top"===t||"bottom"===t}_drawArgs(t){const{top:e,left:i,bottom:s,right:n,options:o}=this,a=o.align;let r,l,h,c=0;return this.isHorizontal()?(l=ut(a,i,n),h=e+t,r=n-i):("left"===o.position?(l=i+t,h=ut(a,s,e),c=-.5*D):(l=n-t,h=ut(a,e,s),c=.5*D),r=s-e),{titleX:l,titleY:h,maxWidth:r,rotation:c}}draw(){const t=this.ctx,e=this.options;if(!e.display)return;const i=mi(e.font),s=i.lineHeight/2+this._padding.top,{titleX:n,titleY:o,maxWidth:a,rotation:r}=this._drawArgs(s);Ae(t,e.text,0,0,i,{color:e.color,maxWidth:a,rotation:r,textAlign:dt(e.align),textBaseline:"middle",translation:[n,o]})}}var zo={id:"title",_element:Io,start(t,e,i){!function(t,e){const i=new Io({ctx:t.ctx,options:e,chart:t});Zi.configure(t,i,e),Zi.addBox(t,i),t.titleBlock=i}(t,i)},stop(t){const e=t.titleBlock;Zi.removeBox(t,e),delete t.titleBlock},beforeUpdate(t,e,i){const s=t.titleBlock;Zi.configure(t,s,i),s.options=i},defaults:{align:"center",display:!1,font:{weight:"bold"},fullSize:!0,padding:10,position:"top",text:"",weight:2e3},defaultRoutes:{color:"color"},descriptors:{_scriptable:!0,_indexable:!1}};const Fo=new WeakMap;var Vo={id:"subtitle",start(t,e,i){const s=new Io({ctx:t.ctx,options:i,chart:t});Zi.configure(t,s,i),Zi.addBox(t,s),Fo.set(t,s)},stop(t){Zi.removeBox(t,Fo.get(t)),Fo.delete(t)},beforeUpdate(t,e,i){const s=Fo.get(t);Zi.configure(t,s,i),s.options=i},defaults:{align:"center",display:!1,font:{weight:"normal"},fullSize:!0,padding:0,position:"top",text:"",weight:1500},defaultRoutes:{color:"color"},descriptors:{_scriptable:!0,_indexable:!1}};const Bo={average(t){if(!t.length)return!1;let e,i,s=0,n=0,o=0;for(e=0,i=t.length;e<i;++e){const i=t[e].element;if(i&&i.hasValue()){const t=i.tooltipPosition();s+=t.x,n+=t.y,++o}}return{x:s/o,y:n/o}},nearest(t,e){if(!t.length)return!1;let i,s,n,o=e.x,a=e.y,r=Number.POSITIVE_INFINITY;for(i=0,s=t.length;i<s;++i){const s=t[i].element;if(s&&s.hasValue()){const t=X(e,s.getCenterPoint());t<r&&(r=t,n=s)}}if(n){const t=n.tooltipPosition();o=t.x,a=t.y}return{x:o,y:a}}};function No(t,e){return e&&(s(e)?Array.prototype.push.apply(t,e):t.push(e)),t}function Wo(t){return("string"==typeof t||t instanceof String)&&t.indexOf("\n")>-1?t.split("\n"):t}function jo(t,e){const{element:i,datasetIndex:s,index:n}=e,o=t.getDatasetMeta(s).controller,{label:a,value:r}=o.getLabelAndValue(n);return{chart:t,label:a,parsed:o.getParsed(n),raw:t.data.datasets[s].data[n],formattedValue:r,dataset:o.getDataset(),dataIndex:n,datasetIndex:s,element:i}}function Ho(t,e){const i=t.chart.ctx,{body:s,footer:n,title:o}=t,{boxWidth:a,boxHeight:r}=e,l=mi(e.bodyFont),h=mi(e.titleFont),c=mi(e.footerFont),u=o.length,f=n.length,g=s.length,p=pi(e.padding);let m=p.height,b=0,x=s.reduce(((t,e)=>t+e.before.length+e.lines.length+e.after.length),0);if(x+=t.beforeBody.length+t.afterBody.length,u&&(m+=u*h.lineHeight+(u-1)*e.titleSpacing+e.titleMarginBottom),x){m+=g*(e.displayColors?Math.max(r,l.lineHeight):l.lineHeight)+(x-g)*l.lineHeight+(x-1)*e.bodySpacing}f&&(m+=e.footerMarginTop+f*c.lineHeight+(f-1)*e.footerSpacing);let _=0;const y=function(t){b=Math.max(b,i.measureText(t).width+_)};return i.save(),i.font=h.string,d(t.title,y),i.font=l.string,d(t.beforeBody.concat(t.afterBody),y),_=e.displayColors?a+2+e.boxPadding:0,d(s,(t=>{d(t.before,y),d(t.lines,y),d(t.after,y)})),_=0,i.font=c.string,d(t.footer,y),i.restore(),b+=p.width,{width:b,height:m}}function $o(t,e,i,s){const{x:n,width:o}=i,{width:a,chartArea:{left:r,right:l}}=t;let h="center";return"center"===s?h=n<=(r+l)/2?"left":"right":n<=o/2?h="left":n>=a-o/2&&(h="right"),function(t,e,i,s){const{x:n,width:o}=s,a=i.caretSize+i.caretPadding;return"left"===t&&n+o+a>e.width||"right"===t&&n-o-a<0||void 0}(h,t,e,i)&&(h="center"),h}function Yo(t,e,i){const s=i.yAlign||e.yAlign||function(t,e){const{y:i,height:s}=e;return i<s/2?"top":i>t.height-s/2?"bottom":"center"}(t,i);return{xAlign:i.xAlign||e.xAlign||$o(t,e,i,s),yAlign:s}}function Uo(t,e,i,s){const{caretSize:n,caretPadding:o,cornerRadius:a}=t,{xAlign:r,yAlign:l}=i,h=n+o,{topLeft:c,topRight:d,bottomLeft:u,bottomRight:f}=gi(a);let g=function(t,e){let{x:i,width:s}=t;return"right"===e?i-=s:"center"===e&&(i-=s/2),i}(e,r);const p=function(t,e,i){let{y:s,height:n}=t;return"top"===e?s+=i:s-="bottom"===e?n+i:n/2,s}(e,l,h);return"center"===l?"left"===r?g+=h:"right"===r&&(g-=h):"left"===r?g-=Math.max(c,u)+n:"right"===r&&(g+=Math.max(d,f)+n),{x:Z(g,0,s.width-e.width),y:Z(p,0,s.height-e.height)}}function Xo(t,e,i){const s=pi(i.padding);return"center"===e?t.x+t.width/2:"right"===e?t.x+t.width-s.right:t.x+s.left}function qo(t){return No([],Wo(t))}function Ko(t,e){const i=e&&e.dataset&&e.dataset.tooltip&&e.dataset.tooltip.callbacks;return i?t.override(i):t}class Go extends Es{constructor(t){super(),this.opacity=0,this._active=[],this._eventPosition=void 0,this._size=void 0,this._cachedAnimations=void 0,this._tooltipItems=[],this.$animations=void 0,this.$context=void 0,this.chart=t.chart||t._chart,this._chart=this.chart,this.options=t.options,this.dataPoints=void 0,this.title=void 0,this.beforeBody=void 0,this.body=void 0,this.afterBody=void 0,this.footer=void 0,this.xAlign=void 0,this.yAlign=void 0,this.x=void 0,this.y=void 0,this.height=void 0,this.width=void 0,this.caretX=void 0,this.caretY=void 0,this.labelColors=void 0,this.labelPointStyles=void 0,this.labelTextColors=void 0}initialize(t){this.options=t,this._cachedAnimations=void 0,this.$context=void 0}_resolveAnimations(){const t=this._cachedAnimations;if(t)return t;const e=this.chart,i=this.options.setContext(this.getContext()),s=i.enabled&&e.options.animation&&i.animations,n=new ys(this.chart,s);return s._cacheable&&(this._cachedAnimations=Object.freeze(n)),n}getContext(){return this.$context||(this.$context=(t=this.chart.getContext(),e=this,i=this._tooltipItems,_i(t,{tooltip:e,tooltipItems:i,type:"tooltip"})));var t,e,i}getTitle(t,e){const{callbacks:i}=e,s=i.beforeTitle.apply(this,[t]),n=i.title.apply(this,[t]),o=i.afterTitle.apply(this,[t]);let a=[];return a=No(a,Wo(s)),a=No(a,Wo(n)),a=No(a,Wo(o)),a}getBeforeBody(t,e){return qo(e.callbacks.beforeBody.apply(this,[t]))}getBody(t,e){const{callbacks:i}=e,s=[];return d(t,(t=>{const e={before:[],lines:[],after:[]},n=Ko(i,t);No(e.before,Wo(n.beforeLabel.call(this,t))),No(e.lines,n.label.call(this,t)),No(e.after,Wo(n.afterLabel.call(this,t))),s.push(e)})),s}getAfterBody(t,e){return qo(e.callbacks.afterBody.apply(this,[t]))}getFooter(t,e){const{callbacks:i}=e,s=i.beforeFooter.apply(this,[t]),n=i.footer.apply(this,[t]),o=i.afterFooter.apply(this,[t]);let a=[];return a=No(a,Wo(s)),a=No(a,Wo(n)),a=No(a,Wo(o)),a}_createItems(t){const e=this._active,i=this.chart.data,s=[],n=[],o=[];let a,r,l=[];for(a=0,r=e.length;a<r;++a)l.push(jo(this.chart,e[a]));return t.filter&&(l=l.filter(((e,s,n)=>t.filter(e,s,n,i)))),t.itemSort&&(l=l.sort(((e,s)=>t.itemSort(e,s,i)))),d(l,(e=>{const i=Ko(t.callbacks,e);s.push(i.labelColor.call(this,e)),n.push(i.labelPointStyle.call(this,e)),o.push(i.labelTextColor.call(this,e))})),this.labelColors=s,this.labelPointStyles=n,this.labelTextColors=o,this.dataPoints=l,l}update(t,e){const i=this.options.setContext(this.getContext()),s=this._active;let n,o=[];if(s.length){const t=Bo[i.position].call(this,s,this._eventPosition);o=this._createItems(i),this.title=this.getTitle(o,i),this.beforeBody=this.getBeforeBody(o,i),this.body=this.getBody(o,i),this.afterBody=this.getAfterBody(o,i),this.footer=this.getFooter(o,i);const e=this._size=Ho(this,i),a=Object.assign({},t,e),r=Yo(this.chart,i,a),l=Uo(i,a,r,this.chart);this.xAlign=r.xAlign,this.yAlign=r.yAlign,n={opacity:1,x:l.x,y:l.y,width:e.width,height:e.height,caretX:t.x,caretY:t.y}}else 0!==this.opacity&&(n={opacity:0});this._tooltipItems=o,this.$context=void 0,n&&this._resolveAnimations().update(this,n),t&&i.external&&i.external.call(this,{chart:this.chart,tooltip:this,replay:e})}drawCaret(t,e,i,s){const n=this.getCaretPosition(t,i,s);e.lineTo(n.x1,n.y1),e.lineTo(n.x2,n.y2),e.lineTo(n.x3,n.y3)}getCaretPosition(t,e,i){const{xAlign:s,yAlign:n}=this,{caretSize:o,cornerRadius:a}=i,{topLeft:r,topRight:l,bottomLeft:h,bottomRight:c}=gi(a),{x:d,y:u}=t,{width:f,height:g}=e;let p,m,b,x,_,y;return"center"===n?(_=u+g/2,"left"===s?(p=d,m=p-o,x=_+o,y=_-o):(p=d+f,m=p+o,x=_-o,y=_+o),b=p):(m="left"===s?d+Math.max(r,h)+o:"right"===s?d+f-Math.max(l,c)-o:this.caretX,"top"===n?(x=u,_=x-o,p=m-o,b=m+o):(x=u+g,_=x+o,p=m+o,b=m-o),y=x),{x1:p,x2:m,x3:b,y1:x,y2:_,y3:y}}drawTitle(t,e,i){const s=this.title,n=s.length;let o,a,r;if(n){const l=yi(i.rtl,this.x,this.width);for(t.x=Xo(this,i.titleAlign,i),e.textAlign=l.textAlign(i.titleAlign),e.textBaseline="middle",o=mi(i.titleFont),a=i.titleSpacing,e.fillStyle=i.titleColor,e.font=o.string,r=0;r<n;++r)e.fillText(s[r],l.x(t.x),t.y+o.lineHeight/2),t.y+=o.lineHeight+a,r+1===n&&(t.y+=i.titleMarginBottom-a)}}_drawColorBox(t,e,i,s,o){const a=this.labelColors[i],r=this.labelPointStyles[i],{boxHeight:l,boxWidth:h,boxPadding:c}=o,d=mi(o.bodyFont),u=Xo(this,"left",o),f=s.x(u),g=l<d.lineHeight?(d.lineHeight-l)/2:0,p=e.y+g;if(o.usePointStyle){const e={radius:Math.min(h,l)/2,pointStyle:r.pointStyle,rotation:r.rotation,borderWidth:1},i=s.leftForLtr(f,h)+h/2,n=p+l/2;t.strokeStyle=o.multiKeyBackground,t.fillStyle=o.multiKeyBackground,Me(t,e,i,n),t.strokeStyle=a.borderColor,t.fillStyle=a.backgroundColor,Me(t,e,i,n)}else{t.lineWidth=n(a.borderWidth)?Math.max(...Object.values(a.borderWidth)):a.borderWidth||1,t.strokeStyle=a.borderColor,t.setLineDash(a.borderDash||[]),t.lineDashOffset=a.borderDashOffset||0;const e=s.leftForLtr(f,h-c),i=s.leftForLtr(s.xPlus(f,1),h-c-2),r=gi(a.borderRadius);Object.values(r).some((t=>0!==t))?(t.beginPath(),t.fillStyle=o.multiKeyBackground,Le(t,{x:e,y:p,w:h,h:l,radius:r}),t.fill(),t.stroke(),t.fillStyle=a.backgroundColor,t.beginPath(),Le(t,{x:i,y:p+1,w:h-2,h:l-2,radius:r}),t.fill()):(t.fillStyle=o.multiKeyBackground,t.fillRect(e,p,h,l),t.strokeRect(e,p,h,l),t.fillStyle=a.backgroundColor,t.fillRect(i,p+1,h-2,l-2))}t.fillStyle=this.labelTextColors[i]}drawBody(t,e,i){const{body:s}=this,{bodySpacing:n,bodyAlign:o,displayColors:a,boxHeight:r,boxWidth:l,boxPadding:h}=i,c=mi(i.bodyFont);let u=c.lineHeight,f=0;const g=yi(i.rtl,this.x,this.width),p=function(i){e.fillText(i,g.x(t.x+f),t.y+u/2),t.y+=u+n},m=g.textAlign(o);let b,x,_,y,v,w,M;for(e.textAlign=o,e.textBaseline="middle",e.font=c.string,t.x=Xo(this,m,i),e.fillStyle=i.bodyColor,d(this.beforeBody,p),f=a&&"right"!==m?"center"===o?l/2+h:l+2+h:0,y=0,w=s.length;y<w;++y){for(b=s[y],x=this.labelTextColors[y],e.fillStyle=x,d(b.before,p),_=b.lines,a&&_.length&&(this._drawColorBox(e,t,y,g,i),u=Math.max(c.lineHeight,r)),v=0,M=_.length;v<M;++v)p(_[v]),u=c.lineHeight;d(b.after,p)}f=0,u=c.lineHeight,d(this.afterBody,p),t.y-=n}drawFooter(t,e,i){const s=this.footer,n=s.length;let o,a;if(n){const r=yi(i.rtl,this.x,this.width);for(t.x=Xo(this,i.footerAlign,i),t.y+=i.footerMarginTop,e.textAlign=r.textAlign(i.footerAlign),e.textBaseline="middle",o=mi(i.footerFont),e.fillStyle=i.footerColor,e.font=o.string,a=0;a<n;++a)e.fillText(s[a],r.x(t.x),t.y+o.lineHeight/2),t.y+=o.lineHeight+i.footerSpacing}}drawBackground(t,e,i,s){const{xAlign:n,yAlign:o}=this,{x:a,y:r}=t,{width:l,height:h}=i,{topLeft:c,topRight:d,bottomLeft:u,bottomRight:f}=gi(s.cornerRadius);e.fillStyle=s.backgroundColor,e.strokeStyle=s.borderColor,e.lineWidth=s.borderWidth,e.beginPath(),e.moveTo(a+c,r),"top"===o&&this.drawCaret(t,e,i,s),e.lineTo(a+l-d,r),e.quadraticCurveTo(a+l,r,a+l,r+d),"center"===o&&"right"===n&&this.drawCaret(t,e,i,s),e.lineTo(a+l,r+h-f),e.quadraticCurveTo(a+l,r+h,a+l-f,r+h),"bottom"===o&&this.drawCaret(t,e,i,s),e.lineTo(a+u,r+h),e.quadraticCurveTo(a,r+h,a,r+h-u),"center"===o&&"left"===n&&this.drawCaret(t,e,i,s),e.lineTo(a,r+c),e.quadraticCurveTo(a,r,a+c,r),e.closePath(),e.fill(),s.borderWidth>0&&e.stroke()}_updateAnimationTarget(t){const e=this.chart,i=this.$animations,s=i&&i.x,n=i&&i.y;if(s||n){const i=Bo[t.position].call(this,this._active,this._eventPosition);if(!i)return;const o=this._size=Ho(this,t),a=Object.assign({},i,this._size),r=Yo(e,t,a),l=Uo(t,a,r,e);s._to===l.x&&n._to===l.y||(this.xAlign=r.xAlign,this.yAlign=r.yAlign,this.width=o.width,this.height=o.height,this.caretX=i.x,this.caretY=i.y,this._resolveAnimations().update(this,l))}}_willRender(){return!!this.opacity}draw(t){const e=this.options.setContext(this.getContext());let i=this.opacity;if(!i)return;this._updateAnimationTarget(e);const s={width:this.width,height:this.height},n={x:this.x,y:this.y};i=Math.abs(i)<.001?0:i;const o=pi(e.padding),a=this.title.length||this.beforeBody.length||this.body.length||this.afterBody.length||this.footer.length;e.enabled&&a&&(t.save(),t.globalAlpha=i,this.drawBackground(n,t,s,e),vi(t,e.textDirection),n.y+=o.top,this.drawTitle(n,t,e),this.drawBody(n,t,e),this.drawFooter(n,t,e),wi(t,e.textDirection),t.restore())}getActiveElements(){return this._active||[]}setActiveElements(t,e){const i=this._active,s=t.map((({datasetIndex:t,index:e})=>{const i=this.chart.getDatasetMeta(t);if(!i)throw new Error("Cannot find a dataset at index "+t);return{datasetIndex:t,element:i.data[e],index:e}})),n=!u(i,s),o=this._positionChanged(s,e);(n||o)&&(this._active=s,this._eventPosition=e,this._ignoreReplayEvents=!0,this.update(!0))}handleEvent(t,e,i=!0){if(e&&this._ignoreReplayEvents)return!1;this._ignoreReplayEvents=!1;const s=this.options,n=this._active||[],o=this._getActiveElements(t,n,e,i),a=this._positionChanged(o,t),r=e||!u(o,n)||a;return r&&(this._active=o,(s.enabled||s.external)&&(this._eventPosition={x:t.x,y:t.y},this.update(!0,e))),r}_getActiveElements(t,e,i,s){const n=this.options;if("mouseout"===t.type)return[];if(!s)return e;const o=this.chart.getElementsAtEventForMode(t,n.mode,n,i);return n.reverse&&o.reverse(),o}_positionChanged(t,e){const{caretX:i,caretY:s,options:n}=this,o=Bo[n.position].call(this,t,e);return!1!==o&&(i!==o.x||s!==o.y)}}Go.positioners=Bo;var Zo={id:"tooltip",_element:Go,positioners:Bo,afterInit(t,e,i){i&&(t.tooltip=new Go({chart:t,options:i}))},beforeUpdate(t,e,i){t.tooltip&&t.tooltip.initialize(i)},reset(t,e,i){t.tooltip&&t.tooltip.initialize(i)},afterDraw(t){const e=t.tooltip;if(e&&e._willRender()){const i={tooltip:e};if(!1===t.notifyPlugins("beforeTooltipDraw",i))return;e.draw(t.ctx),t.notifyPlugins("afterTooltipDraw",i)}},afterEvent(t,e){if(t.tooltip){const i=e.replay;t.tooltip.handleEvent(e.event,i,e.inChartArea)&&(e.changed=!0)}},defaults:{enabled:!0,external:null,position:"average",backgroundColor:"rgba(0,0,0,0.8)",titleColor:"#fff",titleFont:{weight:"bold"},titleSpacing:2,titleMarginBottom:6,titleAlign:"left",bodyColor:"#fff",bodySpacing:2,bodyFont:{},bodyAlign:"left",footerColor:"#fff",footerSpacing:2,footerMarginTop:6,footerFont:{weight:"bold"},footerAlign:"left",padding:6,caretPadding:2,caretSize:5,cornerRadius:6,boxHeight:(t,e)=>e.bodyFont.size,boxWidth:(t,e)=>e.bodyFont.size,multiKeyBackground:"#fff",displayColors:!0,boxPadding:0,borderColor:"rgba(0,0,0,0)",borderWidth:0,animation:{duration:400,easing:"easeOutQuart"},animations:{numbers:{type:"number",properties:["x","y","width","height","caretX","caretY"]},opacity:{easing:"linear",duration:200}},callbacks:{beforeTitle:t,title(t){if(t.length>0){const e=t[0],i=e.chart.data.labels,s=i?i.length:0;if(this&&this.options&&"dataset"===this.options.mode)return e.dataset.label||"";if(e.label)return e.label;if(s>0&&e.dataIndex<s)return i[e.dataIndex]}return""},afterTitle:t,beforeBody:t,beforeLabel:t,label(t){if(this&&this.options&&"dataset"===this.options.mode)return t.label+": "+t.formattedValue||t.formattedValue;let e=t.dataset.label||"";e&&(e+=": ");const s=t.formattedValue;return i(s)||(e+=s),e},labelColor(t){const e=t.chart.getDatasetMeta(t.datasetIndex).controller.getStyle(t.dataIndex);return{borderColor:e.borderColor,backgroundColor:e.backgroundColor,borderWidth:e.borderWidth,borderDash:e.borderDash,borderDashOffset:e.borderDashOffset,borderRadius:0}},labelTextColor(){return this.options.bodyColor},labelPointStyle(t){const e=t.chart.getDatasetMeta(t.datasetIndex).controller.getStyle(t.dataIndex);return{pointStyle:e.pointStyle,rotation:e.rotation}},afterLabel:t,afterBody:t,beforeFooter:t,footer:t,afterFooter:t}},defaultRoutes:{bodyFont:"font",footerFont:"font",titleFont:"font"},descriptors:{_scriptable:t=>"filter"!==t&&"itemSort"!==t&&"external"!==t,_indexable:!1,callbacks:{_scriptable:!1,_indexable:!1},animation:{_fallback:!1},animations:{_fallback:"animation"}},additionalOptionScopes:["interaction"]},Jo=Object.freeze({__proto__:null,Decimation:go,Filler:To,Legend:Ro,SubTitle:Vo,Title:zo,Tooltip:Zo});function Qo(t,e,i,s){const n=t.indexOf(e);if(-1===n)return((t,e,i,s)=>("string"==typeof e?(i=t.push(e)-1,s.unshift({index:i,label:e})):isNaN(e)&&(i=null),i))(t,e,i,s);return n!==t.lastIndexOf(e)?i:n}class ta extends $s{constructor(t){super(t),this._startValue=void 0,this._valueRange=0,this._addedLabels=[]}init(t){const e=this._addedLabels;if(e.length){const t=this.getLabels();for(const{index:i,label:s}of e)t[i]===s&&t.splice(i,1);this._addedLabels=[]}super.init(t)}parse(t,e){if(i(t))return null;const s=this.getLabels();return((t,e)=>null===t?null:Z(Math.round(t),0,e))(e=isFinite(e)&&s[e]===t?e:Qo(s,t,r(e,t),this._addedLabels),s.length-1)}determineDataLimits(){const{minDefined:t,maxDefined:e}=this.getUserBounds();let{min:i,max:s}=this.getMinMax(!0);"ticks"===this.options.bounds&&(t||(i=0),e||(s=this.getLabels().length-1)),this.min=i,this.max=s}buildTicks(){const t=this.min,e=this.max,i=this.options.offset,s=[];let n=this.getLabels();n=0===t&&e===n.length-1?n:n.slice(t,e+1),this._valueRange=Math.max(n.length-(i?0:1),1),this._startValue=this.min-(i?.5:0);for(let i=t;i<=e;i++)s.push({value:i});return s}getLabelForValue(t){const e=this.getLabels();return t>=0&&t<e.length?e[t]:t}configure(){super.configure(),this.isHorizontal()||(this._reversePixels=!this._reversePixels)}getPixelForValue(t){return"number"!=typeof t&&(t=this.parse(t)),null===t?NaN:this.getPixelForDecimal((t-this._startValue)/this._valueRange)}getPixelForTick(t){const e=this.ticks;return t<0||t>e.length-1?null:this.getPixelForValue(e[t].value)}getValueForPixel(t){return Math.round(this._startValue+this.getDecimalForPixel(t)*this._valueRange)}getBasePixel(){return this.bottom}}function ea(t,e,{horizontal:i,minRotation:s}){const n=H(s),o=(i?Math.sin(n):Math.cos(n))||.001,a=.75*e*(""+t).length;return Math.min(e/o,a)}ta.id="category",ta.defaults={ticks:{callback:ta.prototype.getLabelForValue}};class ia extends $s{constructor(t){super(t),this.start=void 0,this.end=void 0,this._startValue=void 0,this._endValue=void 0,this._valueRange=0}parse(t,e){return i(t)||("number"==typeof t||t instanceof Number)&&!isFinite(+t)?null:+t}handleTickRangeOptions(){const{beginAtZero:t}=this.options,{minDefined:e,maxDefined:i}=this.getUserBounds();let{min:s,max:n}=this;const o=t=>s=e?s:t,a=t=>n=i?n:t;if(t){const t=z(s),e=z(n);t<0&&e<0?a(0):t>0&&e>0&&o(0)}if(s===n){let e=1;(n>=Number.MAX_SAFE_INTEGER||s<=Number.MIN_SAFE_INTEGER)&&(e=Math.abs(.05*n)),a(n+e),t||o(s-e)}this.min=s,this.max=n}getTickLimit(){const t=this.options.ticks;let e,{maxTicksLimit:i,stepSize:s}=t;return s?(e=Math.ceil(this.max/s)-Math.floor(this.min/s)+1,e>1e3&&(console.warn(`scales.${this.id}.ticks.stepSize: ${s} would result generating up to ${e} ticks. Limiting to 1000.`),e=1e3)):(e=this.computeTickLimit(),i=i||11),i&&(e=Math.min(i,e)),e}computeTickLimit(){return Number.POSITIVE_INFINITY}buildTicks(){const t=this.options,e=t.ticks;let s=this.getTickLimit();s=Math.max(2,s);const n=function(t,e){const s=[],{bounds:n,step:o,min:a,max:r,precision:l,count:h,maxTicks:c,maxDigits:d,includeBounds:u}=t,f=o||1,g=c-1,{min:p,max:m}=e,b=!i(a),x=!i(r),_=!i(h),y=(m-p)/(d+1);let v,w,M,k,S=F((m-p)/g/f)*f;if(S<1e-14&&!b&&!x)return[{value:p},{value:m}];k=Math.ceil(m/S)-Math.floor(p/S),k>g&&(S=F(k*S/g/f)*f),i(l)||(v=Math.pow(10,l),S=Math.ceil(S*v)/v),"ticks"===n?(w=Math.floor(p/S)*S,M=Math.ceil(m/S)*S):(w=p,M=m),b&&x&&o&&W((r-a)/o,S/1e3)?(k=Math.round(Math.min((r-a)/S,c)),S=(r-a)/k,w=a,M=r):_?(w=b?a:w,M=x?r:M,k=h-1,S=(M-w)/k):(k=(M-w)/S,k=N(k,Math.round(k),S/1e3)?Math.round(k):Math.ceil(k));const P=Math.max(Y(S),Y(w));v=Math.pow(10,i(l)?P:l),w=Math.round(w*v)/v,M=Math.round(M*v)/v;let D=0;for(b&&(u&&w!==a?(s.push({value:a}),w<a&&D++,N(Math.round((w+D*S)*v)/v,a,ea(a,y,t))&&D++):w<a&&D++);D<k;++D)s.push({value:Math.round((w+D*S)*v)/v});return x&&u&&M!==r?s.length&&N(s[s.length-1].value,r,ea(r,y,t))?s[s.length-1].value=r:s.push({value:r}):x&&M!==r||s.push({value:M}),s}({maxTicks:s,bounds:t.bounds,min:t.min,max:t.max,precision:e.precision,step:e.stepSize,count:e.count,maxDigits:this._maxDigits(),horizontal:this.isHorizontal(),minRotation:e.minRotation||0,includeBounds:!1!==e.includeBounds},this._range||this);return"ticks"===t.bounds&&j(n,this,"value"),t.reverse?(n.reverse(),this.start=this.max,this.end=this.min):(this.start=this.min,this.end=this.max),n}configure(){const t=this.ticks;let e=this.min,i=this.max;if(super.configure(),this.options.offset&&t.length){const s=(i-e)/Math.max(t.length-1,1)/2;e-=s,i+=s}this._startValue=e,this._endValue=i,this._valueRange=i-e}getLabelForValue(t){return li(t,this.chart.options.locale,this.options.ticks.format)}}class sa extends ia{determineDataLimits(){const{min:t,max:e}=this.getMinMax(!0);this.min=o(t)?t:0,this.max=o(e)?e:1,this.handleTickRangeOptions()}computeTickLimit(){const t=this.isHorizontal(),e=t?this.width:this.height,i=H(this.options.ticks.minRotation),s=(t?Math.sin(i):Math.cos(i))||.001,n=this._resolveTickFontOptions(0);return Math.ceil(e/Math.min(40,n.lineHeight/s))}getPixelForValue(t){return null===t?NaN:this.getPixelForDecimal((t-this._startValue)/this._valueRange)}getValueForPixel(t){return this._startValue+this.getDecimalForPixel(t)*this._valueRange}}function na(t){return 1===t/Math.pow(10,Math.floor(I(t)))}sa.id="linear",sa.defaults={ticks:{callback:Is.formatters.numeric}};class oa extends $s{constructor(t){super(t),this.start=void 0,this.end=void 0,this._startValue=void 0,this._valueRange=0}parse(t,e){const i=ia.prototype.parse.apply(this,[t,e]);if(0!==i)return o(i)&&i>0?i:null;this._zero=!0}determineDataLimits(){const{min:t,max:e}=this.getMinMax(!0);this.min=o(t)?Math.max(0,t):null,this.max=o(e)?Math.max(0,e):null,this.options.beginAtZero&&(this._zero=!0),this.handleTickRangeOptions()}handleTickRangeOptions(){const{minDefined:t,maxDefined:e}=this.getUserBounds();let i=this.min,s=this.max;const n=e=>i=t?i:e,o=t=>s=e?s:t,a=(t,e)=>Math.pow(10,Math.floor(I(t))+e);i===s&&(i<=0?(n(1),o(10)):(n(a(i,-1)),o(a(s,1)))),i<=0&&n(a(s,-1)),s<=0&&o(a(i,1)),this._zero&&this.min!==this._suggestedMin&&i===a(this.min,0)&&n(a(i,-1)),this.min=i,this.max=s}buildTicks(){const t=this.options,e=function(t,e){const i=Math.floor(I(e.max)),s=Math.ceil(e.max/Math.pow(10,i)),n=[];let o=a(t.min,Math.pow(10,Math.floor(I(e.min)))),r=Math.floor(I(o)),l=Math.floor(o/Math.pow(10,r)),h=r<0?Math.pow(10,Math.abs(r)):1;do{n.push({value:o,major:na(o)}),++l,10===l&&(l=1,++r,h=r>=0?1:h),o=Math.round(l*Math.pow(10,r)*h)/h}while(r<i||r===i&&l<s);const c=a(t.max,o);return n.push({value:c,major:na(o)}),n}({min:this._userMin,max:this._userMax},this);return"ticks"===t.bounds&&j(e,this,"value"),t.reverse?(e.reverse(),this.start=this.max,this.end=this.min):(this.start=this.min,this.end=this.max),e}getLabelForValue(t){return void 0===t?"0":li(t,this.chart.options.locale,this.options.ticks.format)}configure(){const t=this.min;super.configure(),this._startValue=I(t),this._valueRange=I(this.max)-I(t)}getPixelForValue(t){return void 0!==t&&0!==t||(t=this.min),null===t||isNaN(t)?NaN:this.getPixelForDecimal(t===this.min?0:(I(t)-this._startValue)/this._valueRange)}getValueForPixel(t){const e=this.getDecimalForPixel(t);return Math.pow(10,this._startValue+e*this._valueRange)}}function aa(t){const e=t.ticks;if(e.display&&t.display){const t=pi(e.backdropPadding);return r(e.font&&e.font.size,ne.font.size)+t.height}return 0}function ra(t,e,i,s,n){return t===s||t===n?{start:e-i/2,end:e+i/2}:t<s||t>n?{start:e-i,end:e}:{start:e,end:e+i}}function la(t){const e={l:t.left+t._padding.left,r:t.right-t._padding.right,t:t.top+t._padding.top,b:t.bottom-t._padding.bottom},i=Object.assign({},e),n=[],o=[],a=t._pointLabels.length,r=t.options.pointLabels,l=r.centerPointLabels?D/a:0;for(let u=0;u<a;u++){const a=r.setContext(t.getPointLabelContext(u));o[u]=a.padding;const f=t.getPointPosition(u,t.drawingArea+o[u],l),g=mi(a.font),p=(h=t.ctx,c=g,d=s(d=t._pointLabels[u])?d:[d],{w:ye(h,c.string,d),h:d.length*c.lineHeight});n[u]=p;const m=K(t.getIndexAngle(u)+l),b=Math.round($(m));ha(i,e,m,ra(b,f.x,p.w,0,180),ra(b,f.y,p.h,90,270))}var h,c,d;t.setCenterPoint(e.l-i.l,i.r-e.r,e.t-i.t,i.b-e.b),t._pointLabelItems=function(t,e,i){const s=[],n=t._pointLabels.length,o=t.options,a=aa(o)/2,r=t.drawingArea,l=o.pointLabels.centerPointLabels?D/n:0;for(let o=0;o<n;o++){const n=t.getPointPosition(o,r+a+i[o],l),h=Math.round($(K(n.angle+L))),c=e[o],d=ua(n.y,c.h,h),u=ca(h),f=da(n.x,c.w,u);s.push({x:n.x,y:d,textAlign:u,left:f,top:d,right:f+c.w,bottom:d+c.h})}return s}(t,n,o)}function ha(t,e,i,s,n){const o=Math.abs(Math.sin(i)),a=Math.abs(Math.cos(i));let r=0,l=0;s.start<e.l?(r=(e.l-s.start)/o,t.l=Math.min(t.l,e.l-r)):s.end>e.r&&(r=(s.end-e.r)/o,t.r=Math.max(t.r,e.r+r)),n.start<e.t?(l=(e.t-n.start)/a,t.t=Math.min(t.t,e.t-l)):n.end>e.b&&(l=(n.end-e.b)/a,t.b=Math.max(t.b,e.b+l))}function ca(t){return 0===t||180===t?"center":t<180?"left":"right"}function da(t,e,i){return"right"===i?t-=e:"center"===i&&(t-=e/2),t}function ua(t,e,i){return 90===i||270===i?t-=e/2:(i>270||i<90)&&(t-=e),t}function fa(t,e,i,s){const{ctx:n}=t;if(i)n.arc(t.xCenter,t.yCenter,e,0,O);else{let i=t.getPointPosition(0,e);n.moveTo(i.x,i.y);for(let o=1;o<s;o++)i=t.getPointPosition(o,e),n.lineTo(i.x,i.y)}}oa.id="logarithmic",oa.defaults={ticks:{callback:Is.formatters.logarithmic,major:{enabled:!0}}};class ga extends ia{constructor(t){super(t),this.xCenter=void 0,this.yCenter=void 0,this.drawingArea=void 0,this._pointLabels=[],this._pointLabelItems=[]}setDimensions(){const t=this._padding=pi(aa(this.options)/2),e=this.width=this.maxWidth-t.width,i=this.height=this.maxHeight-t.height;this.xCenter=Math.floor(this.left+e/2+t.left),this.yCenter=Math.floor(this.top+i/2+t.top),this.drawingArea=Math.floor(Math.min(e,i)/2)}determineDataLimits(){const{min:t,max:e}=this.getMinMax(!1);this.min=o(t)&&!isNaN(t)?t:0,this.max=o(e)&&!isNaN(e)?e:0,this.handleTickRangeOptions()}computeTickLimit(){return Math.ceil(this.drawingArea/aa(this.options))}generateTickLabels(t){ia.prototype.generateTickLabels.call(this,t),this._pointLabels=this.getLabels().map(((t,e)=>{const i=c(this.options.pointLabels.callback,[t,e],this);return i||0===i?i:""})).filter(((t,e)=>this.chart.getDataVisibility(e)))}fit(){const t=this.options;t.display&&t.pointLabels.display?la(this):this.setCenterPoint(0,0,0,0)}setCenterPoint(t,e,i,s){this.xCenter+=Math.floor((t-e)/2),this.yCenter+=Math.floor((i-s)/2),this.drawingArea-=Math.min(this.drawingArea/2,Math.max(t,e,i,s))}getIndexAngle(t){return K(t*(O/(this._pointLabels.length||1))+H(this.options.startAngle||0))}getDistanceFromCenterForValue(t){if(i(t))return NaN;const e=this.drawingArea/(this.max-this.min);return this.options.reverse?(this.max-t)*e:(t-this.min)*e}getValueForDistanceFromCenter(t){if(i(t))return NaN;const e=t/(this.drawingArea/(this.max-this.min));return this.options.reverse?this.max-e:this.min+e}getPointLabelContext(t){const e=this._pointLabels||[];if(t>=0&&t<e.length){const i=e[t];return function(t,e,i){return _i(t,{label:i,index:e,type:"pointLabel"})}(this.getContext(),t,i)}}getPointPosition(t,e,i=0){const s=this.getIndexAngle(t)-L+i;return{x:Math.cos(s)*e+this.xCenter,y:Math.sin(s)*e+this.yCenter,angle:s}}getPointPositionForValue(t,e){return this.getPointPosition(t,this.getDistanceFromCenterForValue(e))}getBasePosition(t){return this.getPointPositionForValue(t||0,this.getBaseValue())}getPointLabelPosition(t){const{left:e,top:i,right:s,bottom:n}=this._pointLabelItems[t];return{left:e,top:i,right:s,bottom:n}}drawBackground(){const{backgroundColor:t,grid:{circular:e}}=this.options;if(t){const i=this.ctx;i.save(),i.beginPath(),fa(this,this.getDistanceFromCenterForValue(this._endValue),e,this._pointLabels.length),i.closePath(),i.fillStyle=t,i.fill(),i.restore()}}drawGrid(){const t=this.ctx,e=this.options,{angleLines:s,grid:n}=e,o=this._pointLabels.length;let a,r,l;if(e.pointLabels.display&&function(t,e){const{ctx:s,options:{pointLabels:n}}=t;for(let o=e-1;o>=0;o--){const e=n.setContext(t.getPointLabelContext(o)),a=mi(e.font),{x:r,y:l,textAlign:h,left:c,top:d,right:u,bottom:f}=t._pointLabelItems[o],{backdropColor:g}=e;if(!i(g)){const t=gi(e.borderRadius),i=pi(e.backdropPadding);s.fillStyle=g;const n=c-i.left,o=d-i.top,a=u-c+i.width,r=f-d+i.height;Object.values(t).some((t=>0!==t))?(s.beginPath(),Le(s,{x:n,y:o,w:a,h:r,radius:t}),s.fill()):s.fillRect(n,o,a,r)}Ae(s,t._pointLabels[o],r,l+a.lineHeight/2,a,{color:e.color,textAlign:h,textBaseline:"middle"})}}(this,o),n.display&&this.ticks.forEach(((t,e)=>{if(0!==e){r=this.getDistanceFromCenterForValue(t.value);!function(t,e,i,s){const n=t.ctx,o=e.circular,{color:a,lineWidth:r}=e;!o&&!s||!a||!r||i<0||(n.save(),n.strokeStyle=a,n.lineWidth=r,n.setLineDash(e.borderDash),n.lineDashOffset=e.borderDashOffset,n.beginPath(),fa(t,i,o,s),n.closePath(),n.stroke(),n.restore())}(this,n.setContext(this.getContext(e-1)),r,o)}})),s.display){for(t.save(),a=o-1;a>=0;a--){const i=s.setContext(this.getPointLabelContext(a)),{color:n,lineWidth:o}=i;o&&n&&(t.lineWidth=o,t.strokeStyle=n,t.setLineDash(i.borderDash),t.lineDashOffset=i.borderDashOffset,r=this.getDistanceFromCenterForValue(e.ticks.reverse?this.min:this.max),l=this.getPointPosition(a,r),t.beginPath(),t.moveTo(this.xCenter,this.yCenter),t.lineTo(l.x,l.y),t.stroke())}t.restore()}}drawBorder(){}drawLabels(){const t=this.ctx,e=this.options,i=e.ticks;if(!i.display)return;const s=this.getIndexAngle(0);let n,o;t.save(),t.translate(this.xCenter,this.yCenter),t.rotate(s),t.textAlign="center",t.textBaseline="middle",this.ticks.forEach(((s,a)=>{if(0===a&&!e.reverse)return;const r=i.setContext(this.getContext(a)),l=mi(r.font);if(n=this.getDistanceFromCenterForValue(this.ticks[a].value),r.showLabelBackdrop){t.font=l.string,o=t.measureText(s.label).width,t.fillStyle=r.backdropColor;const e=pi(r.backdropPadding);t.fillRect(-o/2-e.left,-n-l.size/2-e.top,o+e.width,l.size+e.height)}Ae(t,s.label,0,-n,l,{color:r.color})})),t.restore()}drawTitle(){}}ga.id="radialLinear",ga.defaults={display:!0,animate:!0,position:"chartArea",angleLines:{display:!0,lineWidth:1,borderDash:[],borderDashOffset:0},grid:{circular:!1},startAngle:0,ticks:{showLabelBackdrop:!0,callback:Is.formatters.numeric},pointLabels:{backdropColor:void 0,backdropPadding:2,display:!0,font:{size:10},callback:t=>t,padding:5,centerPointLabels:!1}},ga.defaultRoutes={"angleLines.color":"borderColor","pointLabels.color":"color","ticks.color":"color"},ga.descriptors={angleLines:{_fallback:"grid"}};const pa={millisecond:{common:!0,size:1,steps:1e3},second:{common:!0,size:1e3,steps:60},minute:{common:!0,size:6e4,steps:60},hour:{common:!0,size:36e5,steps:24},day:{common:!0,size:864e5,steps:30},week:{common:!1,size:6048e5,steps:4},month:{common:!0,size:2628e6,steps:12},quarter:{common:!1,size:7884e6,steps:4},year:{common:!0,size:3154e7}},ma=Object.keys(pa);function ba(t,e){return t-e}function xa(t,e){if(i(e))return null;const s=t._adapter,{parser:n,round:a,isoWeekday:r}=t._parseOpts;let l=e;return"function"==typeof n&&(l=n(l)),o(l)||(l="string"==typeof n?s.parse(l,n):s.parse(l)),null===l?null:(a&&(l="week"!==a||!B(r)&&!0!==r?s.startOf(l,a):s.startOf(l,"isoWeek",r)),+l)}function _a(t,e,i,s){const n=ma.length;for(let o=ma.indexOf(t);o<n-1;++o){const t=pa[ma[o]],n=t.steps?t.steps:Number.MAX_SAFE_INTEGER;if(t.common&&Math.ceil((i-e)/(n*t.size))<=s)return ma[o]}return ma[n-1]}function ya(t,e,i){if(i){if(i.length){const{lo:s,hi:n}=tt(i,e);t[i[s]>=e?i[s]:i[n]]=!0}}else t[e]=!0}function va(t,e,i){const s=[],n={},o=e.length;let a,r;for(a=0;a<o;++a)r=e[a],n[r]=a,s.push({value:r,major:!1});return 0!==o&&i?function(t,e,i,s){const n=t._adapter,o=+n.startOf(e[0].value,s),a=e[e.length-1].value;let r,l;for(r=o;r<=a;r=+n.add(r,1,s))l=i[r],l>=0&&(e[l].major=!0);return e}(t,s,n,i):s}class wa extends $s{constructor(t){super(t),this._cache={data:[],labels:[],all:[]},this._unit="day",this._majorUnit=void 0,this._offsets={},this._normalized=!1,this._parseOpts=void 0}init(t,e){const i=t.time||(t.time={}),s=this._adapter=new wn._date(t.adapters.date);s.init(e),b(i.displayFormats,s.formats()),this._parseOpts={parser:i.parser,round:i.round,isoWeekday:i.isoWeekday},super.init(t),this._normalized=e.normalized}parse(t,e){return void 0===t?null:xa(this,t)}beforeLayout(){super.beforeLayout(),this._cache={data:[],labels:[],all:[]}}determineDataLimits(){const t=this.options,e=this._adapter,i=t.time.unit||"day";let{min:s,max:n,minDefined:a,maxDefined:r}=this.getUserBounds();function l(t){a||isNaN(t.min)||(s=Math.min(s,t.min)),r||isNaN(t.max)||(n=Math.max(n,t.max))}a&&r||(l(this._getLabelBounds()),"ticks"===t.bounds&&"labels"===t.ticks.source||l(this.getMinMax(!1))),s=o(s)&&!isNaN(s)?s:+e.startOf(Date.now(),i),n=o(n)&&!isNaN(n)?n:+e.endOf(Date.now(),i)+1,this.min=Math.min(s,n-1),this.max=Math.max(s+1,n)}_getLabelBounds(){const t=this.getLabelTimestamps();let e=Number.POSITIVE_INFINITY,i=Number.NEGATIVE_INFINITY;return t.length&&(e=t[0],i=t[t.length-1]),{min:e,max:i}}buildTicks(){const t=this.options,e=t.time,i=t.ticks,s="labels"===i.source?this.getLabelTimestamps():this._generate();"ticks"===t.bounds&&s.length&&(this.min=this._userMin||s[0],this.max=this._userMax||s[s.length-1]);const n=this.min,o=st(s,n,this.max);return this._unit=e.unit||(i.autoSkip?_a(e.minUnit,this.min,this.max,this._getLabelCapacity(n)):function(t,e,i,s,n){for(let o=ma.length-1;o>=ma.indexOf(i);o--){const i=ma[o];if(pa[i].common&&t._adapter.diff(n,s,i)>=e-1)return i}return ma[i?ma.indexOf(i):0]}(this,o.length,e.minUnit,this.min,this.max)),this._majorUnit=i.major.enabled&&"year"!==this._unit?function(t){for(let e=ma.indexOf(t)+1,i=ma.length;e<i;++e)if(pa[ma[e]].common)return ma[e]}(this._unit):void 0,this.initOffsets(s),t.reverse&&o.reverse(),va(this,o,this._majorUnit)}afterAutoSkip(){this.options.offsetAfterAutoskip&&this.initOffsets(this.ticks.map((t=>+t.value)))}initOffsets(t){let e,i,s=0,n=0;this.options.offset&&t.length&&(e=this.getDecimalForValue(t[0]),s=1===t.length?1-e:(this.getDecimalForValue(t[1])-e)/2,i=this.getDecimalForValue(t[t.length-1]),n=1===t.length?i:(i-this.getDecimalForValue(t[t.length-2]))/2);const o=t.length<3?.5:.25;s=Z(s,0,o),n=Z(n,0,o),this._offsets={start:s,end:n,factor:1/(s+1+n)}}_generate(){const t=this._adapter,e=this.min,i=this.max,s=this.options,n=s.time,o=n.unit||_a(n.minUnit,e,i,this._getLabelCapacity(e)),a=r(n.stepSize,1),l="week"===o&&n.isoWeekday,h=B(l)||!0===l,c={};let d,u,f=e;if(h&&(f=+t.startOf(f,"isoWeek",l)),f=+t.startOf(f,h?"day":o),t.diff(i,e,o)>1e5*a)throw new Error(e+" and "+i+" are too far apart with stepSize of "+a+" "+o);const g="data"===s.ticks.source&&this.getDataTimestamps();for(d=f,u=0;d<i;d=+t.add(d,a,o),u++)ya(c,d,g);return d!==i&&"ticks"!==s.bounds&&1!==u||ya(c,d,g),Object.keys(c).sort(((t,e)=>t-e)).map((t=>+t))}getLabelForValue(t){const e=this._adapter,i=this.options.time;return i.tooltipFormat?e.format(t,i.tooltipFormat):e.format(t,i.displayFormats.datetime)}_tickFormatFunction(t,e,i,s){const n=this.options,o=n.time.displayFormats,a=this._unit,r=this._majorUnit,l=a&&o[a],h=r&&o[r],d=i[e],u=r&&h&&d&&d.major,f=this._adapter.format(t,s||(u?h:l)),g=n.ticks.callback;return g?c(g,[f,e,i],this):f}generateTickLabels(t){let e,i,s;for(e=0,i=t.length;e<i;++e)s=t[e],s.label=this._tickFormatFunction(s.value,e,t)}getDecimalForValue(t){return null===t?NaN:(t-this.min)/(this.max-this.min)}getPixelForValue(t){const e=this._offsets,i=this.getDecimalForValue(t);return this.getPixelForDecimal((e.start+i)*e.factor)}getValueForPixel(t){const e=this._offsets,i=this.getDecimalForPixel(t)/e.factor-e.end;return this.min+i*(this.max-this.min)}_getLabelSize(t){const e=this.options.ticks,i=this.ctx.measureText(t).width,s=H(this.isHorizontal()?e.maxRotation:e.minRotation),n=Math.cos(s),o=Math.sin(s),a=this._resolveTickFontOptions(0).size;return{w:i*n+a*o,h:i*o+a*n}}_getLabelCapacity(t){const e=this.options.time,i=e.displayFormats,s=i[e.unit]||i.millisecond,n=this._tickFormatFunction(t,0,va(this,[t],this._majorUnit),s),o=this._getLabelSize(n),a=Math.floor(this.isHorizontal()?this.width/o.w:this.height/o.h)-1;return a>0?a:1}getDataTimestamps(){let t,e,i=this._cache.data||[];if(i.length)return i;const s=this.getMatchingVisibleMetas();if(this._normalized&&s.length)return this._cache.data=s[0].controller.getAllParsedValues(this);for(t=0,e=s.length;t<e;++t)i=i.concat(s[t].controller.getAllParsedValues(this));return this._cache.data=this.normalize(i)}getLabelTimestamps(){const t=this._cache.labels||[];let e,i;if(t.length)return t;const s=this.getLabels();for(e=0,i=s.length;e<i;++e)t.push(xa(this,s[e]));return this._cache.labels=this._normalized?t:this.normalize(t)}normalize(t){return rt(t.sort(ba))}}function Ma(t,e,i){let s,n,o,a,r=0,l=t.length-1;i?(e>=t[r].pos&&e<=t[l].pos&&({lo:r,hi:l}=et(t,"pos",e)),({pos:s,time:o}=t[r]),({pos:n,time:a}=t[l])):(e>=t[r].time&&e<=t[l].time&&({lo:r,hi:l}=et(t,"time",e)),({time:s,pos:o}=t[r]),({time:n,pos:a}=t[l]));const h=n-s;return h?o+(a-o)*(e-s)/h:o}wa.id="time",wa.defaults={bounds:"data",adapters:{},time:{parser:!1,unit:!1,round:!1,isoWeekday:!1,minUnit:"millisecond",displayFormats:{}},ticks:{source:"auto",major:{enabled:!1}}};class ka extends wa{constructor(t){super(t),this._table=[],this._minPos=void 0,this._tableRange=void 0}initOffsets(){const t=this._getTimestampsForTable(),e=this._table=this.buildLookupTable(t);this._minPos=Ma(e,this.min),this._tableRange=Ma(e,this.max)-this._minPos,super.initOffsets(t)}buildLookupTable(t){const{min:e,max:i}=this,s=[],n=[];let o,a,r,l,h;for(o=0,a=t.length;o<a;++o)l=t[o],l>=e&&l<=i&&s.push(l);if(s.length<2)return[{time:e,pos:0},{time:i,pos:1}];for(o=0,a=s.length;o<a;++o)h=s[o+1],r=s[o-1],l=s[o],Math.round((h+r)/2)!==l&&n.push({time:l,pos:o/(a-1)});return n}_getTimestampsForTable(){let t=this._cache.all||[];if(t.length)return t;const e=this.getDataTimestamps(),i=this.getLabelTimestamps();return t=e.length&&i.length?this.normalize(e.concat(i)):e.length?e:i,t=this._cache.all=t,t}getDecimalForValue(t){return(Ma(this._table,t)-this._minPos)/this._tableRange}getValueForPixel(t){const e=this._offsets,i=this.getDecimalForPixel(t)/e.factor-e.end;return Ma(this._table,i*this._tableRange+this._minPos,!0)}}ka.id="timeseries",ka.defaults=wa.defaults;var Sa=Object.freeze({__proto__:null,CategoryScale:ta,LinearScale:sa,LogarithmicScale:oa,RadialLinearScale:ga,TimeScale:wa,TimeSeriesScale:ka});return bn.register(Bn,Sa,co,Jo),bn.helpers={...Ti},bn._adapters=wn,bn.Animation=xs,bn.Animations=ys,bn.animator=mt,bn.controllers=Us.controllers.items,bn.DatasetController=Ls,bn.Element=Es,bn.elements=co,bn.Interaction=Vi,bn.layouts=Zi,bn.platforms=ps,bn.Scale=$s,bn.Ticks=Is,Object.assign(bn,Bn,Sa,co,Jo,ps),bn.Chart=bn,"undefined"!=typeof window&&(window.Chart=bn),bn}));

'@

$global:GLOBALJavaScript_Nav = @'
    <script>
        (function () {
        function safeJsonParse(text) {
            try { return JSON.parse(text); } catch (e) { return null; }
        }

        function getManifest() {
            var el = document.getElementById("report-manifest");
            if (!el || !el.textContent) return null;
            return safeJsonParse(el.textContent);
        }

        function getReportTitle(manifest) {
        if (manifest && manifest.currentReportName) {
            var s = String(manifest.currentReportName).replace(/\s+/g, " ").trim();
            if (s) return s;
        }

        if (manifest && manifest.currentReportKey) {
            var k = String(manifest.currentReportKey).replace(/\s+/g, " ").trim();
            if (k) return k;
        }

        var h1 = document.querySelector("h1");
        if (h1) {
            var t = (h1.textContent || "").replace(/\s+/g, " ").trim();
            if (t) return t;
        }

        return "Report";
        }


        function getHeaderMeta(manifest) {
        var tenant = "";
        var executed = "";

        if (manifest) {
            if (manifest.tenantName) {
            tenant = String(manifest.tenantName).trim();
            }

            if (manifest.tenantId) {
            var tid = String(manifest.tenantId).trim();
            if (tid) {
                tenant = tenant ? (tenant + " / ID: " + tid) : ("ID: " + tid);
            }
            }

            if (manifest.executedAt) {
            executed = String(manifest.executedAt).trim();
            }
        }

        return { tenant: tenant, executed: executed };
        }


        function ensureHeadingIds() {
            var headings = document.querySelectorAll("h2");

            headings = Array.prototype.filter.call(headings, function (h2) {
                if (!h2) return false;
                // Exclude help modal heading
                if (h2.closest && h2.closest("#helpModalOverlay")) return false;

                return true;
            });
            for (var i = 0; i < headings.length; i++) {
            var h2 = headings[i];
            if (h2.id) continue;

            var id = (h2.textContent || "")
                .trim()
                .toLowerCase()
                .replace(/\s+/g, "-")
                .replace(/[^a-z0-9\-]/g, "");

            h2.id = id || ("section-" + i);
            }
        }

        function buildNavStackShell(manifest) {
            if (document.getElementById("nav-stack")) return;

            var body = document.body;
            var loading = document.getElementById("loadingOverlay");

            var stack = document.createElement("div");
            stack.id = "nav-stack";

            var header = document.createElement("div");
            header.id = "report-header";

            var left = document.createElement("div");
            left.className = "hdr-left";

            var titleWrap = document.createElement("div");
            titleWrap.className = "hdr-title";

            var name = document.createElement("span");
            name.className = "hdr-name";
            name.textContent = getReportTitle(manifest);

            titleWrap.appendChild(name);
            left.appendChild(titleWrap);

            var meta = getHeaderMeta(manifest);
            var sub = document.createElement("div");
            sub.className = "hdr-sub";
            sub.id = "hdr-subline";

            if (meta.tenant) {
            var t = document.createElement("span");
            t.className = "hdr-meta";
            t.textContent = meta.tenant;
            sub.appendChild(t);
            }

            if (meta.tenant && meta.executed) {
            var dot = document.createElement("span");
            dot.className = "hdr-dot";
            dot.textContent = "\u2022";
            sub.appendChild(dot);
            }

            if (meta.executed) {
            var e = document.createElement("span");
            e.className = "hdr-meta";
            e.innerHTML = "Executed: " + meta.executed.replace(/</g, "&lt;");
            sub.appendChild(e);
            }

            left.appendChild(sub);

            var center = document.createElement("div");
            center.className = "hdr-center";

            var right = document.createElement("div");
            right.className = "hdr-right";
            right.id = "hdr-actions";

            var warnBtn = document.createElement("button");
            warnBtn.className = "hdr-btn hdr-warn-btn";
            warnBtn.id = "hdrWarningsBtn";
            warnBtn.type = "button";
            warnBtn.hidden = true;

            var warnLabel = document.createElement("span");
            warnLabel.className = "hdr-warn-label";
            warnLabel.textContent = "\u26A0\uFE0F Warnings";

            var warnCount = document.createElement("span");
            warnCount.className = "hdr-warn-count";
            warnCount.id = "hdrWarningsCount";
            warnCount.setAttribute("aria-hidden", "true");

            warnBtn.appendChild(warnLabel);
            warnBtn.appendChild(warnCount);

            right.appendChild(warnBtn);

            header.appendChild(left);
            header.appendChild(center);
            header.appendChild(right);

            var tabstrip = document.createElement("div");
            tabstrip.id = "report-tabstrip";

            var sectionStrip = document.createElement("div");
            sectionStrip.id = "section-strip";
            sectionStrip.setAttribute("aria-label", "Sections");

            var sectionInner = document.createElement("div");
            sectionInner.className = "section-strip-inner";
            sectionInner.id = "sectionStripInner";
            sectionStrip.appendChild(sectionInner);

            stack.appendChild(header);
            stack.appendChild(tabstrip);
            stack.appendChild(sectionStrip);

            body.insertBefore(stack, body.firstChild);
            if (loading) body.insertBefore(loading, stack);

            // Warnings drawer shell
            if (!document.getElementById("warnings-drawer")) {
            var backdrop = document.createElement("div");
            backdrop.className = "contents-backdrop";
            backdrop.id = "warnings-backdrop";
            backdrop.hidden = true;

            var drawer = document.createElement("aside");
            drawer.className = "contents-drawer";
            drawer.id = "warnings-drawer";
            drawer.setAttribute("data-drawer", "warnings");
            drawer.setAttribute("aria-hidden", "true");

            var inner = document.createElement("div");
            inner.className = "contents-drawer-inner";

            var hdr = document.createElement("div");
            hdr.className = "contents-drawer-header";

            var ttl = document.createElement("div");
            ttl.className = "contents-drawer-title";
            ttl.textContent = "Execution warnings";

            var close = document.createElement("button");
            close.className = "hdr-btn";
            close.id = "warningsCloseBtn";
            close.type = "button";
            close.textContent = "Close";

            hdr.appendChild(ttl);
            hdr.appendChild(close);

            var bodyWrap = document.createElement("div");
            bodyWrap.className = "warnings-body";
            bodyWrap.id = "warnings-body";

            var list = document.createElement("ul");
            list.className = "warnings-list";
            list.id = "warnings-list";

            var empty = document.createElement("div");
            empty.className = "warnings-empty";
            empty.id = "warnings-empty";
            empty.hidden = true;
            empty.textContent = "No warnings found.";

            bodyWrap.appendChild(list);
            bodyWrap.appendChild(empty);

            inner.appendChild(hdr);
            inner.appendChild(bodyWrap);

            drawer.appendChild(inner);

            body.appendChild(backdrop);
            body.appendChild(drawer);
            }
        }

        function buildReportTabs(manifest) {
            var host = document.getElementById("report-tabstrip");
            if (!host) return;

            host.innerHTML = "";

            if (!manifest || !manifest.reports || !manifest.reports.length) return;

            var inner = document.createElement("div");
            inner.className = "tabstrip-inner";

            var curKey = String((manifest.currentReportKey || manifest.current || "")).trim();
            var curPath = (window.location.pathname || "").split("/").pop();

            for (var i = 0; i < manifest.reports.length; i++) {
            var r = manifest.reports[i] || {};
            if (!r.file) continue;

            var a = document.createElement("a");
            a.className = "report-tab";
            a.href = r.file;
            a.textContent = r.title || r.key || r.file;

            var isActive = false;
            if (curKey && (r.key === curKey || r.title === curKey)) isActive = true;
            if (!isActive && curPath && r.file.split("/").pop() === curPath) isActive = true;

            if (isActive) {
                a.classList.add("active");
                a.setAttribute("aria-current", "page");
                a.href = "#";
            }

            inner.appendChild(a);
            }

            host.appendChild(inner);
        }

        function buildSectionStrip() {
            var inner = document.getElementById("sectionStripInner");
            if (!inner) return;

            while (inner.firstChild) inner.removeChild(inner.firstChild);

            var headings = document.querySelectorAll("h2");

            var added = 0;

            for (var i = 0; i < headings.length; i++) {
                var h2 = headings[i];
                if (!h2 || !h2.id) continue;

                // Exclude help modal heading (if present in DOM)
                if (h2.closest && h2.closest("#helpModalOverlay")) continue;

                // Add separator only BETWEEN items
                if (added > 0) {
                    var sep = document.createElement("span");
                    sep.className = "section-sep";
                    sep.textContent = "\u2022";
                    inner.appendChild(sep);
                }

                var a = document.createElement("a");
                a.className = "section-link";
                a.href = "#" + h2.id;
                a.textContent = (h2.textContent || "").replace(/\s+/g, " ").trim();

                inner.appendChild(a);
                added++;
            }
        }

        function ensureHeaderControls() {
            var actions = document.getElementById("hdr-actions");
            if (!actions) return;

            // -------------------------
            // Theme button
            // -------------------------
            if (!document.getElementById("hdrThemeBtn")) {
                var themeBtn = document.createElement("button");
                themeBtn.id = "hdrThemeBtn";
                themeBtn.className = "hdr-btn";
                themeBtn.type = "button";
                actions.appendChild(themeBtn);

                function setTheme(theme) {
                    document.body.classList.remove("light-mode", "dark-mode");
                    document.body.classList.add(theme + "-mode");
                    localStorage.setItem("theme", theme);

                    themeBtn.textContent = theme === "dark" ? "\uD83C\uDF13 Dark" : "\u2600\uFE0F Light";

                    // Recolor table if the table script exists on this page
                    if (typeof window.colorCells === "function") {
                        var table = document.querySelector("#tableWrapper table");
                        if (table) {
                            var headerCells = table.querySelectorAll("thead tr:first-child th");
                            var headers = Array.prototype.map.call(headerCells, function (th) {
                                return th.getAttribute("data-col") || (th.textContent || "").trim();
                            });
                            window.requestAnimationFrame(function () {
                                window.colorCells(table, headers);
                            });
                        }
                    }
                }

                var savedTheme = localStorage.getItem("theme") || "dark";
                setTheme(savedTheme);

                themeBtn.addEventListener("click", function () {
                    var isDark = document.body.classList.contains("dark-mode");
                    setTheme(isDark ? "light" : "dark");
                });
            }

            // -------------------------
            // Help button + modal
            // -------------------------
            if (!document.getElementById("hdrHelpBtn")) {
                var helpBtn = document.createElement("button");
                helpBtn.id = "hdrHelpBtn";
                helpBtn.className = "hdr-btn";
                helpBtn.type = "button";
                helpBtn.textContent = "\u2753 Help";
                actions.appendChild(helpBtn);

                if (!document.getElementById("helpModalOverlay")) {
                    var modalOverlay = document.createElement("div");
                    modalOverlay.id = "helpModalOverlay";
                    modalOverlay.style.position = "fixed";
                    modalOverlay.style.top = "0";
                    modalOverlay.style.left = "0";
                    modalOverlay.style.width = "100vw";
                    modalOverlay.style.height = "100vh";
                    modalOverlay.style.backgroundColor = "rgba(0, 0, 0, 0.6)";
                    modalOverlay.style.display = "none";
                    modalOverlay.style.zIndex = "9999";
                    modalOverlay.style.justifyContent = "center";
                    modalOverlay.style.alignItems = "center";

                    var modalContent = document.createElement("div");
                    modalContent.id = "helpModalContent";
                    modalContent.style.background = "var(--nav-link-bg)";
                    modalContent.style.color = "var(--nav-link-text)";
                    modalContent.style.padding = "24px";
                    modalContent.style.borderRadius = "12px";
                    modalContent.style.maxWidth = "800px";
                    modalContent.style.width = "90%";
                    modalContent.style.boxShadow = "0 8px 16px rgba(0,0,0,0.4)";
                    modalContent.style.fontSize = "15px";
                    modalContent.style.lineHeight = "1.6";
                    modalContent.style.position = "relative";

                    // Paste your existing help HTML here unchanged:
                    modalContent.innerHTML = `
                    <h2 style="margin-top: 0;">How to Use This Report</h2>
                    <strong>General</strong>
                    <ul style="margin-top: 6px;">
                        <li>Click the \u2699\uFE0F <strong>Columns</strong> button to show or hide specific columns.
                        <li>Click \u{1F4BE} <strong>Export CSV</strong> to download the currently visible data as a CSV file.</li>
                        <li>Click \u{1F441} <strong>Share View</strong> to copy filters, sorting, and column selection as a shareable link.</li>
                        <li>Click \uD83E\uDDF0 <strong>Preset Views</strong> to apply preconfigured filters and column selections.</li>
                        <li>Click \uD83D\uDD01 <strong>Reset View</strong> to reset the view to the default.</li>
                        <li>Click on object names to jump to detailed information, even across reports.<br>
                        Links look like this: <a href="#" onclick="return false;" style="pointer-events: none;">Example Link</a></li>
                        <li>When navigating within the report, use the browser's back button to return.</li>
                        <li>Browser search can locate content even within collapsed <em>details</em> sections.</li>
                        <li>Some table header fields display helper text on mouse hover.</li>
                        <li>Sort data by clicking any table header.
                    </ul>
                    <strong>Filtering</strong>
                    <ul style="margin-top: 6px;">
                        <li>If no operator is specified, filtering defaults to <em>contains</em>.</li>
                        <li>Use <code>=</code> for an exact match.</li>
                        <li>Use <code>^</code> for <em>starts with</em> (e.g., <code>^Mallory</code>).</li>
                        <li>Use <code>$</code> for <em>ends with</em> (e.g., <code>$domain.ch</code>).</li>
                        <li>Comparison operators like <code>&gt;</code>, <code>&lt;</code>, <code>&gt;=</code>, <code>&lt;=</code> are supported (for numeric values only).</li>
                        <li>Filters can be negated by starting with <code>!</code> (except for numeric comparisons).<br>Examples: <code>!Mallory</code>, <code>!=Mallory</code>, <code>!^Mallory</code> or <code>!$domain.ch</code>.</li>
                        <li>Use <code>=empty</code> to match empty cells, or <code>!=empty</code> to match non-empty cells.</li>
                        <li>Use <code>||</code> to match any of multiple values in the same column (e.g., <code>Admin || Guest</code>).</li>
                        <li>To apply <code>OR</code> logic across columns, use <code>or_</code> or <code>group1_</code>. Examples: Column1:<code>or_>1</code> Column2:<code>or_!Mallory</code>.</li>
                        <li>The <strong>DisplayName</strong> column includes the object's ID (hidden), allowing filtering by ID.</li>
                    </ul>
                    <strong>Rating</strong>
                    <ul style="margin-top: 6px;">
                        <li><strong>Impact</strong>: Represents the amount or severity of permission the object has.</li>
                        <li><strong>Likelihood</strong>: Represents how easily the object can be influenced or strongly it is protected.</li>
                        <li><strong>Risk</strong>: Calculated as: <em>Impact x Likelihood = Risk</em>.</li>
                        <li><strong>Important</strong>:
                            <ul>
                                <li>This scoring is meant as a basic evaluation to help sort and prioritize entries in the table.</li>
                                <li>Risk scores are not directly comparable between object types or reports.</li>
                                <li>It is not intended to replace a full risk assessment.</li>
                            </ul>
                        </li> 
                    </ul>
                    \u{1F4D6} More information in the <a href="https://github.com/CompassSecurity/EntraFalcon">GitHub README</a><br>
                        <button id="closeHelpModal" style="margin-top: 16px; padding: 6px 12px; font-size: 14px; border-radius: 4px; border: 1px solid #aaa; cursor: pointer;">\u2716 Close</button>
                    `;

                    modalOverlay.appendChild(modalContent);
                    document.body.appendChild(modalOverlay);

                    modalOverlay.addEventListener("click", function (e) {
                        if (e.target === modalOverlay || e.target.id === "closeHelpModal") {
                            modalOverlay.style.display = "none";
                        }
                    });

                    document.addEventListener("keydown", function (e) {
                        var isVisible = modalOverlay.style.display === "flex";
                        if (e.key === "Escape" && isVisible) {
                            modalOverlay.style.display = "none";
                        }
                    });
                }

                helpBtn.addEventListener("click", function () {
                    var overlay = document.getElementById("helpModalOverlay");
                    if (overlay) overlay.style.display = "flex";
                });
            }
        }


        function getNavOffset() {
            var doc = document.documentElement;
            var raw = "";
            try {
                raw = getComputedStyle(doc).getPropertyValue("--report-header-offset") || "";
            } catch (e) {
                raw = "";
            }
            var n = parseInt(String(raw).trim(), 10);
            return isNaN(n) ? 120 : n;
        }

        function updateActiveSectionLink() {
            var links = document.querySelectorAll("#sectionStripInner .section-link");
            if (!links.length) return;

            var activeId = "";
            var headings = document.querySelectorAll("h2[id]");
            for (var i = 0; i < headings.length; i++) {
            var rect = headings[i].getBoundingClientRect();
            if (rect.top <= getNavOffset()) activeId = headings[i].id;
            }

            for (var j = 0; j < links.length; j++) {
            var href = links[j].getAttribute("href") || "";
            var id = href.indexOf("#") === 0 ? href.slice(1) : "";
            if (id && id === activeId) {
                links[j].classList.add("active");
            } else {
                links[j].classList.remove("active");
            }
            }
        }

        function parseExecutionWarnings() {
            function normalizeWarnings(input) {
                if (!input) return [];

                var arr = [];
                if (Array.isArray(input)) {
                    arr = input;
                } else if (typeof input === "string") {
                    arr = [input];
                } else {
                    return [];
                }

                var out = [];
                for (var i = 0; i < arr.length; i++) {
                    var s = String(arr[i] || "").replace(/\s+/g, " ").trim();
                    if (s) out.push(s);
                }
                return out;
            }

            // Prefer the already-parsed manifest if present
            if (window.__reportManifest && window.__reportManifest.warnings != null) {
                return normalizeWarnings(window.__reportManifest.warnings);
            }

            // Otherwise parse from the embedded JSON script tag
            var el = document.getElementById("report-manifest");
            if (!el || !el.textContent) return [];

            try {
                var manifest = JSON.parse(el.textContent);
                return normalizeWarnings(manifest && manifest.warnings);
            } catch (e) {
                return [];
            }
        }


        function openWarnings() {
            var drawer = document.getElementById("warnings-drawer");
            var backdrop = document.getElementById("warnings-backdrop");
            if (!drawer || !backdrop) return;

            drawer.classList.add("open");
            drawer.setAttribute("aria-hidden", "false");
            backdrop.hidden = false;
        }

        function closeWarnings() {
            var drawer = document.getElementById("warnings-drawer");
            var backdrop = document.getElementById("warnings-backdrop");
            if (!drawer || !backdrop) return;

            drawer.classList.remove("open");
            drawer.setAttribute("aria-hidden", "true");
            backdrop.hidden = true;
        }

        function wireWarningsDrawer() {
            var btn = document.getElementById("hdrWarningsBtn");
            var closeBtn = document.getElementById("warningsCloseBtn");
            var backdrop = document.getElementById("warnings-backdrop");

            if (btn) btn.addEventListener("click", function () {
            var drawer = document.getElementById("warnings-drawer");
            if (drawer && drawer.classList.contains("open")) {
                closeWarnings();
            } else {
                openWarnings();
            }
            });

            if (closeBtn) closeBtn.addEventListener("click", closeWarnings);
            if (backdrop) backdrop.addEventListener("click", closeWarnings);
        }

        function renderWarningsPanel() {
            var warnings = parseExecutionWarnings();

            var btn = document.getElementById("hdrWarningsBtn");
            var countEl = document.getElementById("hdrWarningsCount");
            var list = document.getElementById("warnings-list");
            var empty = document.getElementById("warnings-empty");

            if (!btn || !countEl || !list || !empty) return;

            while (list.firstChild) list.removeChild(list.firstChild);

            if (!warnings || warnings.length === 0) {
                btn.hidden = true;
                btn.style.display = "none";
                countEl.textContent = "";
                empty.hidden = false;
                return;
            }

            btn.hidden = false;
            btn.style.display = "";

            for (var i = 0; i < warnings.length; i++) {
                var li = document.createElement("li");
                li.textContent = warnings[i];
                list.appendChild(li);
            }

            countEl.textContent = String(warnings.length);
            btn.hidden = false;
            empty.hidden = true;
        }

        function updateNavStackPadding() {
            var stack = document.getElementById("nav-stack");
            if (!stack) return;

            var h = stack.getBoundingClientRect().height || 0;
            var offset = h + 12;
            document.body.style.paddingTop = String(offset) + "px";
            document.documentElement.style.setProperty("--report-header-offset", String(Math.max(0, h - 1)) + "px");
        }

        function init() {
            var manifest = getManifest();

            ensureHeadingIds();
            buildNavStackShell(manifest);
            ensureHeaderControls();

            buildReportTabs(manifest);
            buildSectionStrip();
            renderWarningsPanel();
            wireWarningsDrawer();

            updateNavStackPadding();
            updateActiveSectionLink();

            window.addEventListener("scroll", function () {
            updateActiveSectionLink();
            }, { passive: true });

            window.addEventListener("resize", function () {
            updateNavStackPadding();
            });
        }

        document.addEventListener("DOMContentLoaded", init);
        })();
    </script>

'@

# CSS for formating the table
$global:GLOBALCss = @"
<style>
    /* ======== Shared Styles ======== */
    html {
        scroll-behavior: smooth;
    }

    body {
        font-family: Arial, Helvetica, sans-serif;
        margin: 0;
        padding: 0;
        padding-left: 12px;
        padding-right: 12px;
    }

    table {
        width: auto;
        max-width: 100%;
        margin-top: 20px;
        border-collapse: collapse;
        font-size: 12px;
    }

    th {
        font-size: 11px;
        font-weight: bold;
        padding-top: 6px;
        padding-bottom: 6px;
        vertical-align: middle;
    }

	td {
        padding: 6px;
        max-width: 100%;
    }

    .overview-table td {
        text-align: center;
        padding: 6px;
        max-width: 100%;
    }
        
	.property-table th {
		font-size: 12px;
		padding-left: 8px;
		padding-right: 8px;
	}

    td.left-align {
        text-align: left;
    }

    thead input[data-filter] {
        width: auto;
        max-width: 90%;
        font-size: 11px;
        padding: 0px;
    }

    thead tr:first-child th {
        position: sticky;
        top: 50px;
        z-index: 2;
    }

    #mainTableContainer {
        padding: 0px 16px 5px 0px;
        max-width: fit-content;
        margin: 0;
    }

    #mainTableContainer table {
        width: 100%;
    }

    .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        width: 100%;
        margin: 15px 0;
    }

    .toolbar .left-section,
    .toolbar .right-section {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .info-box {
        font-size: 14px;
        white-space: nowrap;
    }

    .toolbar select,
    .toolbar button,
    select,
    button {
        padding: 6px 10px;
        font-size: 14px;
        border-radius: 4px;
        border: 1px solid;
    }

    #paginationControls {
        margin-top: 16px;
    }

    #loadingOverlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(20, 20, 20, 0.85);
        z-index: 2000;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        color: #fff;
        font-size: 20px;
        font-weight: bold;
        backdrop-filter: blur(3px);
    }

    #loadingOverlay .spinner {
        border: 6px solid #ccc;
        border-top: 6px solid #4CAF50;
        border-radius: 50%;
        width: 60px;
        height: 60px;
        animation: spin 1s linear infinite;
        margin-bottom: 15px;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    /* -- Details Section -- */
    .details-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin: 10px 0;
        gap: 12px;
    }

    .details-info {
        font-size: 14px;
        white-space: nowrap;
    }
    .column-toggle-wrapper {
        position: relative;
        display: inline-block;
        margin: 0;
    }

    .column-toggle-button {
        padding: 6px 10px;
        font-size: 14px;
        cursor: pointer;
        border-radius: 4px;
    }

    .column-toggle-menu {
        display: none;
        position: absolute;
        top: 110%;
        left: 0;
        padding: 8px;
        z-index: 1000;
        max-height: 200px;
        overflow-y: auto;
        min-width: 150px;
    }

    .column-toggle-wrapper.show .column-toggle-menu {
        display: block;
    }

    .column-toggle-menu label {
        display: block;
        white-space: nowrap;
        margin: 4px 0;
        font-size: 13px;
    }

    details {
        margin-bottom: 12px;
        border-radius: 8px;
        padding: 10px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.4);
        scroll-margin-top: var(--sticky-offset, 60px); /* Matches nav height */
    }

    summary {
        font-weight: bold;
        font-size: 14px;
        cursor: pointer;
    }

    pre.yaml-block {
        padding: 10px;
        border-radius: 6px;
        white-space: pre-wrap;
        font-family: Consolas, monospace;
        font-size: 12px;
        margin-top: 10px;
        overflow-x: auto;
    }

    #toggle-expand {
        border-radius: 4px;
        padding: 6px 12px;
        margin: 10px 0;
        cursor: pointer;
        font-size: 14px;
    }

    code {
        padding: 2px 5px;
        border-radius: 4px;
        font-family: Consolas, monospace;
        font-size: 90%;
    }

    .preset-modal {
        position: fixed;
        top: 110px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 9999;
        padding: 20px;
        border-radius: 12px;
        max-width: 480px;
        width: auto;
        background: var(--nav-link-bg);
        color: var(--nav-link-text);
        border: 1px solid var(--nav-link-hover-bg);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        display: none;
        flex-direction: column;
        gap: 10px;
    }

    .preset-modal-content {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .preset-modal.show,
    .preset-modal:not(.hidden) {
        display: flex;
    }

    .preset-modal button {
        padding: 6px 12px;
        font-size: 14px;
        border-radius: 6px;
        cursor: pointer;
        border: 1px solid var(--nav-link-hover-bg);
        background-color: var(--nav-link-bg);
        color: var(--nav-link-text);
    }

    .preset-modal button:hover {
        background-color: var(--nav-link-hover-bg);
    }
    /* ======== Dark Mode ======== */
    body.dark-mode {
        background-color: #121212;
        color: #E0E0E0;
    }

    body.dark-mode h1 {
        color: #bebebe;
        font-size: 32px;
        border-bottom: 2px solid #bebebe;
    }

    body.dark-mode h2 {
        color: #BB86FC;
        font-size: 24px;
        font-weight: bold;
    }

    body.dark-mode h3 {
        color: #03DAC6;
        font-size: 18px;
    }

    body.dark-mode table {
        background-color: #1E1E1E;
        color: #E0E0E0;
    }

    body.dark-mode th {
        background: #282a36;
        color: #E0E0E0;
        border: 1px solid #333;
    }

    body.dark-mode td {
        border: 1px solid #333;
    }

    body.dark-mode tbody tr:nth-child(even) {
        background-color: #1A1A1A;
    }

    body.dark-mode tbody tr:nth-child(odd) {
        background-color: #2A2A2A;
    }

    body.dark-mode tbody tr:hover td {
        background-color: #444 !important;
    }

    body.dark-mode a {
        color: #FFB74D;
        text-decoration: none;
    }

    body.dark-mode a:hover {
        color: #FF6F61;
        text-decoration: underline;
    }

    body.dark-mode .column-toggle-button {
        background-color: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode .column-toggle-menu {
        background: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #555;
        box-shadow: 0 2px 8px rgba(255, 255, 255, 0.05);
    }

    body.dark-mode .column-toggle-button:hover {
        background-color: #3a3a3a;
    }

    body.dark-mode select,
    body.dark-mode button {
        background-color: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode select:hover,
    body.dark-mode button:hover {
        background-color: #3a3a3a;
    }

    body.dark-mode select:focus,
    body.dark-mode button:focus {
        outline: none;
        border-color: #888;
        box-shadow: 0 0 4px #888;
    }

    body.dark-mode details {
        background-color: #1c1c1c;
        border: 1px solid #333;
    }

    body.dark-mode pre.yaml-block {
        background-color: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #444;
    }

    body.dark-mode #toggle-expand {
        background-color: #333;
        color: #E0E0E0;
        border: 1px solid #666;
    }

    body.dark-mode #toggle-expand:hover {
        background-color: #444;
        border-color: #888;
    }

    body.dark-mode {
        --nav-bg: #1e1e1e;
        --nav-text: #fff;
        --nav-link-bg: #2a2a2a;
        --nav-link-text: #fff;
        --nav-link-hover-bg: #3a3a3a;
    }

    body.dark-mode code {
        background-color: #2e2e2e;
        color: #ff79c6; /* Bright pink/purple for dark contrast */
        border: 1px solid #444;
    }

    /* ======== Light Mode ======== */
    body.light-mode {
        background-color: white;
        color: black;
    }

    body.light-mode h1 {
        color: #e68a00;
        font-size: 32px;
        border-bottom: 2px solid #bebebe;
    }

    body.light-mode h2 {
        color: #3a3aec;
        font-size: 24px;
        font-weight: bold;
    }

    body.light-mode h3 {
        color: #000099;
        font-size: 18px;
    }

    body.light-mode th {
        background: #5d8fb8;
        color: #fff;
        border: 1px solid #d2d2d2;
    }

    body.light-mode td {
        border: 1px solid #d2d2d2;
    }

    body.light-mode tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

    body.light-mode tbody tr:nth-child(odd) {
        background: white;
    }

    body.light-mode tbody tr:hover td {
        background-color: lightblue !important;
    }

    body.light-mode a {
        color: #0645AD;
        text-decoration: none;
    }

    body.light-mode a:hover {
        text-decoration: underline;
    }

    body.light-mode .column-toggle-button {
        background-color: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode .column-toggle-button:hover {
        background-color: #e0e0e0;
    }

    body.light-mode .column-toggle-menu {
        background: #fff;
        color: #000;
        border: 1px solid #ccc;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }

    body.light-mode select,
    body.light-mode button {
        background-color: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode select:hover,
    body.light-mode button:hover {
        background-color: #e0e0e0;
    }

    body.light-mode select:focus,
    body.light-mode button:focus {
        outline: none;
        border-color: #666;
        box-shadow: 0 0 4px #aaa;
    }

    body.light-mode details {
        background-color: rgb(250, 250, 250);
        border: 1px solid #333;
        box-shadow: 0 1px 4px rgb(213, 223, 231);
    }

    body.light-mode pre.yaml-block {
        background-color: rgb(205, 209, 211);
        border: 1px solid #444;
        color: #000;
    }

    body.light-mode #toggle-expand {
        background-color: rgb(231, 229, 229);
        color: #000;
        border: 1px solid #666;
    }

    body.light-mode #toggle-expand:hover {
        background-color: #e0e0e0;
        border-color: #888;
    }

    body.light-mode {
        --nav-bg: #f9f9f9;
        --nav-text: #000;
        --nav-link-bg: #e0e0e0;
        --nav-link-text: #000;
        --nav-link-hover-bg: #ccc;
    }
    body.light-mode code {
        background-color: #f2f2f2;
        color: #d6336c;
        border: 1px solid #ddd;
    }

    /* ======== Report header + report tabs + section strip + warnings drawer ======== */
    :root{ --report-header-offset: 120px; }

    /* Fixed nav stack */
    #nav-stack{
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2000;
    }

    /* Background behind the whole stack */
    body.light-mode #nav-stack{ background: rgba(255,255,255,0.70); }
    body.dark-mode  #nav-stack{ background: rgba(0,0,0,0.45); }

    /* Header row */
    #report-header{
    position: relative !important;
    top: auto !important;
    display: grid;
    grid-template-columns: minmax(260px, 1fr) minmax(360px, 1.2fr) auto;
    gap: 12px;
    align-items: center;
    padding: 10px 14px;
    border-bottom: 1px solid rgba(0,0,0,0.18);
    background: rgba(255,255,255,0.86);
    backdrop-filter: blur(6px);
    }
    body.light-mode #report-header{
    background: rgba(255,255,255,0.92);
    border-bottom: 1px solid rgba(0,0,0,0.12);
    }
    body.dark-mode #report-header{
    background: rgba(22,22,22,0.86);
    border-bottom: 1px solid rgba(255,255,255,0.12);
    }

    .hdr-left{ display:flex; flex-direction:column; gap:4px; min-width: 240px; }
    .hdr-title{ display:flex; align-items:baseline; gap:10px; }
    .hdr-name{ font-size: 16px; font-weight: 800; }

    .hdr-sub{
    display:flex;
    flex-wrap:nowrap;
    align-items:center;
    gap:8px;
    font-size: 12px;
    opacity: 0.9;
    }
    .hdr-meta{ white-space: nowrap; }
    .hdr-dot{ opacity: 0.55; }
    @media (max-width: 900px){
    .hdr-sub{ flex-wrap: wrap; }
    }

    .hdr-center{
    display:flex;
    align-items:center;
    gap: 10px;
    flex-wrap: wrap;
    justify-content: center;
    }

    .hdr-right{
    display:flex;
    align-items:center;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: flex-end;
    }

    /* Buttons in header */
    .hdr-btn{
        height: 32px;
        padding: 0 10px;
        font-size: 13px;
        border-radius: 8px;
        border: 1px solid rgba(255,255,255,0.14);
        background: rgba(255,255,255,0.06);
        color: inherit;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        line-height: 32px;
    }
    .hdr-btn:hover{ background: rgba(255,255,255,0.10); }

    /* Make header buttons consistent */
    #hdr-actions button{
        height: 32px;
        line-height: 32px;
        padding: 0 10px;
        font-size: 13px;
        border-radius: 8px;
        box-sizing: border-box;
    }


    body.light-mode .hdr-btn{
    border: 1px solid rgba(0,0,0,0.16);
    background: rgba(0,0,0,0.03);
    }
    body.light-mode .hdr-btn:hover{ background: rgba(0,0,0,0.06); }

    body.dark-mode .hdr-btn{
    border: 1px solid rgba(255,255,255,0.14);
    background: rgba(255,255,255,0.06);
    }
    body.dark-mode .hdr-btn:hover{ background: rgba(255,255,255,0.10); }

    /* Report tab strip */
    #report-tabstrip{
    position: relative !important;
    top: auto !important;
    z-index: 999;
    background: rgba(255,255,255,0.92);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(0,0,0,0.10);
    }
    body.dark-mode #report-tabstrip{
    background: rgba(18, 18, 18, 0.92);
    border-bottom: 1px solid rgba(255,255,255,0.08);
    }
    .tabstrip-inner{
    display: flex;
    gap: 2px;
    align-items: center;
    padding: 4px 14px;
    overflow-x: auto;
    overscroll-behavior-x: contain;
    scrollbar-width: thin;
    }
    .tabstrip-inner::-webkit-scrollbar{ height: 8px; }
    .tabstrip-inner::-webkit-scrollbar-thumb{ border-radius: 8px; }
    body.light-mode .tabstrip-inner::-webkit-scrollbar-thumb{ background: rgba(0,0,0,0.18); }
    body.dark-mode  .tabstrip-inner::-webkit-scrollbar-thumb{ background: rgba(255,255,255,0.18); }

    .report-tab{
    display: inline-flex;
    align-items: center;
    padding: 6px 10px;
    font-size: 13px;
    letter-spacing: 0.2px;
    color: inherit;
    text-decoration: none;
    white-space: nowrap;
    border-bottom: 2px solid transparent;
    border-radius: 6px;
    background: transparent;
    }
    body.light-mode .report-tab:hover{ background: rgba(0,0,0,0.05); }
    body.dark-mode  .report-tab:hover{ background: rgba(255,255,255,0.06); }

    body.light-mode .report-tab.active{
    border-bottom-color: rgba(0,0,0,0.45);
    background: rgba(0,0,0,0.03);
    }
    body.dark-mode .report-tab.active{
    border-bottom-color: rgba(255,255,255,0.55);
    background: rgba(255,255,255,0.04);
    }

    /* Warnings badge */
    .hdr-warn-btn{ position: relative; }
    .hdr-warn-count{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 6px;
    margin-left: 8px;
    border-radius: 999px;
    font-size: 12px;
    line-height: 18px;
    font-weight: 700;
    }
    body.light-mode .hdr-warn-count{
    background: rgba(160, 90, 0, 0.16);
    border: 1px solid rgba(160, 90, 0, 0.35);
    }
    body.dark-mode .hdr-warn-count{
    background: rgba(255, 180, 80, 0.14);
    border: 1px solid rgba(255, 180, 80, 0.28);
    }

    /* Warnings drawer */
    .contents-backdrop{
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.45);
    z-index: 2000;
    }
    .contents-drawer{
    position: fixed;
    top: 0;
    right: 0;
    height: 100vh;
    width: min(360px, 92vw);
    background: rgba(22,22,22,0.98);
    color: inherit;
    border-left: 1px solid rgba(255,255,255,0.10);
    transform: translateX(100%);
    transition: transform 180ms ease;
    z-index: 2001;
    }
    .contents-drawer.open{ transform: translateX(0); }
    .contents-drawer-inner{
    height: 100%;
    display: flex;
    flex-direction: column;
    }
    .contents-drawer-header{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    border-bottom: 1px solid rgba(255,255,255,0.10);
    }
    .contents-drawer-title{
    font-size: 14px;
    font-weight: 650;
    letter-spacing: 0.2px;
    }
    .warnings-body{ padding: 12px 16px 16px; }
    .warnings-list{ margin: 0; padding-left: 18px; }
    .warnings-list li{ margin: 8px 0; line-height: 1.35; }
    .warnings-empty{ opacity: 0.8; font-size: 13px; padding: 10px 0; }

    /* Force-hide warnings button when hidden attribute is set */
    #hdrWarningsBtn[hidden]{
        display: none !important;
    }


    /* Warnings drawer: light mode */
    body.light-mode .contents-drawer{
        background: rgba(255,255,255,0.98);
        color: rgba(0,0,0,0.92);
        border-left: 1px solid rgba(0,0,0,0.14);
    }

    body.light-mode .contents-drawer-header{
        border-bottom: 1px solid rgba(0,0,0,0.12);
    }

    body.light-mode .warnings-empty{
        opacity: 0.85;
    }

    /* Optional: backdrop slightly lighter in light mode */
    body.light-mode .contents-backdrop{
        background: rgba(0,0,0,0.25);
    }

    /* Optional: ensure the Close button is readable in light mode */
    body.light-mode .contents-drawer .hdr-btn{
        border: 1px solid rgba(0,0,0,0.16);
        background: rgba(0,0,0,0.03);
        color: rgba(0,0,0,0.92);
    }
    body.light-mode .contents-drawer .hdr-btn:hover{
        background: rgba(0,0,0,0.06);
    }



    /* Section strip (micro) */
    #section-strip{
    position: relative !important;
    top: auto !important;
    z-index: 998;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border-bottom: none;
    }
    body.light-mode #section-strip{ background: rgba(255,255,255,0.88); }
    body.dark-mode  #section-strip{ background: rgba(18,18,18,0.80); }

    .section-strip-inner{
    display: flex;
    gap: 10px;
    align-items: center;
    overflow-x: auto;
    white-space: nowrap;
    padding: 2px 14px;
    scrollbar-width: thin;
    }
    .section-strip-inner::-webkit-scrollbar{ height: 6px; }
    .section-strip-inner::-webkit-scrollbar-thumb{ border-radius: 999px; }
    body.light-mode .section-strip-inner::-webkit-scrollbar-thumb{ background: rgba(0,0,0,0.18); }
    body.dark-mode  .section-strip-inner::-webkit-scrollbar-thumb{ background: rgba(255,255,255,0.18); }

    .section-link{
    text-decoration: none;
    font-size: 11.5px;
    opacity: 0.72;
    padding: 2px 0;
    border-bottom: 1px solid transparent;
    }
    .section-link:hover{ opacity: 0.95; }
    .section-link.active{
    opacity: 1;
    border-bottom-color: currentColor;
    }
    .section-sep{ opacity: 0.22; }


    /* Make native form popups prefer the active color scheme */
    body.dark-mode {
        color-scheme: dark;
    }

    body.light-mode {
        color-scheme: light;
    }


    body.light-mode .section-link{ color: rgba(0,0,0,0.88); }
    body.dark-mode  .section-link{ color: rgba(255,255,255,0.88); }
    body.light-mode .section-link.active{ color: rgba(0,0,0,0.95); }
    body.dark-mode  .section-link.active{ color: rgba(255,255,255,0.95); }
    body.light-mode .section-sep{ color: rgba(0,0,0,0.55); }
    body.dark-mode  .section-sep{ color: rgba(255,255,255,0.55); }

    /* Make anchors work with the new fixed stack */
    h2{ scroll-margin-top: var(--report-header-offset, 120px); }
    thead tr:first-child th{ top: var(--report-header-offset, 120px); }
    details{ scroll-margin-top: var(--report-header-offset, 120px); }

</style>
"@

$global:GLOBALJavaScript = $global:GLOBALJavaScript_Table + "`n" + $global:GLOBALJavaScript_Nav

$global:GLOBALReportManifestScript = ''

############################## Internal function section ########################

# Check if MS Graph is authenticated; if not, call the function for interactive sign-in
function EnsureAuthMsGraph {
    $result = $false
    if (AuthCheckMSGraph) {
        write-host "[+] MS Graph session OK"
        $result = $true
        
    } else {
        if (AuthenticationMSGraph) {
            write-host "[+] MS Graph successfully authenticated"
            $result = $true
        } else {
            if (-not $GLOBALAuthParameters['Tenant']) {write-host "[i] Maybe try to specify the tenant: -Tenant"}
            Write-host "[!] Aborting"
            $result = $false
            
        }
    }
    Return $result
}


# Check if ARM API authentication worked. If not, call the function for interactive sign-in
function EnsureAuthAzurePsNative {
    if (AuthCheckAzPSNative) {
        write-host "[+] Azure PS Session OK"
        $result = $true
    } else {
        if (AuthenticationAzurePSNative) {
            write-host "[+] Azure PS successfully authenticated"
            $result = $true
        } else {
            $result = $false
        }
    }
    return $result
}

#Function to check if a valid MS Graph session exists
function AuthCheckMSGraph {
    $result = $true
    Write-host "[*] Checking session MS Graph"
    if ($null -ne $GLOBALMsGraphAccessToken.access_token) {
        try {
            Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/organization?$select=id' -erroraction Stop -UserAgent $($GlobalAuditSummary.UserAgent.Name) | out-null
        } catch {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
            $result = $false
        }
    } else {
        Write-host "[i] Not yet authenticated"
        $result = $false
    }
    return $result
}
#Get basic tenant info
function Get-OrgInfo {
    $QueryParameters = @{
        '$select' = "Id,DisplayName"
    }
    $OrgInfo = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/organization" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    return $OrgInfo
}

#Get information if users are MFA capable
function Get-RegisterAuthMethodsUsers {
    # Requires Premium otherwise HTTP 403:Tenant is not a B2C tenant and doesn't have premium license
    write-host "[*] Retrieve users registered auth methods"

    $QueryParameters = @{
        '$select' = "Id,IsMfaCapable"
        '$top' = "3000"
    }
    try {
        $RegisteredAuthMethods = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/reports/authenticationMethods/userRegistrationDetails" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
    } catch {
        if ($($_.Exception.Message) -match "Status: 403") {
            write-host "[!] HTTP 403 Error: Most likely due to missing Entra ID premium licence. Can't retrieve users auth methods."
        } else {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Can't retrieve users auth methods."
        }
    }
    
    #Convert to HT
    $UserAuthMethodsTable = @{}
    foreach ($method in $RegisteredAuthMethods ) {
        $UserAuthMethodsTable[$method.Id] = $method.IsMfaCapable
    }

    Write-Log -Level Verbose -Message "Got $($UserAuthMethodsTable.Count) auth methods"

    return $UserAuthMethodsTable
}

#Get all Users
function Get-UsersBasic {
    Param (
        [Parameter(Mandatory = $true)][int]$ApiTop
    )

     write-host "[*] Retrieve basic user list"

    $QueryParameters = @{
        '$select' = "Id,UserPrincipalName,UserType,accountEnabled,onPremisesSyncEnabled"
        '$top' = $ApiTop
      }
      $RawResponse = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $AllUsersBasicHT = @{}
    foreach ($user in $RawResponse) {
        $AllUsersBasicHT[$user.id] = $user
    }
    Write-Log -Level Verbose -Message "Got $($AllUsersBasicHT.count) users"
    return $AllUsersBasicHT
}

#Get Basic User Infos
function Get-Devices {
    Param (
        [Parameter(Mandatory = $true)][int]$ApiTop
    )
     write-host "[*] Retrieve devices"

    $QueryParameters = @{
        '$select' = "Id,accountEnabled,displayName,Manufacturer,trustType,operatingSystem,operatingSystemVersion"
        '$top' = $ApiTop
    }

    $DevicesRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/devices" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    
    #Convert to HT
    $Devices = @{}
    foreach ($device in $DevicesRaw) {
        $Devices[$device.Id] = $device
    }

    Write-Log -Level Verbose -Message "Got $($Devices.Count) devices "
    
    return $Devices
}

function AuthCheckAzPSNative {
    $result = $true
    Write-host "[*] Checking access to ARM API"
    if ($null -ne $GLOBALArmAccessToken.access_token) {
        try {
            $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
            $headers = @{   
                'Authorization' = "Bearer $($GLOBALArmAccessToken.access_token)"
                'User-Agent' = $($GlobalAuditSummary.UserAgent.Name)
            }
            Invoke-RestMethod -Uri $url -Method GET -Headers $headers -erroraction 'Stop'
        } catch {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
            $result = $false
        }
    } else {
        Write-host "[i] Not yet authenticated"
        $result = $false
    }
    return $result
}


function checkSubscriptionNative {
    $result = $true

    $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    $headers = @{   
        'Authorization' = "Bearer $($GLOBALArmAccessToken.access_token)"
        'User-Agent' = $($GlobalAuditSummary.UserAgent.Name)
    }
    $Subscription = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -erroraction 'Stop'

    if ($Subscription.count.value -gt 0) {
        write-host "[+] User has access to $($Subscription.count.value) Subscription(s)."
        $GlobalAuditSummary.Subscriptions.Count = $Subscription.count.value
    } else {
        write-host "[-] User does not have access to a Subscription."
        $result = $false
    }
    return $result
}

#Function to perform MSGraph authentication using EntraTokenAid
function AuthenticationMSGraph {
    if (-not (invoke-EntraFalconAuth -Action Auth -Purpose MainAuth @GLOBALAuthMethods)) {
        throw "[!] Authentication failed for MainAuth"
    }

    if (AuthCheckMSGraph) {
        $result = $true
    } else {
        write-host "[!] Authentication failed (MS Graph)"
        $result = $false
    }

    return $result
}


function AuthenticationAzurePSNative {
   
    #Get tokens for Azure ARM API
    invoke-EntraFalconAuth -Action Auth -Purpose Azure @GLOBALAuthMethods
    if (AuthCheckAzPSnative) {
        $result = $true
    } else {
        write-host "[!] Authentication failed (ARM API)"
        $result = $false
    }

return $result
}

#Refresh MS Graph session
function RefreshAuthenticationMsGraph {
    $result = $true
    invoke-EntraFalconAuth -Action Refresh -Purpose MainAuth @GLOBALAuthMethods

    if (AuthCheckMSGraph) {
        $result = $true
    } else {
        write-host "[!] Refresh failed"
        $result = $false
    }

    return $result
}

function Invoke-CheckTokenExpiration ($Object) {
    #write-host "[*] Checking access token expiration... $($Object.Target)"
    $validForMinutes = [Math]::Ceiling((NEW-TIMESPAN -Start (Get-Date) -End $Object.Expiration_time).TotalMinutes)

    #Check if the token is valid for more than 15 minutes
    if ($validForMinutes -ge 30) {
        #write-host "[+] Token is still valid for $validForMinutes minutes"
        $result = $true

    } elseif ($validForMinutes -le 30 -and $validForMinutes -ge 0) {
        write-host "[!] Access token will expire in $validForMinutes minutes"
        $result = $false   
    } else {
        write-host "[!] Access token has expired $([Math]::Abs($validForMinutes)) minutes ago"
        $result = $false
    }
    return $result

}

#Rough Entra role rating (Tier level per role)
$global:GLOBALEntraRoleRating = @{
    "62e90394-69f5-4237-9190-012177145e10" = 0 #Global Administrator
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = 0 #Partner Tier2 Support
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = 0 #Privileged Authentication Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = 0 #Privileged Role Administrator
    "8329153b-31d0-4727-b945-745eb3bc5f31" = 0 #Domain Name Administrator
    "be2f45a1-457d-42af-a067-6ec1fa63bc45" = 0 #External Identity Provider Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = 0 #Hybrid Identity Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = 0 #Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7" = 0 #Cloud Application Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = 1 #Security Administrator
    "d29b2b05-8046-44ba-8758-1e26182fcf32" = 1 #Directory Synchronization Accounts
    "a92aed5d-d78a-4d16-b381-09adb37eb3b0" = 1 #On Premises Directory Sync Account
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = 1 #Conditional Access Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" = 1 #Authentication Administrator
    "e3973bdf-4987-49ae-837a-ba8e231c7286" = 1 #Azure DevOps Administrator
    "9360feb5-f418-4baa-8175-e2a00bac4301" = 1 #Directory Writers
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = 1 #Exchange Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c" = 1 #Groups Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = 1 #Helpdesk Administrator
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = 1 #Identity Governance Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5" = 1 #Intune Administrator
    "b5a8dcf3-09d5-43a9-a639-8e29ef291470" = 1 #Knowledge Administrator
    "744ec460-397e-42ad-a462-8b3f9747a02c" = 1 #Knowledge Manager
    "59d46f88-662b-457b-bceb-5c3809e5908f" = 1 #Lifecycle Workflows Administrator
    "4ba39ca4-527c-499a-b93d-d9b492c50246" = 1 #Partner Tier1 Support
    "966707d0-3269-4727-9be2-8c3a10f19b9d" = 1 #Password Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = 1 #SharePoint Administrator
    "69091246-20e8-4a56-aa4d-066075b2a7a8" = 1 #Teams Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = 1 #User Administrator
    "11451d60-acb2-45eb-a7d6-43d0f0125c13" = 1 #Windows 365 Administrator
    "810a2642-a034-447f-a5e8-41beaa378541" = 1 #Yammer Administrator
    "0526716b-113d-4c15-b2c8-68e3c22b9f80" = 2 #Authentication Policy Administrator
    "9f06204d-73c1-4d4c-880a-6edb90606fd8" = 2 #Azure AD Joined Device Local Administrator
    "7698a772-787b-4ac8-901f-60d6b08affd2" = 2 #Cloud Device Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = 2 #Global Reader
    "95e79109-95c0-4d8e-aee3-d01accf2d47b" = 2 #Guest Inviter
    "5d6b6bb7-de71-4623-b4af-96380a352509" = 2 #Security Reader
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = 2 #Directory Readers
}

#Rough Entra role rating (Tier level per role)
$global:GLOBALAzureRoleRating = @{
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" = 0 #Owner
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" = 0 #User Access Administrator
    "b24988ac-6180-42a0-ab88-20f7382dd24c" = 0 #Contributor
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168" = 0 #Role Based Access Control Administrator
    "a8889054-8d42-49c9-bc1c-52486c10e7cd" = 0 #Reservations Administrator
    "fb1c8493-542b-48eb-b624-b4c8fea62acd" = 1 #Security Admin
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c" = 1 #Virtual Machine Contributor
    "66f75aeb-eabe-4b70-9f1e-c350c4c9ad04" = 1 #Virtual Machine Data Access Administrator
    "1c0163c0-47e6-4577-8991-ea5c82e286e4" = 1 #Virtual Machine Administrator Login
    "a6333a3e-0164-44c3-b281-7a577aff287f" = 1 #Windows Admin Center Administrator Login
    "3bc748fc-213d-45c1-8d91-9da5725539b9" = 1 #Container Registry Contributor and Data Access Configuration Administrator
    "00482a5a-887f-4fb3-b363-3b7fe8e74483" = 1 #Key Vault Administrator
    "8b54135c-b56d-4d72-a534-26097cfdc8d8" = 1 #Key Vault Data Access Administrator	
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7" = 1 #Key Vault Secrets Officer
    "4633458b-17de-408a-b874-0445c86b69e6" = 1 #Key Vault Secrets User
    "3498e952-d568-435e-9b2c-8d77e338d7f7" = 1 #Azure Kubernetes Service RBAC Admin
    "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b" = 1 #Azure Kubernetes Service RBAC Cluster Admin
    "dffb1e0c-446f-4dde-a09f-99eb5cc68b96" = 1 #Azure Arc Kubernetes Admin
    "8393591c-06b9-48a2-a542-1bd6b377f6a2" = 1 #Azure Arc Kubernetes Cluster Admin
    "b748a06d-6150-4f8a-aaa9-ce3940cd96cb" = 1 #Azure Arc VMware VM Contributor
    "17d1049b-9a84-46fb-8f53-869881c3d3ab" = 1 #Storage Account Contributor
    "acdd72a7-3385-48ef-bd42-f606fba81ae7" = 2 #Reader
    "39bc4728-0917-49c7-9d2c-d95423bc2eb4" = 2 #SecurityReader
    "fb879df8-f326-4884-b1cf-06f3ad86be52" = 3 #Virtual Machine User Login
    "1d18fff3-a72a-46b5-b4a9-0b38a3cd7e63" = 3 #Desktop Virtualization User
}

$global:GLOBALImpactScore = @{
    "EntraRoleTier0"            = 800
    "EntraRoleTier1"            = 400
    "EntraRoleTier2"            = 80
    "EntraRoleTier?Privileged"  = 100
    "EntraRoleTier?"            = 80
    "AzureRoleTier0"            = 200
    "AzureRoleTier1"            = 100
    "AzureRoleTier2"            = 50
    "AzureRoleTier3"            = 10
    "AzureRoleTier?"            = 50
}

$global:GLOBALApiPermissionCategorizationList= @{
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "Dangerous" #RoleManagement.ReadWrite.Directory
    "06b708a9-e830-4db3-a914-8e69da51d44f" = "Dangerous" #AppRoleAssignment.ReadWrite.All
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Dangerous" #Application.ReadWrite.All
    "dd199f4a-f148-40a4-a2ec-f0069cc799ec" = "Dangerous" #RoleAssignmentSchedule.ReadWrite.Directory
    "41202f2c-f7ab-45be-b001-85c9728b9d69" = "Dangerous" #PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup
    "2f6817f8-7b12-4f0f-bc18-eeaf60705a9e" = "Dangerous" #PrivilegedAccess.ReadWrite.AzureADGroup
    "fee28b28-e1f3-4841-818e-2704dc62245f" = "Dangerous" #RoleEligibilitySchedule.ReadWrite.Directory
    "618b6020-bca8-4de6-99f6-ef445fa4d857" = "Dangerous" #PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup
    "7e05723c-0bb0-42da-be95-ae9f08a6e53c" = "Dangerous" #Domain.ReadWrite.All
    "fc023787-fd04-4e44-9bc7-d454f00c0f0a" = "Dangerous" #Application.ReadUpdate.All   
    "ab43b826-2c7a-4aff-9ecd-d0629d0ca6a9" = "High" #ADSynchronization.ReadWrite.All
    "9acd699f-1e81-4958-b001-93b1d2506e19" = "High" #EntitlementManagement.ReadWrite.All
    "292d869f-3427-49a8-9dab-8c70152b74e9" = "High" #Organization.ReadWrite.All
    "a402ca1c-2696-4531-972d-6e5ee4aa11ea" = "High" #Policy.ReadWrite.PermissionGrant
    "b38dcc4d-a239-4ed6-aa84-6c65b284f97c" = "High" #RoleManagementPolicy.ReadWrite.AzureADGroup
    "31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad" = "High" #RoleManagementPolicy.ReadWrite.Directory
    "29c18626-4985-4dcd-85c0-193eef327366" = "High" #Policy.ReadWrite.AuthenticationMethod"
    "eccc023d-eccf-4e7b-9683-8813ab36cecc" = "High" #User.DeleteRestore.All
    "3011c876-62b7-4ada-afa2-506cbbecc68c" = "High" #User.EnableDisableAccount.All
    "8e8e4742-1d95-4f68-9d56-6ee75648c72a" = "High" #DelegatedPermissionGrant.ReadWrite.All
    "01c0a623-fc9b-48e9-b794-0756f8e8f067" = "High" #Policy.ReadWrite.ConditionalAccess
    "0e263e50-5827-48a4-b97c-d940288653c7" = "High" #Directory.AccessAsUser.All
    "9241abd9-d0e6-425a-bd4f-47ba86e767a4" = "High" #DeviceManagementConfiguration.ReadWrite.All
    "e330c4f0-4170-414e-a55a-2f022ec2b57b" = "High" #DeviceManagementRBAC.ReadWrite.Al
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "High" #Directory.ReadWrite.All
    "62a82d76-70ea-41e2-9197-370581804d09" = "High" #Group.ReadWrite.All
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" = "High" #GroupMember.ReadWrite.All
    "50483e42-d915-4231-9639-7fdb7fd190e5" = "High" #UserAuthenticationMethod.ReadWrite.All
    "cc117bb9-00cf-4eb8-b580-ea2a878fe8f7" = "High" #User-PasswordProfile.ReadWrite.All    
    "a82116e5-55eb-4c41-a434-62fe8a61c773" = "High" #Sites.FullControl.All
    "678536fe-1083-478a-9c59-b99265e6b0d3" = "High" #Sites.FullControl.All SharePointAPI
    "9bff6588-13f2-4c48-bbf2-ddab62256b36" = "High" #Sites.Manage.All SharePointAPI
    "d13f72ca-a275-4b96-b789-48ebcc4da984" = "High" #Sites.Read.All SharePointAPI
    "fbcd29d2-fcca-4405-aded-518d457caae4" = "High" #Sites.ReadWrite.All SharePointAPI
    "0c0bf378-bf22-4481-8f81-9e89a9b4960a" = "High" #Sites.Manage.All
    "332a536c-c7ef-4017-ab91-336970924f0d" = "High" #Sites.Read.All
    "9492366f-7969-46a4-8d15-ed1a20078fff" = "High" #Sites.ReadWrite.All
    "01d4889c-1287-42c6-ac1f-5d1e02578ef6" = "High" #Files.Read.All
    "75359482-378d-4052-8f01-80520e7db3cd" = "High" #Files.ReadWrite.All
    "db51be59-e728-414b-b800-e0f010df1a79" = "High" #DeviceLocalCredential.Read.All
    "5eb59dd3-1da2-4329-8733-9dabdc435916" = "High" #AdministrativeUnit.ReadWrite.All
    "7e9ebcc1-90aa-4471-8051-e68d6b4e9c89" = "High" #UserAuthMethod-HardwareOATH.ReadWrite.All
    "6e85d483-7092-4375-babe-0a94a8213a58" = "High" #UserAuthMethod-Phone.ReadWrite.All
    "4869299f-18c3-40c8-98f2-222657e67db1" = "High" #UserAuthMethod-QR.ReadWrite.All
    "627169a8-8c15-451c-861a-5b80e383de5c" = "High" #UserAuthMethod-TAP.ReadWrite.All
    "741f803b-c850-494e-b5df-cde7c675a1ca" = "Medium" #User.ReadWrite.All
    "18a4783c-866b-4cc7-a460-3d5e5662c884" = "Medium" #Application.ReadWrite.OwnedBy
    "6b7d71aa-70aa-4810-a8d9-5d9fb2830017" = "Medium" #Chat.Read.All
    "294ce7c9-31ba-490a-ad7d-97a7d075e4ed" = "Medium" #Chat.ReadWrite.All
    "ef54d2bf-783f-4e0f-bca1-3210c0444d99" = "Medium" #Calendars.ReadWrite
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Medium" #Mail.Read
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Medium" #Mail.ReadWrite
    "b633e1c5-b582-4048-a93e-9f11b44c7e96" = "Medium" #Mail.Send
    "b8bb2037-6e08-44ac-a4ea-4674e010e2a4" = "Medium" #OnlineMeetings.ReadWrite.All  
    "de89b5e4-5b8f-48eb-8925-29c2b33bd8bd" = "Medium" #CustomSecAttributeAssignment.ReadWrite.All
    "89c8469c-83ad-45f7-8ff2-6e3d4285709e" = "Medium" #ServicePrincipalEndpoint.ReadWrite.All (Still an issue?)
}

$global:GLOBALDelegatedApiPermissionCategorizationList= @{
    "RoleManagement.ReadWrite.Directory" = "Dangerous" #d01b97e9-cbc0-49fe-810a-750afd5527a3
    "AppRoleAssignment.ReadWrite.All" = "Dangerous" #84bccea3-f856-4a8a-967b-dbe0a3d53a64
    "Application.ReadWrite.All" = "Dangerous" #bdfbf15f-ee85-4955-8675-146e8e5296b5
    "RoleAssignmentSchedule.ReadWrite.Directory" = "Dangerous" #8c026be3-8e26-4774-9372-8d5d6f21daff
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup" = "Dangerous" #06dbc45d-6708-4ef0-a797-f797ee68bf4b
    "PrivilegedAccess.ReadWrite.AzureADGroup" = "Dangerous" #32531c59-1f32-461f-b8df-6f8a3b89f73b
    "RoleEligibilitySchedule.ReadWrite.Directory" = "Dangerous" #62ade113-f8e0-4bf9-a6ba-5acb31db32fd
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup" = "Dangerous" #ba974594-d163-484e-ba39-c330d5897667
    "Domain.ReadWrite.All" = "Dangerous" #0b5d694c-a244-4bde-86e6-eb5cd07730fe
    "Application.ReadUpdate.All" = "Dangerous" #0586a906-4d89-4de8-b3c8-1aacdcc0c679
    "EntitlementManagement.ReadWrite.All" = "High" #ae7a573d-81d7-432b-ad44-4ed5c9d89038
    "Organization.ReadWrite.All" = "High" #46ca0847-7e6b-426e-9775-ea810a948356
    "Policy.ReadWrite.PermissionGrant" = "High" #2672f8bb-fd5e-42e0-85e1-ec764dd2614e
    "RoleManagementPolicy.ReadWrite.AzureADGroup" = "High" #0da165c7-3f15-4236-b733-c0b0f6abe41d
    "RoleManagementPolicy.ReadWrite.Directory" = "High" #1ff1be21-34eb-448c-9ac9-ce1f506b2a68
    "Policy.ReadWrite.AuthenticationMethod" = "High" #7e823077-d88e-468f-a337-e18f1f0e6c7c
    "User.DeleteRestore.All" = "High" #4bb440cd-2cf2-4f90-8004-aa2acd2537c5
    "User.EnableDisableAccount.All" = "High" #f92e74e7-2563-467f-9dd0-902688cb5863
    "DelegatedPermissionGrant.ReadWrite.All" = "High" #41ce6ca6-6826-4807-84f1-1c82854f7ee5
    "Policy.ReadWrite.ConditionalAccess" = "High" #ad902697-1014-4ef5-81ef-2b4301988e8c
    "DeviceManagementConfiguration.ReadWrite.All" = "High" #0883f392-0a7a-443d-8c76-16a6d39c7b63
    "DeviceManagementRBAC.ReadWrite.All" = "High" #0c5e8a55-87a6-4556-93ab-adc52c4d862d
    "Directory.ReadWrite.All" = "High" #c5366453-9fb0-48a5-a156-24f0c49a4b84
    "User-PasswordProfile.ReadWrite.All" = "High" #56760768-b641-451f-8906-e1b8ab31bca7
    "Group.ReadWrite.All" = "High" #4e46008b-f24c-477d-8fff-7bb4ec7aafe0
    "GroupMember.ReadWrite.All" = "High" #f81125ac-d3b7-4573-a3b2-7099cc39df9e
    "UserAuthenticationMethod.ReadWrite.All" = "High" #b7887744-6746-4312-813d-72daeaee7e2d
    "Sites.FullControl.All" = "High" #5a54b8b3-347c-476d-8f8e-42d5c7424d29
    "Sites.Manage.All" = "High" #65e50fdc-43b7-4915-933e-e8138f11f40a
    "Sites.Read.All" = "High" #205e70e5-aba6-4c52-a976-6d2d46c48043
    "Sites.ReadWrite.All" = "High" #89fe6a52-be36-487e-b7d8-d061c450a026
    "Files.Read.All" = "High" #df85f4d6-205c-4ac5-a5ea-6bf408dba283
    "Files.ReadWrite.All" = "High" #863451e7-0667-486c-a5d6-d135439485f0
    "DeviceLocalCredential.Read.All" = "High" #9917900e-410b-4d15-846e-42a357488545
    "AdministrativeUnit.ReadWrite.All" = "High" #7b8a2d34-6b3f-4542-a343-54651608ad81
    "User.ReadWrite.All" = "Medium" #204e0828-b5ca-4ad8-b9f3-f32a958e7cc4
    "Chat.ReadWrite.All" = "Medium" #7e9a077b-3711-42b9-b7cb-5fa5f3f7fea7
    "Mail.Read" = "Medium" #570282fd-fa5c-430d-a7fd-fc8dc98a9dca
    "Mail.ReadWrite" = "Medium" #024d486e-b451-40bb-833d-3e66d98c5c73
    "Mail.Send" = "Medium" #e383f46e-2787-4529-855e-0e479a3ffac0
    "CustomSecAttributeAssignment.ReadWrite.All" = "Medium" #ca46335e-8453-47cd-a001-8459884efeae
    "ServicePrincipalEndpoint.ReadWrite.All" = "Medium" #7297d82c-9546-4aed-91df-3d4f0a9b3ff0
    "BitlockerKey.Read.All" = "Medium" #b27a61ec-b99c-4d6a-b126-c4375d08ae30
    "Calendars.Read" = "Medium" #465a38f9-76ea-45b9-9f34-9e8b0d4b0b42
    "Calendars.Read.Shared" = "Medium" #2b9c4092-424d-4249-948d-b43879977640
    "Calendars.ReadWrite" = "Medium" #1ec239c2-d7c9-4623-a91a-a9775856bb36
    "Calendars.ReadWrite.Shared" = "Medium" #12466101-c9b8-439a-8589-dd09ee67e8e9
    "ChannelMessage.ReadWrite" = "Medium" #5922d31f-46c8-4404-9eaf-2117e390a8a4
    "ChannelMessage.Send" = "Medium" #ebf0f66e-9fb1-49e4-a278-222f76911cf4
    "Chat.ReadWrite" = "Medium" #9ff7295e-131b-4d94-90e1-69fde507ac11
    "Directory.AccessAsUser.All" = "Medium" #0e263e50-5827-48a4-b97c-d940288653c7
    "Directory.Read.All" = "Medium" #06da0dbc-49e2-44d2-8312-53f166ab848a
    "Files.ReadWrite" = "Medium" #5c28f0bf-8a70-41f1-8ab2-9032436ddb65
    "MailboxItem.ImportExport" = "Medium" #df96e8a0-f4e1-4ecf-8d83-a429f822cbd6
    "offline_access" = "Medium" #7427e0e9-2fba-42fe-b0c0-848c9e6a8182
    "openid" = "Low" #37f7f235-527c-4136-accd-4a02d197296e
    "email" = "Low" #64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0
    "profile" = "Low" #14dad69e-099b-42c9-810b-d002981feec1
    "User.Read" = "Low" #14dad69e-099b-42c9-810b-d002981feec1
}

#Store the MS Tenant IDs in an array to check if an Enterprise Application is a Microsoft app
$global:GLOBALMsTenantIds = @("f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47", "33e01921-4d64-4f8c-a055-5bdaffd5e33d", "cdc5aeea-15c5-4db6-b079-fcadd2505dc2")

#Function to rate Entra ID role assignments and generate the warning message
function Invoke-EntraRoleProcessing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RoleDetails
    )

        #Process Entra Role assignments
        $ImpactScore = 0
        $Tier0Count = 0
        $Tier1Count = 0
        $Tier2Count = 0
        $UnknownTierCount = 0
        $roleSummary = ""
        
        foreach ($Role in $RoleDetails) {
            switch ($Role.RoleTier) {
                0 {
                    $ImpactScore += $GLOBALImpactScore["EntraRoleTier0"]
                    $Tier0Count++
                    break
                }
                1 {
                    $ImpactScore += $GLOBALImpactScore["EntraRoleTier1"]
                    $Tier1Count++
                    break
                }
                2 {
                    $ImpactScore += $GLOBALImpactScore["EntraRoleTier2"]
                    $Tier2Count++
                    break
                }
                default {
                    $UnknownTierCount++
                    if ($Role.IsPrivileged) {
                        $ImpactScore += $GLOBALImpactScore["EntraRoleTier?Privileged"]
                    } else {
                        $ImpactScore += $GLOBALImpactScore["EntraRoleTier?"]
                    }
                    break
                }
            }
        }
        
        # Build role description parts
        $roleParts = @()
        if ($Tier0Count -ge 1) { $roleParts += "$Tier0Count (Tier0)" }
        if ($Tier1Count -ge 1) { $roleParts += "$Tier1Count (Tier1)" }
        if ($Tier2Count -ge 1) { $roleParts += "$Tier2Count (Tier2)" }
        if ($UnknownTierCount -ge 1) { $roleParts += "$UnknownTierCount (Tier?)" }
        if (($Tier0Count + $Tier1Count + $Tier2Count + $UnknownTierCount) -ge 2) {
            $word = "roles"
        } else {
            $word = "role"
        }
        # If not already handled, create summary
        if ($roleParts.Count -gt 0) {
            $roleSummary = ($roleParts -join ", ") + " Entra "+$word+" assigned"
        }
        
        return [PSCustomObject]@{
            ImpactScore = $ImpactScore
            Warning     = $roleSummary
        }
}

#Function to rate Entra ID role assignments and generate the warning message
function Invoke-AzureRoleProcessing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RoleDetails
    )

        #Process Entra Role assignments
        $ImpactScore = 0
        $Tier0Count = 0
        $Tier1Count = 0
        $Tier2Count = 0
        $Tier3Count = 0
        $UnknownTierCount = 0
        $roleSummary = ""
        
        foreach ($Role in $RoleDetails) {
            switch ($Role.RoleTier) {
                0 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier0"]
                    $Tier0Count++
                    break
                }
                1 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier1"]
                    $Tier1Count++
                    break
                }
                2 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier2"]
                    $Tier2Count++
                    break
                }
                3 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier3"]
                    $Tier3Count++
                    break
                }
                default {
                    $UnknownTierCount++
                    if ($Role.IsPrivileged) {
                        $ImpactScore += $GLOBALImpactScore["AzureRoleTier?Privileged"]
                    } else {
                        $ImpactScore += $GLOBALImpactScore["AzureRoleTier?"]
                    }
                    break
                }
            }
        }
        
        # Build role description parts
        $roleParts = @()
        if ($Tier0Count -ge 1) { $roleParts += "$Tier0Count (Tier0)" }
        if ($Tier1Count -ge 1) { $roleParts += "$Tier1Count (Tier1)" }
        if ($Tier2Count -ge 1) { $roleParts += "$Tier2Count (Tier2)" }
        if ($Tier3Count -ge 1) { $roleParts += "$Tier3Count (Tier3)" }
        if ($UnknownTierCount -ge 1) { $roleParts += "$UnknownTierCount (Tier?)" }
        if (($Tier0Count + $Tier1Count + $Tier2Count + $UnknownTierCount) -ge 2) {
            $word = "roles"
        } else {
            $word = "role"
        }
        # If not already handled, create summary
        if ($roleParts.Count -gt 0) {
            $roleSummary = ($roleParts -join ", ") + " Azure "+$word+" assigned"
        }
        
        return [PSCustomObject]@{
            ImpactScore = $ImpactScore
            Warning     = $roleSummary
        }
}


# Function to get Azure IAM assignments
function Get-AllAzureIAMAssignmentsNative {
    [CmdletBinding()]
    param()

    Write-Host "[*] Get Azure IAM assignments"

    $IamAssignmentsHT = @{}
    $assignmentsEligible = @()
    $seenAssignments = New-Object System.Collections.Generic.HashSet[System.String]
    $headers = @{   
        'Authorization' = "Bearer $($GLOBALArmAccessToken.access_token)"
        'User-Agent' = $($GlobalAuditSummary.UserAgent.Name)
    }

    #Retrieve role assignments for each subscription and filter by scope
    $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -erroraction 'Stop'
    $subscriptions = $response.value | ForEach-Object {
        [PSCustomObject]@{
            Id          = $_.subscriptionId
            displayName  = $_.displayName
            managedByTenants  = $_.managedByTenants
        }
    }

    foreach ($sub in $subscriptions) {
        $managedTenantCount = if ($null -ne $sub.ManagedByTenants) {
            @($sub.ManagedByTenants).Count
        } else {
            0
        }
        Write-Log -Level Debug -Message "Subscription $($sub.DisplayName) $($sub.Id) | ManagedByTenants: $managedTenantCount"
    }

    #Get all Azure roles for lookup
    $url = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
    $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
    $roleHashTable = @{}
    $response.value | ForEach-Object {
        # Extract RoleName and ObjectId
        $roleName = $_.properties.RoleName
        $RoleType = $_.properties.type
        $objectId = ($_.id -split '/')[-1]
    
        # Store the values in the hashtable (ObjectId as the key, RoleName as the value)
        $roleHashTable[$objectId] = @{
            RoleName = $roleName
            RoleType = $roleType
            RoleId   = $objectId
        }
    }

    #Get all custom roles and add them to the HT
    $url = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?`$filter=type+eq+'CustomRole'&api-version=2022-04-01"
    $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers

    $response.value | ForEach-Object {
        # Extract RoleName and ObjectId
        $roleName = $_.properties.RoleName
        $RoleType = $_.properties.type
        $objectId = ($_.id -split '/')[-1]
    
        # Store the values in the hashtable (ObjectId as the key, RoleName as the value)
        $roleHashTable[$objectId] = @{
            RoleName = $roleName
            RoleType = $roleType
            RoleId   = $objectId
        }
    }
    Write-Log -Level Debug -Message "Got $($roleHashTable.count) role definitions"


    foreach ($subscription in $subscriptions) {       
        #Active Roles
        $url = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
        $AssignmentsActive = $response.value | ForEach-Object {
            $roleId = ($_.properties.roleDefinitionId -split '/')[-1]

            # Null safe check
            if (-not $roleHashTable.ContainsKey($roleId)) {
                Write-Host-Message "[!] Skipping unknown RoleId: $roleId"
                return
            }
            $RoleDetails = $roleHashTable[$roleId]
            $hasCondition = ($null -ne $_.properties.condition -and $_.properties.condition.Trim() -ne "")


            if ($GLOBALAzureRoleRating.ContainsKey($RoleDetails.RoleId)) {
                # If the RoleDefinition ID is found, return it's Tier-Level
                $RoleTier = $GLOBALAzureRoleRating[$RoleDetails.RoleId]
            } else {
                # Set to ? if not assigned to a tier level
                $RoleTier = "?"
            }
            [PSCustomObject]@{
                ObjectId           = $_.properties.principalId
                RoleDefinitionName = $RoleDetails.RoleName
                RoleType           = $RoleDetails.RoleType
                RoleTier           = $RoleTier
                Scope              = $_.properties.scope
                Conditions         = $hasCondition 
                PrincipalType      = $_.properties.principalType
                AssignmentType     = "Active"
            }
        }
        Write-Log -Level Debug -Message "Got $($AssignmentsActive.count) active role assignments"

        #Eligible Roles
        # If HTTP 400 assuing error message is "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
        $AzurePIM = $true
        try {
            Write-Log -Level Debug -Message "Checking PIM assignments for subscription $($subscription.Id)"
            $url = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01-preview"
            $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
        } catch {
            if ($($_.Exception.Message) -match "400") {
                write-host "[!] HTTP 400 Error: Most likely due to missing Entra ID premium licence. Assuming no PIM for Azure is used."
            } else {
                write-host "[!] Auth error: $($_.Exception.Message)"
            }
            $AzurePIM = $false
        }
        $AssignmentsEligible = @()
        if ($AzurePIM) {
            $AssignmentsEligible = $response.value | ForEach-Object {
                $RoleDetails = $roleHashTable[(($_.properties.roleDefinitionId -split '/')[-1])]
                $hasCondition = ($null -ne $_.properties.condition -and $_.properties.condition.Trim() -ne "")
                if ($GLOBALAzureRoleRating.ContainsKey($RoleDetails.RoleId)) {
                    # If the RoleDefinition ID is found, return it's Tier-Level
                    $RoleTier = $GLOBALAzureRoleRating[$RoleDetails.RoleId]
                } else {
                    # Set to ? if not assigned to a tier level
                    $RoleTier = "?"
                }
                [PSCustomObject]@{
                    ObjectId          = $_.properties.principalId
                    RoleDefinitionName = $RoleDetails.RoleName
                    RoleType           = $RoleDetails.RoleType
                    RoleTier           = $RoleTier
                    Scope              = $_.properties.scope
                    Conditions         = $hasCondition 
                    PrincipalType      = $_.properties.principalType
                    AssignmentType     = "Eligible"
                }
            }
            Write-Log -Level Debug -Message "Got $($AssignmentsEligible.count) eligible role assignments"
        }
   
        $AllAssignments = @($AssignmentsActive) + @($AssignmentsEligible)

        foreach ($assignment in $AllAssignments) {
            # Create a unique key for each role assignment
            $uniqueKey = "$($assignment.ObjectId)|$($assignment.RoleDefinitionName)|$($assignment.Scope)|$($assignment.AssignmentType)"

            # Check if the role assignment has already been processed
            if (-not $seenAssignments.Contains($uniqueKey)) {
                # Add the key to the HashSet to mark it as seen
                $seenAssignments.Add($uniqueKey) | Out-Null

                # Ensure the ObjectId exists in the hashtable
                if (-not $IamAssignmentsHT.ContainsKey($assignment.ObjectId)) {
                    $IamAssignmentsHT[$assignment.ObjectId] = @()
                }

                # Add the assignment to the hashtable
                $IamAssignmentsHT[$assignment.ObjectId] += [PSCustomObject]@{
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    Scope = $assignment.Scope
                    RoleType = $assignment.RoleType
                    RoleTier = $assignment.RoleTier
                    Conditions = $assignment.Conditions
                    PrincipalType = $assignment.PrincipalType
                    AssignmentType = $assignment.AssignmentType
                }
            }
        }
    }

    return $IamAssignmentsHT
}

# Function to check the Azure IAM role assignments for the input object
function Get-AzureRoleDetails {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory = $true)]
        [string]$ObjectId
    )

    $azureRoleDetails = @()

    # Filtering assignments based on ObjectType and the associated IDs
    if ($AzureIAMAssignments.ContainsKey($ObjectId)) {
        # Key exists, retrieve its value
        $matchingAzureRoles = $AzureIAMAssignments[$ObjectId]
        foreach ($role in $matchingAzureRoles) {
            $roleInfo = [PSCustomObject]@{
                RoleName = $role.RoleDefinitionName
                RoleType = $role.RoleType
                Scope    = $role.Scope
                Conditions = $role.Conditions
                RoleTier = $role.RoleTier
                AssignmentType  = $role.AssignmentType
            }
            $azureRoleDetails += $roleInfo
        }
    }

    return $azureRoleDetails
}


# Function to get user details for PIM fro groups eligible assignments
function Get-PIMForGroupsAssignmentsDetails {
    param (
        [Parameter(Mandatory = $true)]
        [array]$TenantPimForGroupsAssignments
    )

    foreach ($item in $TenantPimForGroupsAssignments) {

        $principalId = $item.principalId
        
        # Lookup displayname and object type for each object
        $ObjectInfo = Get-ObjectInfo $principalId

        if ($ObjectInfo) {
            # Add properties to the matching entry
            $TenantPimForGroupsAssignments | ForEach-Object {
                if ($_.principalId -eq $principalId) {
                    $_ | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $ObjectInfo.DisplayName -Force
                    $_ | Add-Member -MemberType NoteProperty -Name "Type" -Value $ObjectInfo.Type -Force
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'UserPrincipalName') {$_ | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $ObjectInfo.UserPrincipalName -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'AccountEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "AccountEnabled" -Value $ObjectInfo.AccountEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'UserType') {$_ | Add-Member -MemberType NoteProperty -Name "UserType" -Value $ObjectInfo.UserType -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'OnPremisesSyncEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "OnPremisesSyncEnabled" -Value $ObjectInfo.OnPremisesSyncEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'Department') {$_ | Add-Member -MemberType NoteProperty -Name "Department" -Value $ObjectInfo.Department -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'JobTitle') {$_ | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value $ObjectInfo.JobTitle -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'SecurityEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "SecurityEnabled" -Value $ObjectInfo.SecurityEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'IsAssignableToRole') {$_ | Add-Member -MemberType NoteProperty -Name "IsAssignableToRole" -Value $ObjectInfo.IsAssignableToRole -Force}
                }
            }
        }
    }
    return $TenantPimForGroupsAssignments
}

# Function to get all administrative units
function Get-AdministrativeUnitsWithMembers {
    Write-Host "[*] Get Administrative units with members"
    $QueryParameters = @{
        '$select' = "Id,DisplayName,IsMemberManagementRestricted"
    }
    $AdminUnits = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $AdminUnitWithMembers = foreach ($AdminUnit in $AdminUnits) {

        # Retrieve members of the current administrative unit
        $Members = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits/$($AdminUnit.Id)/members" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

        $MembersUser = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user'} | Select-Object id,@{n='Type';e={'User'}},displayName
        $MembersGroup = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group'}  | Select-Object id,@{n='Type';e={'Group'}},displayName
        $MembersDevices = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device'} | Select-Object id,@{n='Type';e={'Device'}},displayName
    
        # Create a custom object for the administrative unit with its members
        [pscustomobject]@{
            AuId                            = $AdminUnit.Id
            DisplayName                     = $AdminUnit.Displayname
            IsMemberManagementRestricted    = $AdminUnit.IsMemberManagementRestricted
            MembersUser                     = $MembersUser
            MembersGroup                    = $MembersGroup
            MembersDevices                  = $MembersDevices
        }
    }

    $AuCount = $($AdminUnitWithMembers | Measure-Object).Count

    #Add information to the enumeration summary
    $GlobalAuditSummary.AdministrativeUnits.Count = $AuCount

    Write-Host "[+] Got $AuCount Administrative units with members"
    Return $AdminUnitWithMembers
}

# Get Conditional Access Policies with user and group relations
function Get-ConditionalAccessPolicies {

    Write-Host "[*] Get Conditional Access Policies"
    $Caps = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/identity/conditionalAccess/policies" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    if ($Caps) {
        $CapsCount = $($Caps | Measure-Object).Count
        Write-Host "[+] Got $CapsCount Conditional Access Policies"
        $CapGroups = foreach ($cap in $Caps) {
            $excludedGroups = $cap.Conditions.Users.ExcludeGroups
            $includedGroups = $cap.Conditions.Users.IncludeGroups
            $ExcludeUsers = $cap.Conditions.Users.ExcludeUsers
            $IncludeUsers = $cap.Conditions.Users.IncludeUsers
            [PSCustomObject]@{ 
                Id = $cap.Id
                CAPName = $cap.DisplayName
                ExcludedGroup = $excludedGroups
                IncludedGroup = $includedGroups
                ExcludedUser = $ExcludeUsers
                IncludedUser = $IncludeUsers
                CAPStatus = $cap.State
            } 
        }
        $global:GLOBALPermissionForCaps = $true
    } else {
        Write-Host "[!] No Conditional Access Policies found."
        $GroupScriptWarningList += "Coverage gap: Conditional Access group assignments not assessed; CAP links may be missing."
        $global:GLOBALPermissionForCaps = $false
    }
    Return $CapGroups
}

#Authenticate using an refresh token and get a new token for PIM
function Invoke-MsGraphAuthPIM {

    Invoke-EntraFalconAuth -Action Auth -Purpose PimforEntra @GLOBALAuthMethods
    
    #Abort if error
    if ($GLOBALPIMsGraphAccessToken) {
        if (AuthCheckMSGraph) {
            write-host "[+] MS Graph session OK"
            $result = $true
            $global:GLOBALGraphExtendedChecks = $true
            
        } else {
            Write-host "[!] Authentication with Managed Meeting Rooms client failed"
            $result = $false
            $global:GLOBALGraphExtendedChecks = $false
        }
    } else {
        write-host "[!] PIM Data will not be collected"
        $global:GLOBALGraphExtendedChecks = $false
        $result = $false
    }
    return $result
}

#Refresh PIM token
function Invoke-MsGraphRefreshPIM {

    invoke-EntraFalconAuth -Action Refresh -Purpose PimforEntra @GLOBALAuthMethods
    
}


#Get all active Entra role assignments
function Get-EntraPIMRoleAssignments {

    Write-Host "[*] Get PIM Entra role assignments"

    $TenantPIMRoleAssignments = @()

    #Ugly workaround since $_.RoleDefinition.IsPrivileged is always empty :-(
    $EntraroleDefinitions = @{}
    # Get the role definitions and populate the array

    # Get all roleassignments and store as HT
    $QueryParameters = @{
        '$select' = "Id,IsPrivileged"
    }
    $TenantRoleDefinitions= Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleDefinitions" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($role in $TenantRoleDefinitions) {
        $EntraroleDefinitions[$role.Id] = $role.IsPrivileged
    }

    try {
        # Get all PIM for Roles assignments
        $QueryParameters = @{
            '$select' = "PrincipalId,DirectoryScopeId,RoleDefinition,RoleDefinitionId,ScheduleInfo"
            '$expand' = "RoleDefinition"
        }
        $PimRoles = Send-GraphRequest -AccessToken $GLOBALPIMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleEligibilitySchedules" -QueryParameters $QueryParameters -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
    
    } catch {
        if ($($_.Exception.Message) -match "Status: 400") {
            write-host "[!] HTTP 400 Error: Most likely due to missing Entra ID premium licence. Assuming no PIM for Entra roles is used."
        } else {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Assuming no PIM for Entra roles is used."
        }
        #Set global var so that PIM role settigns are NOT checked
        $global:GLOBALPIMForEntraRolesChecked = $false
        Return
    }

    $PimRoles | ForEach-Object {
        $ScopeResolved = $null

        # Resolve the DirectoryScopeId
        if ($_.DirectoryScopeId -eq "/") {
            $ScopeResolved = [PSCustomObject]@{
                DisplayName = "/"
                Type        = "Tenant"
            }
        } elseif ($($_.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $_.DirectoryScopeId.Replace("/administrativeUnits/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID AdministrativeUnit
        } else {
            $ObjectID = $_.DirectoryScopeId.Replace("/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID
        }

        if ($GLOBALEntraRoleRating.ContainsKey($_.RoleDefinition.Id)) {
            # If the RoleDefinition ID is found, return it's Tier-Level
            $RoleTier = $GLOBALEntraRoleRating[$_.RoleDefinition.Id]
        } else {
            # Set to ? if not assigned to a tier level
            $RoleTier = "?"
        }


        # Add the role assignment to the array
        $TenantPIMRoleAssignments += [PSCustomObject]@{
            PrincipalId     = $_.PrincipalId
            AssignmentType  = "Eligible"
            DirectoryScopeId = $_.DirectoryScopeId
            RoleDefinitionId  = $_.RoleDefinition.Id
            DisplayName      = $_.RoleDefinition.DisplayName
            IsPrivileged     = $EntraroleDefinitions[$_.RoleDefinition.Id]
            RoleTier         = $RoleTier
            IsEnabled        = $_.RoleDefinition.IsEnabled
            IsBuiltIn        = $_.RoleDefinition.IsBuiltIn
            StartTime        = $_.ScheduleInfo.StartDateTime
            ExpiryDate       = if ($_.ScheduleInfo.Expiration.EndDateTime) {$_.ScheduleInfo.Expiration.EndDateTime} else {"noExpiration"}
            ScopeResolved    = ($ScopeResolved | select-object DisplayName,Type)
        }

    }

    #Set global var so that PIM role settigns are checked as well
    $global:GLOBALPIMForEntraRolesChecked = $true

    Write-Host "[+] Got $($TenantPIMRoleAssignments.Count) PIM eligible Entra role assignments"
    Return $TenantPIMRoleAssignments
}

#Get all active Entra role assignments
function Get-EntraRoleAssignments {
    param (
        [Parameter(Mandatory = $false)]
        [array]$TenantPimRoleAssignments
    )

    Write-Host "[*] Get Entra role assignments"

    # Create a array to store the role assignments
    $TenantRoleAssignments = @()

    # Get all roleassignments
    $QueryParameters = @{
        '$select' = "PrincipalId,DirectoryScopeId,RoleDefinitionId"
        '$expand' = "RoleDefinition"
    }
    $TenantRoleAssignmentsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleAssignments" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    foreach ($role in $TenantRoleAssignmentsRaw) {
        $ScopeResolved = $null

        # Resolve the DirectoryScopeId
        if ($role.DirectoryScopeId -eq "/") {
            $ScopeResolved = [PSCustomObject]@{
                DisplayName = "/"
                Type        = "Tenant"
            }
        } elseif ($($role.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $role.DirectoryScopeId.Replace("/administrativeUnits/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID AdministrativeUnit
        } else {
            $ObjectID = $role.DirectoryScopeId.Replace("/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID
        }

        if ($GLOBALEntraRoleRating.ContainsKey($role.RoleDefinition.Id)) {
            # If the RoleDefinition ID is found, return it's Tier-Level
            $RoleTier = $GLOBALEntraRoleRating[$role.RoleDefinition.Id]
        } else {
            # Set to ? if not assigned to a tier level
            $RoleTier = "?"
        }

        # Add the role assignment to the array
        $TenantRoleAssignments += [PSCustomObject]@{
            PrincipalId      = $role.PrincipalId
            AssignmentType   = "Active"
            DirectoryScopeId  = $role.DirectoryScopeId
            RoleDefinitionId = $role.RoleDefinition.Id
            DisplayName      = $role.RoleDefinition.DisplayName
            IsPrivileged     = $role.RoleDefinition.IsPrivileged
            RoleTier         = $RoleTier
            IsEnabled        = $role.RoleDefinition.IsEnabled
            IsBuiltIn        = $role.RoleDefinition.IsBuiltIn
            ScopeResolved    = ($ScopeResolved | select-object DisplayName,Type)
        }
    }
    
    Write-Host "[+] Retrieved $($TenantRoleAssignments.Count) role assignments"

    if ($TenantPimRoleAssignments.count -ge 1) {
        Write-Host "[+] Merge with PIM role assignments"
        # Combine both arrays into one
        $TenantRoleAssignments = $TenantRoleAssignments + $TenantPimRoleAssignments
    }

    # Build the hashtable
    $TenantRoleAssignmentsHT = @{}

    foreach ($assignment in $TenantRoleAssignments) {
        $principalId = $assignment.PrincipalId

        if (-not $TenantRoleAssignmentsHT.ContainsKey($principalId)) {
            $TenantRoleAssignmentsHT[$principalId] = @()
        }
        $TenantRoleAssignmentsHT[$principalId] += $assignment
    }
    Return $TenantRoleAssignmentsHT
}



$global:TenantReportTabs = @()

function Initialize-TenantReportTabs {
    param(
        [Parameter(Mandatory)][string]$StartTimestamp,
        [Parameter(Mandatory)][pscustomobject]$CurrentTenant,
        [Parameter(Mandatory)][pscustomobject]$TenantReports
    )

    $tenantNameEscaped = [uri]::EscapeDataString($CurrentTenant.DisplayName)

    $defs = @(
        @{ Prop = 'Summary';                   Key = 'Summary';    Title = 'Summary';                   File = "_EntraFalconEnumerationSummary_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'Users';                     Key = 'Users';      Title = 'Users';                     File = "Users_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'Groups';                    Key = 'Groups';     Title = 'Groups';                    File = "Groups_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'EnterpriseApps';            Key = 'EA';         Title = 'Enterprise Apps';           File = "EnterpriseApps_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'ManagedIdenties';           Key = 'MI';         Title = 'Managed Identities';        File = "ManagedIdentities_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'AppRegistrations';          Key = 'AR';         Title = 'App Registrations';         File = "AppRegistration_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'ConditionalAccessPolicies'; Key = 'CAP';        Title = 'Conditional Access';        File = "ConditionalAccessPolicies_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'Agents';                    Key = 'Agents';     Title = 'Agents';                    File = "Agents_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'EntraRoles';                Key = 'RoleEntra';  Title = 'Role Assignments (Entra)';  File = "Role_Assignments_Entra_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'AzureRoles';                Key = 'RoleAz';     Title = 'Role Assignments (Azure)';  File = "Role_Assignments_Azure_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'PimForEntra';               Key = 'PIM';        Title = 'PIM (Entra)';                File = "PIM_${StartTimestamp}_${tenantNameEscaped}.html" }
    )

    $tabs = New-Object System.Collections.Generic.List[object]

    foreach ($d in $defs) {
        $prop = [string]$d.Prop
        $enabled = $false

        try {
            $value = $TenantReports.$prop
            if ($value -is [bool]) { $enabled = $value }
        } catch {
            $enabled = $false
        }

        if (-not $enabled) { continue }

        $tabs.Add([pscustomobject]@{
            key   = [string]$d.Key
            title = [string]$d.Title
            file  = [string]$d.File
        })
    }

    $global:TenantReportTabs = $tabs
}


function Set-GlobalReportManifest {
    param(
        [Parameter(Mandatory)][string]$CurrentReportKey,
        [Parameter(Mandatory)][string]$CurrentReportName,
        [Parameter()][object]$Warnings
    )

    $warningsArray = @()

    if ($null -ne $Warnings) {
        if ($Warnings -is [string]) {
            $warningsArray = @($Warnings)
        } elseif ($Warnings -is [System.Collections.IEnumerable]) {
            $warningsArray = @($Warnings) | ForEach-Object { [string]$_ }
        } else {
            $warningsArray = @([string]$Warnings)
        }

        $warningsArray = $warningsArray |
            ForEach-Object { ($_ -replace '\s+', ' ').Trim() } |
            Where-Object { $_ }
    }

    $manifest = [pscustomobject]@{
        tenantName        = $global:ReportContext.TenantName
        tenantId          = $global:ReportContext.TenantId
        executedAt        = $global:ReportContext.StartTimestamp
        currentReportKey  = $CurrentReportKey
        currentReportName = $CurrentReportName
        warnings          = $warningsArray
        reports           = $global:TenantReportTabs
    }

    $json = $manifest | ConvertTo-Json -Depth 6 -Compress
    $global:GLOBALReportManifestScript = "<script id=`"report-manifest`" type=`"application/json`">$json</script>"
}





#Get all active Entra role assignments
function Get-PimforGroupsAssignments {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][String]$AuthMethod
    )
    $ResultAuthCheck = $true
    
    Write-Host "[*] Trigger interactive authentication for PIM for Groups assessment (skip with -SkipPimForGroups)"
    if (-not (invoke-EntraFalconAuth -Action Auth -Purpose PimforGroup @GLOBALAuthMethods)) {
        throw "[!] Authentication failed for PimforGroup"
    }

    try {
        $AuthCheck = Send-GraphRequest -AccessToken $GLOBALPimForGroupAccessToken.access_token -Method GET -Uri '/me?$select=id' -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -erroraction Stop
    } catch {
        write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
        $ResultAuthCheck = $false
        $global:GLOBALPimForGroupsChecked = $false
    }

    if ($ResultAuthCheck) {
        $global:GLOBALPimForGroupsChecked = $true
        $proceed = $true

        #Retrieve Pim Enabled groups. If HTTP 400 assuing error message is "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
        try {
            #Use alternative Endpoint for BroCI since no SP with pre-consented privieleges PrivilegedAccess.Read(Write).AzureADGroup exists
            if ($GLOBALAuthMethods.ContainsKey("BroCi")) {
                Write-Host "[*] Retrieve PIM enabled groups (BroCi / using api.azrbac.mspim.azure.com)"
                $headers = @{
                    Authorization = "Bearer $($GLOBALPimForGroupAzrbacAccessToken.access_token)"
                    "User-Agent"  = $GlobalAuditSummary.UserAgent.Name
                }

                $uri = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources?`$select=id,displayName&`$top=999"

                # Collect all pages
                $all = New-Object System.Collections.Generic.List[object]

                do {
                    $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop

                    if ($resp.value) {
                        foreach ($item in $resp.value) { [void]$all.Add($item) }
                    }

                    # Some endpoints return nextLink as a property literally named "@odata.nextLink"
                    $uri = $resp.'@odata.nextLink'
                }
                while (-not [string]::IsNullOrWhiteSpace($uri))

                $PimEnabledGroupsRaw = $all
            }

            else {
                Write-Host "[*] Retrieve PIM enabled groups (Graph)"
                $PimEnabledGroupsRaw = Send-GraphRequest -AccessToken $GLOBALPimForGroupAccessToken.access_token -Method GET -Uri "/privilegedAccess/aadGroups/resources" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
            }
        }
        catch {
            # Normalize status code detection across both request styles
            $statusCode = $null

            # Invoke-RestMethod / Invoke-WebRequest often expose a Response with StatusCode
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            elseif ($_.Exception.Message -match "Status:\s*(\d{3})") {
                $statusCode = [int]$Matches[1]
            }

            if ($statusCode -eq 400) {
                Write-Host "[!] HTTP 400 Error: Most likely due to missing Entra ID premium licence. Assuming no PIM for Groups is used." -ForegroundColor Yellow
            }
            else {
                $msg = ($_.Exception.Message -split "`n")[0]
                Write-Host "[!] Auth/Request error: $msg. Assuming no PIM for Groups is used." -ForegroundColor Yellow
            }

            $PIMforGroupsAssignments = ""
            $proceed = $false
        }

        if ($proceed) {
            $PimEnabledGroups = $PimEnabledGroupsRaw | ForEach-Object {
                [PSCustomObject]@{
                    Id          = $_.Id
                    displayName  = $_.displayName
                }
            }
    
            #Stored groups in global HT var to use in groups module
            $global:GLOBALPimForGroupsHT = @{}
            foreach ($item in $PimEnabledGroups) {
                $GLOBALPimForGroupsHT[$item.Id] = $item.displayName
            }
    
            $PimEnabledGroupsCount = ($PimEnabledGroups | Measure-Object).count
            if ($PimEnabledGroupsCount -ge 1) {
                Write-Host "[+] Got $PimEnabledGroupsCount PIM enabled groups"
                                     
                $Requests = @()
                $RequestID = 0
                # Loop through each group and create a request entry
                $PimEnabledGroups | ForEach-Object {
                    $RequestID++
                    $Requests += @{
                        "id"     = $RequestID  # Unique request ID
                        "method" = "GET"
                        "url"    =   "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$select=accessId,groupId,principalId&`$filter=groupId eq '$($_.id)'"
                    }
                }
    
                # Send Batch request
                $PIMforGroupsAssignments = (Send-GraphBatchRequest -AccessToken $GLOBALPimForGroupAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)).response.value
                Write-Host "[+] Got $($PIMforGroupsAssignments.Count) objects eligible for a PIM-enabled group"
                
            } else {
                Write-Host "[!] No PIM enabled groups found"
                $PIMforGroupsAssignments = ""
            }
        }
    }

    Return $PIMforGroupsAssignments
}

#Function to check the API permission for known Dangerous or high
function Get-APIPermissionCategory{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$InputPermission,
        [Parameter(Mandatory=$true)][string]$PermissionType
    )

    if ($PermissionType -eq "application") {
            # Check if the input permission ID exists in the hashtable
        if ($GLOBALApiPermissionCategorizationList.ContainsKey($InputPermission)) {
            # If the permission ID is found, return its categorization
            return $GLOBALApiPermissionCategorizationList[$inputPermission]
        } else {
            # If the permission ID is not found, return a message indicating that
            return "Uncategorized"
        }

    } elseif ($PermissionType -eq "delegated") {
        # Check if the input permission ID exists in the hashtable
        if ($GLOBALDelegatedApiPermissionCategorizationList.ContainsKey($InputPermission)) {
            # If the permission ID is found, return its categorization
            return $GLOBALDelegatedApiPermissionCategorizationList[$inputPermission]
        } else {
            # If the permission ID is not found, return a message indicating that
            return "Uncategorized"
        }
    } else {
        return "ApiPermissionLookupError"
    }
}

#Function to check if objects exist to determine if the reports wil lbe generated.
function Get-TenantReportAvailability {
    $requests = New-Object 'System.Collections.Generic.List[object]'

    $requestSpecs = @(
        @{ Name = 'Groups';           Url = '/groups' }
        @{ Name = 'AppRegistrations'; Url = '/applications' }
        @{ Name = 'ManagedIdenties';  Url = '/servicePrincipals'; Query = @{ '$filter' = "servicePrincipalType eq 'ManagedIdentity'" } }
        #@{ Name = 'EnterpriseApps';   Url = '/servicePrincipals'; Query = @{ '$filter' = "servicePrincipalType eq 'Application'" } }
        #@{ Name = 'Agents';           Url = '/servicePrincipals'; Query = @{ '$filter' = "servicePrincipalType eq 'ServiceIdentity'" } }
    )

    foreach ($spec in $requestSpecs) {
        $req = @{
            id     = $spec.Name
            method = 'GET'
            url    = $spec.Url
        }

        if ($spec.ContainsKey('Query') -and $spec.Query) {
            $req.queryParameters = $spec.Query
        }

        $requests.Add($req)
    }

    $response = Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $requests -BetaAPI -UserAgent $GlobalAuditSummary.UserAgent.Name -QueryParameters @{ '$select' = 'id'; '$top' = '1' } -DisablePagination

    $result = [ordered]@{}
    foreach ($spec in $requestSpecs) {
        $result[$spec.Name] = $false
    }

    foreach ($r in @($response)) {
        if ($null -eq $r.id) { continue }
        if (-not $result.Contains($r.id)) { continue }

        if ($r.status -ge 200 -and $r.status -lt 300) {
            $result[$r.id] = (@($r.response.value).Count -gt 0)
        } else {
            $result[$r.id] = $false
        }
    }

    [pscustomobject]$result
}

#Function to provide detailed info about an object. Since the object type is not always known (Get-MgBetaRoleManagementDirectoryRoleAssignment) the type has to be determined first.
#The type can specified to save some GraphAPI calls
if (-not $script:ObjectInfoCache) {
    $script:ObjectInfoCache = @{}
}
function Get-ObjectInfo {
    param(
        [Parameter(Mandatory)][string]$ObjectID,
        [string]$type = "unknown"
    )

    # Caching
    $normalizedType = $type.ToString().ToLowerInvariant()
    $cacheKey = "$normalizedType|$ObjectID"
    if ($script:ObjectInfoCache.ContainsKey($cacheKey)) {
        Write-Log -Level Trace -Message "Cache hit for $ObjectID"
        return $script:ObjectInfoCache[$cacheKey]
    }

    Write-Log -Level Trace -Message "Manually resolve $ObjectID"

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "serviceprincipal" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName"
        }
        $EnterpriseApp = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($EnterpriseApp) {
            $object = [PSCustomObject]@{ 
                DisplayName = $EnterpriseApp.DisplayName
                Type = "Enterprise Application"
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "appregistration" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName"
        }
        $AppRegistration = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/applications/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($AppRegistration) {
            $object = [PSCustomObject]@{ 
                DisplayName = $AppRegistration.DisplayName
                Type = "App Registration"
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "administrativeunit" ) {
        $QueryParameters = @{
            '$select' = "DisplayName"
        }
        $AdministrativeUnit = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($AdministrativeUnit) {
            $object = [PSCustomObject]@{ 
                DisplayName = $AdministrativeUnit.DisplayName
                Type = "Administrative Unit"
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "user" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,OnPremisesSyncEnabled,JobTitle,Department"
        }
        $user = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($user) {
            $object = [PSCustomObject]@{ 
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Type = "User"
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled
                JobTitle = $user.JobTitle
                Department = $user.Department
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "group" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,SecurityEnabled,IsAssignableToRole"
        }
        $group = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/groups/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        
        if ($group) {
            $IsAssignabletoRole = if ($null -ne $group.IsAssignableToRole) { $group.IsAssignableToRole } else { $false }
            $object = [PSCustomObject]@{ 
                DisplayName = $group.DisplayName
                Type = "Group"
                SecurityEnabled = $group.SecurityEnabled
                IsAssignableToRole = $isAssignabletoRole
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        } 
    }

    if ($normalizedType -eq "unknown") {
        Write-Log -Level Debug -Message "Unknown Object: $ObjectID"
        $object = [PSCustomObject]@{ 
            DisplayName = $ObjectID
            Type = "Unknown"
        }

        $script:ObjectInfoCache[$cacheKey] = $object
        return $object
    }
}

#Function to define global summary variable
function start-InitTasks {
    Param (
        [Parameter(Mandatory=$false)][string]$UserAgent = "EntraFalcon",
        [Parameter(Mandatory=$true)][string]$EntraFalconVersion
    )

    $Global:GlobalAuditSummary = @{
        Time                   = @{ Start = Get-Date -Format "yyyyMMdd HH:mm"; End = ""}
        Tenant                 = @{ Name = ""; Id = "" }
        EntraFalcon            = @{ Version = "$EntraFalconVersion"; Source = "https://github.com/CompassSecurity/EntraFalcon" }
        TenantLicense          = @{ Name = ""; Level = 0}
        Subscriptions          = @{ Count = 0 }
        UserAgent              = @{ Name = $UserAgent}
        Users                  = @{ Count = 0; Guests = 0; Inactive = 0; Enabled=0; OnPrem=0; MfaCapable=0; SignInActivity = @{ '0-1 month' = 0; '1-2 months' = 0; '2-3 months' = 0; '4-5 months' = 0; '5-6 months' = 0; '6+ months' = 0; 'Never' = 0 }}
        Groups                 = @{ Count = 0; M365 = 0; PublicM365 = 0; PimOnboarded = 0; OnPrem = 0}
        AppRegistrations       = @{ Count = 0; AppLock = 0; Credentials = @{ 'AppsSecrets' = 0; 'AppsCerts' = 0; 'AppsNoCreds' = 0}; Audience = @{ 'SingleTenant' = 0; 'MultiTenant' = 0; 'MultiTenantPersonal' = 0} }
        EnterpriseApps         = @{ Count = 0; Foreign = 0; IncludeMsApps = $false; Credentials = 0; ApiCategorization = @{ 'Dangerous' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Misc' = 0}}
        ManagedIdentities      = @{ Count = 0; IsExplicit = 0; ApiCategorization = @{ 'Dangerous' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Misc' = 0} }
        AdministrativeUnits    = @{ Count = 0 }
        ConditionalAccess      = @{ Count = 0; Enabled = 0 }
        EntraRoleAssignments   = @{ Count = 0; Eligible = 0; BuiltIn = 0; PrincipalType = @{ 'User' = 0; 'Group' = 0; 'App' = 0; 'MI' = 0; 'Unknown' = 0}; Tiers = @{ 'Tier-0' = 0; 'Tier-1' = 0; 'Tier-2' = 0; 'Uncategorized' = 0} }
        AzureRoleAssignments   = @{ Count = 0; Eligible = 0; BuiltIn = 0; PrincipalType = @{ 'User' = 0; 'Group' = 0; 'SP' = 0; 'Unknown' = 0}; }
        PimSettings            = @{ Count = 0}
        Errors                 = @()
    }
}


#Function to get the applied Entra teant license
function Get-EffectiveEntraLicense {
    [CmdletBinding()]

    $planPriority = @(
        @{ Plan = 'AAD_PREMIUM_P2'; Name = 'Microsoft Entra ID P2';    Int = 4 }
        @{ Plan = 'AAD_PREMIUM';    Name = 'Microsoft Entra ID P1';    Int = 3 }
        @{ Plan = 'AAD_BASIC';      Name = 'Microsoft Entra ID Basic'; Int = 2 }
        @{ Plan = 'AAD_FREE';       Name = 'Microsoft Entra ID Free';  Int = 1 }
    )

    $QueryParameters = @{
        '$select' = "capabilityStatus,servicePlans"
    }
    try {
        $response = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/subscribedSkus' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
    } catch {
        Write-Log -Level Debug -Message "Can't get Entra Tenant license. Request to /subscribedSkus failed"
        return [pscustomobject]@{
            EntraIDLicencesString = 'Unknown'
            EntraIDLicencesInt    = 0
        }
    }
    $skus =
        if ($null -eq $response) { @() }
        elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) { @($response) }
        elseif ($response.PSObject.Properties.Name -contains 'value') { @($response.value) }
        else { @($response) }

    # Entra Free does not have any SKUs
    if ($skus.Count -eq 0) {
        return [pscustomobject]@{
            EntraIDLicencesString = 'Microsoft Entra ID Free'
            EntraIDLicencesInt    = 1
        }
    }

    $observedPlans = New-Object System.Collections.Generic.HashSet[string]

    foreach ($sku in $skus) {
        if ($null -eq $sku) { continue }

        $capabilityStatus = $sku.capabilityStatus
        if ($capabilityStatus -ne 'Enabled' -and $capabilityStatus -ne 'Warning') { continue }

        foreach ($plan in @($sku.servicePlans)) {
            if ($null -eq $plan) { continue }

            if ($plan.provisioningStatus -ne 'Success') { continue }

            $servicePlanName = [string]$plan.servicePlanName
            [void]$observedPlans.Add($servicePlanName)
        }
    }

    foreach ($item in $planPriority) {
        if ($observedPlans.Contains($item.Plan)) {
            Write-Log -Level Verbose -Message "Entra Tenant license: $($item.Name)"
            return [pscustomobject]@{
                EntraIDLicencesString = $item.Name
                EntraIDLicencesInt    = $item.Int
            }
        }
    }

    Write-Log -Level Verbose -Message "Entra Tenant license: Unknown"
    return [pscustomobject]@{
        EntraIDLicencesString = 'Unknown'
        EntraIDLicencesInt    = 0
    }
}



# Function to help built the TXT report (avoiding using slow stuff like format-table)
function Format-ReportSection {
    param (
        [string]$Title,
        [array]$Objects,
        [string[]]$Properties,
        [hashtable]$ColumnWidths
    )

    $sb = New-Object System.Text.StringBuilder

    $line = "=" * 120
    [void]$sb.AppendLine($line)
    [void]$sb.AppendLine($Title)
    [void]$sb.AppendLine($line)

    # Header
    $header = ""
    foreach ($prop in $Properties) {
        $header += ("{0,-$($ColumnWidths[$prop])} " -f $prop)
    }
    [void]$sb.AppendLine($header)

    # Rows
    foreach ($obj in $Objects) {
        $row = ""
        foreach ($prop in $Properties) {
            $val = $obj.$prop
            $row += ("{0,-$($ColumnWidths[$prop])} " -f $val)
        }
        [void]$sb.AppendLine($row)
    }

    return $sb.ToString()
}


function invoke-EntraFalconAuth {
    <#
    .SYNOPSIS
    Routes and executes Entra ID, Microsoft Graph, PIM, and Azure ARM authentication or token refresh flows.

    .DESCRIPTION
    invoke-EntraFalconAuth is an internal orchestration helper that selects and executes the correct authentication
    or token refresh routine based on Action, Purpose, AuthMethod, and whether the BroCi flow is enabled.

    The function supports standard OAuth authentication (AuthCode, DeviceCode, ManualCode), token refresh and
    token exchange scenarios, as well as the BroCi flow with optional Bring-Your-Own BroCi refresh token support.
    When a BroCi token is supplied, the initial BroCi bootstrap authentication step is skipped and the provided
    token is used directly for subsequent token exchanges.

    The function prints a short status message, invokes the required underlying helper functions
    (Invoke-Auth, Invoke-DeviceCodeFlow, Invoke-Refresh), stores resulting tokens in predefined global variables,
    and returns $true on success or $false on failure.

    DeviceCode authentication is not supported with BroCi and will throw.

    .PARAMETER AuthMethod
    Specifies the authentication method to use when Action is Auth.
    Valid values: AuthCode, DeviceCode, ManualCode, Refresh.
    Note: When a BroCi token is supplied, AuthMethod is ignored for the BroCi bootstrap step.

    .PARAMETER BroCi
    Enables the BroCi authentication flow, which uses alternate client and redirect parameters and may perform
    additional token exchange steps.

    .PARAMETER BroCiToken
    Optional BroCi refresh token provided by the caller.
    When specified, the BroCi bootstrap authentication step is skipped and the provided token is used directly.

    .PARAMETER Action
    Specifies whether to authenticate or refresh tokens.
    Valid values: Auth, Refresh.

    .PARAMETER Purpose
    Specifies which token to obtain or refresh.
    Valid values: MainAuth, PimforEntra, PimforGroup, Azure.

    .OUTPUTS
    System.Boolean.
    Returns $true when the selected flow completes successfully; otherwise returns $false.
    Throws for invalid parameter combinations.

    .EXAMPLE
    invoke-EntraFalconAuth -Action Auth -Purpose MainAuth -AuthMethod DeviceCode

    .EXAMPLE
    invoke-EntraFalconAuth -Action Auth -Purpose MainAuth -AuthMethod AuthCode -BroCi -BroCiToken $BroCiRefreshToken

    .EXAMPLE
    invoke-EntraFalconAuth -Action Auth -Purpose PimforEntra -AuthMethod Refresh

    .EXAMPLE
    invoke-EntraFalconAuth -Action Refresh -Purpose MainAuth -BroCi
    #>

    [CmdletBinding()]
    param(
        # Authentication method
        [ValidateSet("AuthCode", "DeviceCode", "ManualCode", "Refresh")]
        [string]$AuthMethod = "AuthCode",

        [Parameter(Mandatory = $false)]
        [switch]$BroCi = $false,

        # Action
        [Parameter(Mandatory = $true)]
        [ValidateSet("Auth", "Refresh")]
        [string]$Action,

        # Purpose
        [Parameter(Mandatory = $true)]
        [ValidateSet("MainAuth", "PimforEntra", "PimforGroup", "Azure")]
        [string]$Purpose,

        #BrociToken
        [Parameter(Mandatory = $false)]
        [string]$BroCiToken

    )

    Write-Log -Level Debug -Message "Starting authentication: Action=$Action Purpose=$Purpose AuthMethod=$AuthMethod BroCi=$BroCi"

    if ($BroCi -and $AuthMethod -eq "DeviceCode") {
        throw "Invalid parameter combination: -AuthMethod DeviceCode cannot be used with -BroCi"
    }

    if (-not [string]::IsNullOrWhiteSpace($BroCiToken)) {
        $BroCiTokenObj = [pscustomobject]@{ refresh_token = $BroCiToken }
    } else {
        $BroCiTokenObj = $null
    }

    function Get-Plan {
        param(
            [hashtable]$Table,
            [string[]]$Keys
        )
        $node = $Table
        foreach ($k in $Keys) {
            if ($node -isnot [hashtable] -or -not $node.ContainsKey($k)) {
                return $null
            }
            $node = $node[$k]
        }
        return $node
    }

    function Get-EntraFalconStatusMessage {
        param(
            [ValidateSet("Auth", "Refresh")]
            [string]$Action,

            [ValidateSet("MainAuth", "PimforEntra", "PimforGroup", "Azure")]
            [string]$Purpose,

            [bool]$BroCi,

            [ValidateSet("AuthCode", "DeviceCode", "ManualCode", "Refresh")]
            [string]$AuthMethod
        )

        $modeText = if ($BroCi) { " (BroCi)" } else { "" }

        switch ($Action) {
            'Auth' {
                if ($AuthMethod -eq 'Refresh') {
                    return "[*] Exchanging token for $Purpose$modeText"
                }
                return "[*] Authenticating for $Purpose using $AuthMethod$modeText"
            }
            'Refresh' {
                return "[*] Refreshing $Purpose access token$modeText"
            }
        }
    }

    # --------------------------
    # ROUTING TABLE ("plans")
    # --------------------------
    $Routes = @{
        Auth = @{
            NoBroCi = @{
                MainAuth = @{
                    AuthCode = {
                        $tokens = Invoke-Auth -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                    DeviceCode = {
                        $tokens = Invoke-DeviceCodeFlow -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                    ManualCode = {
                        $tokens = Invoke-Auth -DisableJwtParsing -ManualCode @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                }

                PimforGroup = @{
                    AuthCode = {
                        $tokens = Invoke-Auth -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' `
                                             -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens
                        $true
                    }
                    DeviceCode = {
                        $tokens = Invoke-DeviceCodeFlow -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' `
                                                       -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens
                        $true
                    }
                    ManualCode = {
                        $tokens = Invoke-Auth -ManualCode `
                                             -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' `
                                             -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens
                        $true
                    }
                }

                Azure = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALMsGraphAccessToken.refresh_token `
                                                -Api management.azure.com `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALArmAccessToken = $tokens
                        $true
                    }
                }

                PimforEntra = @{
                    AuthCode = {
                        $tokens = Invoke-Auth -ClientID '51f81489-12ee-4a9e-aaae-a2591f45987d' `
                                             -RedirectUrl 'http://localhost:13824/' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                    DeviceCode = {
                        $tokens = Invoke-DeviceCodeFlow -ClientID '51f81489-12ee-4a9e-aaae-a2591f45987d' `
                                                       -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                    ManualCode = {
                        $tokens = Invoke-Auth -ManualCode `
                                             -ClientID '51f81489-12ee-4a9e-aaae-a2591f45987d' `
                                             -RedirectUrl 'http://localhost:13824/' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                }
            }

            BroCi = @{
                MainAuth = @{
                    AuthCode = {
                        # If caller provided a BroCi token use it
                        if ($BroCiTokenObj) {
                            $global:GLOBALBrociAccessToken = $BroCiTokenObj
                        } else {
                            $tokens = Invoke-Auth -ClientID "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" `
                                                -RedirectUrl "https://startups.portal.azure.com/auth/login/" `
                                                -Origin "https://doesnotmatter" `
                                                -DisableJwtParsing @GLOBALAuthParameters
                            $global:GLOBALBrociAccessToken = $tokens
                        }


                        $tokensIbiza = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                     -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                     -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                     -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                     -Origin 'https://portal.azure.com' @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokensIbiza
                        $true
                    }

                    ManualCode = {
                        # If caller provided a BroCi token use it
                         if ($BroCiTokenObj) {
                            $global:GLOBALBrociAccessToken = $BroCiTokenObj
                        } else {
                            $tokens = Invoke-Auth -ClientID 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUrl 'https://startups.portal.azure.com/auth/login/' `
                                                -Origin 'https://doesnotmatter' `
                                                -DisableJwtParsing -ManualCode @GLOBALAuthParameters
                            $global:GLOBALBrociAccessToken = $tokens
                        }

                        $tokensIbiza = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                     -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                     -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                     -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                     -Origin 'https://portal.azure.com' @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokensIbiza
                        $true
                    }

                    
                }

                PimforGroup = @{
                    Any = {
                        #Note: Maybe use the Ibiza Token
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '50aaa389-5a33-4f1a-91d7-2c45ecd8dac8' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens

                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '50aaa389-5a33-4f1a-91d7-2c45ecd8dac8' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Api 'api.azrbac.mspim.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAzrbacAccessToken = $tokens
                        $true
                    }
                }

                Azure = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -Api "management.azure.com" `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALArmAccessToken = $tokens
                        $true
                    }
                }

                PimforEntra = @{
                    Any = {
                        #Note: Maybe use the Ibiza Token
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                }
            }
        }

        Refresh = @{
            NoBroCi = @{
                MainAuth = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALMsGraphAccessToken.refresh_token `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                }
                PimforEntra = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALPIMsGraphAccessToken.refresh_token `
                                                -ClientId "51f81489-12ee-4a9e-aaae-a2591f45987d" `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                }
            }

            BroCi = @{
                MainAuth = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                }
                PimforEntra = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                }
            }
        }
    }

    # --------------------------
    # EXECUTION
    # --------------------------
    $broKey = if ($BroCi) { 'BroCi' } else { 'NoBroCi' }

    try {
        $plan = Get-Plan -Table $Routes -Keys @($Action, $broKey, $Purpose, $AuthMethod)

        #Fallback to any if no explicit is found
        if (-not $plan -and $Action -eq "Auth") {
            $plan = Get-Plan -Table $Routes -Keys @($Action, $broKey, $Purpose, "Any")
        }

        # If action is Refresh, authmethod isn't relevant: fall back to 'Any'
        if (-not $plan -and $Action -eq 'Refresh') {
            $plan = Get-Plan -Table $Routes -Keys @($Action, $broKey, $Purpose, 'Any')
        }

        if (-not $plan) {
            return $false
        }

        $status = Get-EntraFalconStatusMessage `
            -Action $Action `
            -Purpose $Purpose `
            -BroCi ([bool]$BroCi) `
            -AuthMethod $AuthMethod

        Write-Host $status

        & $plan
    }
    catch {
        Write-Host "[!] Authentication flow failed for $Purpose" -ForegroundColor Red
        return $false
    }
}



# Remove global variables
function start-CleanUp {
    remove-variable -Scope Global GLOBALMsGraphAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALApiPermissionCategorizationList -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALGraphExtendedChecks -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALArmAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALUserAppRoles -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsHT -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuditSummary -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALMainTableDetailsHEAD -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALJavaScript -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALJavaScript_Table -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALJavaScript_Nav -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALCss -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALDelegatedApiPermissionCategorizationList -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALMsTenantIds -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPermissionForCaps -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsChecked -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzurePsChecks -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzureIamWarningText -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuthParameters -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALEntraRoleRating -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzureRoleRating -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALImpactScore -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPIMsGraphAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPIMForEntraRolesChecked -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALBrociAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuthMethods -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupAzrbacAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALEntraFalconLogLevel -ErrorAction SilentlyContinue
}

enum LogLevel {
    Off     = 0
    Verbose = 1
    Debug   = 2
    Trace   = 3
}

function Get-LogLevel {
    [CmdletBinding()]
    param()

    $raw = $global:GLOBALEntraFalconLogLevel
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [LogLevel]::Off
    }

    try {
        return [LogLevel]::$raw
    } catch {
        return [LogLevel]::Off
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [LogLevel]$Level,

        [switch]$Timestamp
    )

    $currentLevel = Get-LogLevel
    if ($currentLevel -eq [LogLevel]::Off) { return }
    if ([int]$Level -gt [int]$currentLevel) { return }

    $prefix = if ($Timestamp) {
        "[{0}] [{1}]" -f $Level, (Get-Date -Format 'HH:mm:ss')
    } else {
        "[{0}]" -f $Level
    }

    Write-Information "$prefix $Message" -InformationAction Continue
}



function Show-EntraFalconBanner {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$EntraFalconVersion
    )
    $banner = @'

    ______      __                ______      __               
   / ____/___  / /__________ _   / ____/___ _/ /________  ____ 
  / __/ / __ \/ __/ ___/ __ `/  / /_  / __ `/ / ___/ __ \/ __ \
 / /___/ / / / /_/ /  / /_/ /  / __/ / /_/ / / /__/ /_/ / / / /
/_____/_/ /_/\__/_/   \__,_/  /_/    \__,_/_/\___/\____/_/ /_/ 
                                                               
'@

    # Show Banner with color
    Write-Host $banner -ForegroundColor Cyan
    If ($EntraFalconVersion) {Write-Host $EntraFalconVersion -ForegroundColor Cyan}
    Write-Host ""
}

Export-ModuleMember -Function Show-EntraFalconBanner,AuthenticationMSGraph,Get-TenantReportAvailability,Initialize-TenantReportTabs,Set-GlobalReportManifest,Get-EffectiveEntraLicense,Get-Devices,Get-UsersBasic,start-CleanUp,Format-ReportSection,Get-OrgInfo,Get-LogLevel, Write-Log,Invoke-MsGraphRefreshPIM,Write-LogVerbose,Invoke-AzureRoleProcessing,Get-RegisterAuthMethodsUsers,Invoke-EntraRoleProcessing,Get-EntraPIMRoleAssignments,AuthCheckMSGraph,RefreshAuthenticationMsGraph,Get-PimforGroupsAssignments,Invoke-CheckTokenExpiration,Invoke-MsGraphAuthPIM,EnsureAuthMsGraph,Get-AzureRoleDetails,Get-AdministrativeUnitsWithMembers,Get-ConditionalAccessPolicies,Get-EntraRoleAssignments,Get-APIPermissionCategory,Get-ObjectInfo,EnsureAuthAzurePsNative,checkSubscriptionNative,Get-AllAzureIAMAssignmentsNative,Get-PIMForGroupsAssignmentsDetails,Show-EnumerationSummary,start-InitTasks
