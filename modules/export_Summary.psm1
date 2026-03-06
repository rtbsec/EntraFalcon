<#
.SYNOPSIS
   Generate a summary about the enumerated objects in the tenant.

#>
function Export-Summary {
    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp
    )

    ############################## Function section ########################
    function New-ChartSection {
        param (
            [string]$Title,
            [string]$Prefix,
            [int]$ChartCount
        )
        $charts = ""
        for ($i = 1; $i -le $ChartCount; $i++) {
            $charts += "<div class='chart-box'><canvas id='${Prefix}_chart$i'></canvas></div>`n"
        }
    
return @"
<h2>$Title</h2>
<div class='chart-grid'>
    $charts
</div>
"@
    }

    ############################## Script section ########################

    #Define basic variables
    $Title = "EntraFalcon Enumeration Summary"

    $chartJsEmbedded = $global:GLOBALJavaScript_Chart

    $mainTable = [pscustomobject]@{ 
            "Users"                       = $($GlobalAuditSummary.Users.Count)
            "Groups"                      = $($GlobalAuditSummary.Groups.Count)
            "App Registrations"           = $($GlobalAuditSummary.AppRegistrations.Count)
            "Enterprise Applications"     = $($GlobalAuditSummary.EnterpriseApps.Count)
            "Managed Identities"          = $($GlobalAuditSummary.ManagedIdentities.Count)
            "Administrative Units"        = $($GlobalAuditSummary.AdministrativeUnits.Count)
            "Conditional Access Policies" = $($GlobalAuditSummary.ConditionalAccess.Count)
            "Entra Role Assignments"      = $($GlobalAuditSummary.EntraRoleAssignments.Count)
            "Azure Role Assignments"      = $($GlobalAuditSummary.AzureRoleAssignments.Count)
            "PIM Settings"                = $($GlobalAuditSummary.PimSettings.Count)
        }

    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 10 -Compress

    write-host "[*] Writing log files"


    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'

    $GlobalAuditSummary.Time.End = Get-Date -Format "yyyyMMdd HH:mm"

    $MsAppsEnumerated = if ([bool]$GlobalAuditSummary.EnterpriseApps.IncludeMsApps) {
        "True"
    } else {
        "False (default)"
    }

    #Check whether there are subscriptions
    if ($($GlobalAuditSummary.Subscriptions.Count) -eq 0) {
        if ($($GlobalAuditSummary.ManagedIdentities.Count) -ge 1) {
            $SubscriptionCount = "? (no access - but there are managed identities!)"
        } else {
            $SubscriptionCount = "0 (no subscriptions or no access)"
        }
    } else {
        $SubscriptionCount = $($GlobalAuditSummary.Subscriptions.Count)
    }

    $securityFindingsSummary = $GlobalAuditSummary.SecurityFindings
    if ($null -eq $securityFindingsSummary) {
        $securityFindingsSummary = @{ Vulnerable = 0; NotVulnerable = 0; Skipped = 0; Total = 0 }
    }
    $findingsStatusLine = "{0} Vulnerable / {1} Not Vulnerable / {2} Skipped" -f `
        $securityFindingsSummary.Vulnerable, $securityFindingsSummary.NotVulnerable, $securityFindingsSummary.Skipped
    $hostOs = Get-EntraFalconHostOs
    $powerShellDisplay = "V$($PSVersionTable.PSVersion.ToString()) ($hostOs)"

    #Define header HTML
    $headerHTML = [pscustomobject]@{ 
        "Tenant Name"                           = $($GlobalAuditSummary.Tenant.Name)
        "Tenant ID"                             = $($GlobalAuditSummary.Tenant.ID)
        "Tenant License"                        = $($GlobalAuditSummary.TenantLicense.Name)
        "Subscriptions"                         = $SubscriptionCount
        "Start Time"                            = $($GlobalAuditSummary.Time.Start)
        "End Time"                              = $($GlobalAuditSummary.Time.End)
        "EntraFalcon Version"                   = $($GlobalAuditSummary.EntraFalcon.Version)
        "PowerShell Version"                    = $powerShellDisplay
        "UserAgent"                             = $($GlobalAuditSummary.UserAgent.Name)
        "Enumerate Azure IAM"                   = $GLOBALAzurePsChecks
        "Enumerate PIM for Entra/Azure Roles"   = $GLOBALGraphExtendedChecks
        "Enumerate PIM for Groups"              = $GLOBALPimForGroupsChecked
        "Enumerate Default Microsoft SP"        = $MsAppsEnumerated
        "Security Findings (V/NV/Skipped)"      = $findingsStatusLine
    }


    # Generate chart sections
    $Chartsection += New-ChartSection -Title "Users" -Prefix "user" -ChartCount 6
    # Only include PIM chart if it's checked
    if ($GLOBALPimForGroupsChecked) { $ChartsectionGroups += New-ChartSection -Title "Groups" -Prefix "group" -ChartCount 4} else {$ChartsectionGroups += New-ChartSection -Title "Groups" -Prefix "group" -ChartCount 3}
    $ChartsectionEnterpriseApps += New-ChartSection -Title "Enterprise Applications" -Prefix "enterpriseapps" -ChartCount 3
    $ChartsectionAppRegistrations += New-ChartSection -Title "App Registrations" -Prefix "appregistrations" -ChartCount 3
    $ChartsectionManagedIdentities += New-ChartSection -Title "Managed Identities" -Prefix "managedidentities" -ChartCount 2
    $ChartsectionEntraRoles += New-ChartSection -Title "Entra ID Role Assignments" -Prefix "entraroles" -ChartCount 4
    $ChartsectionAzureRoles += New-ChartSection -Title "Azure Role Assignments" -Prefix "azureroles" -ChartCount 3


    #Dynamically generate sections
    if ($($GlobalAuditSummary.Groups.Count) -ge 1) {
        $Chartsection += $ChartsectionGroups
    }
    if ($($GlobalAuditSummary.EnterpriseApps.Count) -ge 1) {
        $Chartsection += $ChartsectionEnterpriseApps
    }
    if ($($GlobalAuditSummary.AppRegistrations.Count) -ge 1) {
        $Chartsection += $ChartsectionAppRegistrations
    }
    if ($($GlobalAuditSummary.ManagedIdentities.Count) -ge 1) {
        $Chartsection += $ChartsectionManagedIdentities
    }
    if ($($GlobalAuditSummary.EntraRoleAssignments.Count) -ge 1) {
        $Chartsection += $ChartsectionEntraRoles
    }
    if ($($GlobalAuditSummary.AzureRoleAssignments.Count) -ge 1) {
        $Chartsection += $ChartsectionAzureRoles
    }

    $Chartsection += "<script type='text/javascript'>`n$chartJsEmbedded`n</script>"

    # Chart script
    $Chartsection += @"
<script>
document.addEventListener('DOMContentLoaded', function () {
    // === 1. Your data source(s) ===
    const dataSources = {
        // ============ USERS ============
        users_general: {
            internal: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.Guests)),
            guests: $($GlobalAuditSummary.Users.Guests),
            total: $($GlobalAuditSummary.Users.Count)
        },
        users_enabled: {
            enabled: $($GlobalAuditSummary.Users.Enabled),
            disabled: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.Enabled))
        },
        users_onprem: {
            onprem: $($GlobalAuditSummary.Users.OnPrem),
            cloudOnly: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.OnPrem))
        },
        users_mfacap: {
            mfacap: $($GlobalAuditSummary.Users.MfaCapable),
            notmfacap: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.MfaCapable))
        },
        users_inactive: {
            inactive: $($GlobalAuditSummary.Users.Inactive),
            active: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.Inactive))
        },
        users_lastsignin: {
            '0-1 month': $($GlobalAuditSummary.Users.SignInActivity."0-1 month"),
            '1-2 months': $($GlobalAuditSummary.Users.SignInActivity."1-2 months"),
            '2-3 months': $($GlobalAuditSummary.Users.SignInActivity."2-3 months"),
            '3-4 months': $($GlobalAuditSummary.Users.SignInActivity."3-4 months"),
            '4-5 months': $($GlobalAuditSummary.Users.SignInActivity."4-5 months"),
            '5-6 months': $($GlobalAuditSummary.Users.SignInActivity."5-6 months"),
            '6+ months': $($GlobalAuditSummary.Users.SignInActivity."6+ months"),
            'Never': $($GlobalAuditSummary.Users.SignInActivity."Never")
        },

        // ============ GROUPS ============
        groups_general: {
            security: $($($GlobalAuditSummary.Groups.Count) - $($GlobalAuditSummary.Groups.M365)),
            m365: $($GlobalAuditSummary.Groups.M365),
            total: $($GlobalAuditSummary.Groups.Count)
        },
        groups_onprem: {
            onprem: $($GlobalAuditSummary.Groups.OnPrem),
            cloudonly: $($($GlobalAuditSummary.Groups.Count) - $($GlobalAuditSummary.Groups.OnPrem))
        },
        groups_public: {
            public: $($GlobalAuditSummary.Groups.PublicM365),
            notpublic: $($($GlobalAuditSummary.Groups.M365) - $($GlobalAuditSummary.Groups.PublicM365))
        },
        groups_pimonboarded: {
            onboarded: $($GlobalAuditSummary.Groups.PimOnboarded),
            notonboarded: $($($GlobalAuditSummary.Groups.Count) - $($GlobalAuditSummary.Groups.PimOnboarded))
        },

        // ============ Enterprise Apps ============
        enterpriseapps_general: {
            internal: $($($GlobalAuditSummary.EnterpriseApps.Count) - $($GlobalAuditSummary.EnterpriseApps.Foreign)),
            foreign: $($GlobalAuditSummary.EnterpriseApps.Foreign),
            total: $($GlobalAuditSummary.EnterpriseApps.Count)
        },
        enterpriseapps_credentials: {
            credentials: $($GlobalAuditSummary.EnterpriseApps.Credentials),
            nocredentials: $($($GlobalAuditSummary.EnterpriseApps.Count) - $($GlobalAuditSummary.EnterpriseApps.Credentials))
        },
            enterpriseapps_apicategorization: {
            'Dangerous': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Dangerous),
            'High': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.High),
            'Medium': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Medium),
            'Low': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Low),
            'Uncategorized': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Misc)
        },

        // ============ App Registrations ============
        appregistrations_general: {
            singletenant: $($GlobalAuditSummary.AppRegistrations.Audience.SingleTenant),
            multitenant: $($GlobalAuditSummary.AppRegistrations.Audience.MultiTenant),
            multitenantpersonal: $($GlobalAuditSummary.AppRegistrations.Audience.MultiTenantPersonal),
            total: $($GlobalAuditSummary.AppRegistrations.Count)
        },
        appregistrations_applock: {
            applock: $($GlobalAuditSummary.AppRegistrations.AppLock),
            noapplock: $($($GlobalAuditSummary.AppRegistrations.Count) - $($GlobalAuditSummary.AppRegistrations.AppLock))
        },
        appregistrations_credentials: {
            'Secrets': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsSecrets),
            'Certificates': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsCerts),
            'Federated Credentials': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsFederatedCreds),
            'None': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsNoCreds)
        },

        // ============ Managed Identities ============
        managedidentities_general: {
            systemassigned: $($($GlobalAuditSummary.ManagedIdentities.Count) - $($GlobalAuditSummary.ManagedIdentities.IsExplicit)),
            userassigned: $($GlobalAuditSummary.ManagedIdentities.IsExplicit),
            total: $($GlobalAuditSummary.ManagedIdentities.Count)
        },
            managedidentities_apicategorization: {
            'Dangerous': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Dangerous),
            'High': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.High),
            'Medium': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Medium),
            'Low': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Low),
            'Uncategorized': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Misc)
        },

        // ============ Entra Roles ============
        entraroles_general: {
            active: $($($GlobalAuditSummary.EntraRoleAssignments.Count) - $($GlobalAuditSummary.EntraRoleAssignments.Eligible)),
            eligible: $($GlobalAuditSummary.EntraRoleAssignments.Eligible),
            total: $($GlobalAuditSummary.EntraRoleAssignments.Count)
        },
        entraroles_builtin: {
            builtin: $($GlobalAuditSummary.EntraRoleAssignments.BuiltIn),
            custom: $($($GlobalAuditSummary.EntraRoleAssignments.Count) - $($GlobalAuditSummary.EntraRoleAssignments.BuiltIn))
        },
        entraroles_tiers: {
            'Tier-0': $($GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-0"),
            'Tier-1': $($GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-1"),
            'Tier-2': $($GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-2"),
            'Uncategorized': $($GlobalAuditSummary.EntraRoleAssignments.Tiers.Uncategorized)
        },
        entraroles_principaltypes: {
            'User': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.User),
            'Group': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Group),
            'App': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.App),
            'Managed Identity': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.MI),
            'Unknown': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Unknown)
        },

        // ============ Azure Roles ============
        azureroles_general: {
            active: $($($GlobalAuditSummary.AzureRoleAssignments.Count) - $($GlobalAuditSummary.AzureRoleAssignments.Eligible)),
            eligible: $($GlobalAuditSummary.AzureRoleAssignments.Eligible),
            total: $($GlobalAuditSummary.AzureRoleAssignments.Count)
        },
        azureroles_builtin: {
            builtin: $($GlobalAuditSummary.AzureRoleAssignments.BuiltIn),
            custom: $($($GlobalAuditSummary.AzureRoleAssignments.Count) - $($GlobalAuditSummary.AzureRoleAssignments.BuiltIn))
        },
        azureroles_principaltypes: {
            'User': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.User),
            'Group': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Group),
            'ServicePrincipal': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.SP),
            'Unknown': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Unknown)
        }        
    };

    // === 2. Shared chart config ===
    const chartColorPalette = ['#4CAF50', '#FF7043', '#29B6F6', '#FFCA28', '#AB47BC', '#26A69A', '#EC407A'];
    const chartInstances = [];

    function getChartData(datasetKey) {

        // ============ USERS ============

        if (datasetKey === 'users_general') {
            return {
                labels: ['Internal Users', 'Guest Users'],
                datasets: [{
                    data: [dataSources.users_general.internal, dataSources.users_general.guests],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_enabled') {
            return {
                labels: ['Enabled Users', 'Disabled Users'],
                datasets: [{
                    data: [dataSources.users_enabled.enabled, dataSources.users_enabled.disabled],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_onprem') {
            return {
                labels: ['Cloud-Only Users', 'Synced Users'],
                datasets: [{
                    data: [dataSources.users_onprem.cloudOnly, dataSources.users_onprem.onprem],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_mfacap') {
            return {
                labels: ['MFA Capable Users', 'Not MFA Capable Users'],
                datasets: [{
                    data: [dataSources.users_mfacap.mfacap, dataSources.users_mfacap.notmfacap],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_inactive') {
            return {
                labels: ['Active Users', 'Inactive Users'],
                datasets: [{
                    data: [dataSources.users_inactive.active, dataSources.users_inactive.inactive],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_lastsignin') {
            const entries = Object.entries(dataSources.users_lastsignin);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Users',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }
        
        // ============ Groups ============

        if (datasetKey === 'groups_general') {
            return {
                labels: ['Security Groups', 'M365 Groups'],
                datasets: [{
                    data: [dataSources.groups_general.security, dataSources.groups_general.m365],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'groups_onprem') {
            return {
                labels: ['Cloud-Only Groups', 'Synced Groups'],
                datasets: [{
                    data: [dataSources.groups_onprem.cloudonly, dataSources.groups_onprem.onprem],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'groups_public') {
            return {
                labels: ['Private M365 Group', 'Public M365 Groups'],
                datasets: [{
                    data: [dataSources.groups_public.notpublic, dataSources.groups_public.public],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'groups_pimonboarded') {
            return {
                labels: ['Not PIM Onboarded Groups', 'PIM Onboarded Groups'],
                datasets: [{
                    data: [dataSources.groups_pimonboarded.notonboarded, dataSources.groups_pimonboarded.onboarded],
                    backgroundColor: chartColorPalette
                }]
            };
        }

        // ============ Enterprise Apps ============
        if (datasetKey === 'enterpriseapps_general') {
            return {
                labels: ['Internal Apps', 'Foreign Apps'],
                datasets: [{
                    data: [dataSources.enterpriseapps_general.internal, dataSources.enterpriseapps_general.foreign],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'enterpriseapps_credentials') {
            return {
                labels: ['Apps without Credentials', 'Apps with Credentials'],
                datasets: [{
                    data: [dataSources.enterpriseapps_credentials.nocredentials, dataSources.enterpriseapps_credentials.credentials],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'enterpriseapps_apicategorization') {
            const entries = Object.entries(dataSources.enterpriseapps_apicategorization);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Apps',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        // ============ App Registrations ============
        if (datasetKey === 'appregistrations_general') {
            return {
                labels: ['Single Tenant', 'Multitenant', 'Multitenant and Personal'],
                datasets: [{
                    data: [dataSources.appregistrations_general.singletenant, dataSources.appregistrations_general.multitenant, dataSources.appregistrations_general.multitenantpersonal],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'appregistrations_applock') {
            return {
                labels: ['Apps with AppLock', 'Apps without AppLock'],
                datasets: [{
                    data: [dataSources.appregistrations_applock.applock, dataSources.appregistrations_applock.noapplock],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'appregistrations_credentials') {
            const entries = Object.entries(dataSources.appregistrations_credentials);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Apps',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        // ============ Managed Identities ============
        if (datasetKey === 'managedidentities_general') {
            return {
                labels: ['System Assigned', 'User Assigned'],
                datasets: [{
                    data: [dataSources.managedidentities_general.systemassigned, dataSources.managedidentities_general.userassigned],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'managedidentities_apicategorization') {
            const entries = Object.entries(dataSources.managedidentities_apicategorization);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Apps',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        // ============ Entra Roles ============
        if (datasetKey === 'entraroles_general') {
            return {
                labels: ['Eligible Assignments', 'Active Assignments'],
                datasets: [{
                    data: [dataSources.entraroles_general.eligible, dataSources.entraroles_general.active],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'entraroles_builtin') {
            return {
                labels: ['Built-In Roles', 'Custom Roles'],
                datasets: [{
                    data: [dataSources.entraroles_builtin.builtin, dataSources.entraroles_builtin.custom],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'entraroles_tiers') {
            const entries = Object.entries(dataSources.entraroles_tiers);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Roles',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }
        if (datasetKey === 'entraroles_principaltypes') {
            const entries = Object.entries(dataSources.entraroles_principaltypes);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Principals',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }


        // ============ Azure Roles ============
        if (datasetKey === 'azureroles_general') {
            return {
                labels: ['Eligible Assignments', 'Active Assignments'],
                datasets: [{
                    data: [dataSources.azureroles_general.eligible, dataSources.azureroles_general.active],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'azureroles_builtin') {
            return {
                labels: ['Built-In Roles', 'Custom Roles'],
                datasets: [{
                    data: [dataSources.azureroles_builtin.builtin, dataSources.azureroles_builtin.custom],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'azureroles_principaltypes') {
            const entries = Object.entries(dataSources.azureroles_principaltypes);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Principals',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        return null;
    }

    function getChartOptions(titleText, type, datasetKey, indexAxis = 'x', showLegend = true) {
        const isDarkMode = document.body.classList.contains('dark-mode');
        const axisColor = isDarkMode ? '#ccc' : '#333';
        const gridColor = isDarkMode ? '#444' : '#ccc';
        const titleColor = isDarkMode ? '#ccc' : '#222';
        const labelColor = isDarkMode ? '#eee' : '#111';

        const plugins = [];

        if (type === 'doughnut') {
            plugins.push({
                id: 'centerText',
                beforeDraw: (chart) => {
                    const { width, height, ctx } = chart;
                    const total = dataSources[datasetKey].total;

                    ctx.save();
                    ctx.font = 'bold 14px Arial';
                    ctx.fillStyle = labelColor;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(total + ' Total', width / 2, height / 2 + 37);
                    ctx.restore();
                }
            });
        }

        return {
            type,
            data: getChartData(datasetKey),
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: type === 'doughnut' ? '70%' : undefined,
                indexAxis: indexAxis,
                plugins: {
                    legend: {
                        display: showLegend,
                        position: 'top',
                        labels: { color: axisColor }
                    },
                    title: {
                        display: true,
                        text: titleText,
                        color: titleColor,
                        font: { size: 16 }
                    }
                },
                scales: type === 'bar' ? {
                    x: {
                        ticks: { color: axisColor },
                        grid: { color: gridColor }
                    },
                    y: {
                        ticks: { color: axisColor },
                        grid: { color: gridColor }
                    }
                } : {}
            },
            plugins
        };
    }

    // === 3. Chart layout/config ===
    const chartConfigs = [
        // ============ Users ============
        { id: 'user_chart1', title: 'Users vs Guests', type: 'doughnut', dataset: 'users_general' },
        { id: 'user_chart2', title: 'Enabled vs Disabled Users', type: 'bar', dataset: 'users_enabled', showLegend: false },
        { id: 'user_chart3', title: 'MFA Capable vs Not Capable Users', type: 'bar', dataset: 'users_mfacap', showLegend: false },
        { id: 'user_chart4', title: 'Cloud-Only vs Synced Users', type: 'bar', dataset: 'users_onprem', showLegend: false },
        { id: 'user_chart5', title: 'Active vs Inactive Users', type: 'bar', dataset: 'users_inactive', showLegend: false },
        { id: 'user_chart6', title: 'Last Successful Sign-In', type: 'bar', dataset: 'users_lastsignin',indexAxis: 'y', showLegend: false },
        
        // ============ Groups ============
        { id: 'group_chart1', title: 'Security vs M365 Groups', type: 'doughnut', dataset: 'groups_general' },
        { id: 'group_chart2', title: 'Cloud-Only vs Synced Groups', type: 'bar', dataset: 'groups_onprem', showLegend: false },
        { id: 'group_chart3', title: 'Private vs Public M365 Groups', type: 'bar', dataset: 'groups_public', showLegend: false },
        { id: 'group_chart4', title: 'PIM-Onboarded Groups', type: 'bar', dataset: 'groups_pimonboarded', showLegend: false },

        // ============ Enterprise Apps ============
        { id: 'enterpriseapps_chart1', title: 'Internal vs Foreign Apps', type: 'doughnut', dataset: 'enterpriseapps_general' },
        { id: 'enterpriseapps_chart2', title: 'Apps without Credentials vs Apps with Credentials', type: 'bar', dataset: 'enterpriseapps_credentials', showLegend: false },
        { id: 'enterpriseapps_chart3', title: 'Apps by API Permission Severity', type: 'bar', dataset: 'enterpriseapps_apicategorization',indexAxis: 'y', showLegend: false },

        // ============ App Registrations ============
        { id: 'appregistrations_chart1', title: 'Apps Audience', type: 'doughnut', dataset: 'appregistrations_general' },
        { id: 'appregistrations_chart2', title: 'Apps with vs without AppLock', type: 'bar', dataset: 'appregistrations_applock', showLegend: false },
        { id: 'appregistrations_chart3', title: 'Apps with Credentials', type: 'bar', dataset: 'appregistrations_credentials',indexAxis: 'y', showLegend: false },

        // ============ Managed Identities  ============
        { id: 'managedidentities_chart1', title: 'System-Assigned vs User-Assigned MI', type: 'doughnut', dataset: 'managedidentities_general' },
        { id: 'managedidentities_chart2', title: 'MI by API Permission Severity', type: 'bar', dataset: 'managedidentities_apicategorization',indexAxis: 'y', showLegend: false },

        // ============ Entra Roles ============
        { id: 'entraroles_chart1', title: 'Eligible vs Active Role Assignments', type: 'doughnut', dataset: 'entraroles_general' },
        { id: 'entraroles_chart2', title: 'Built-In vs Custom Role Assignments', type: 'bar', dataset: 'entraroles_builtin', showLegend: false },
        { id: 'entraroles_chart3', title: 'Assignments per Role Tier-Level', type: 'bar', dataset: 'entraroles_tiers',indexAxis: 'y', showLegend: false },
        { id: 'entraroles_chart4', title: 'Assignments per Principal Type', type: 'bar', dataset: 'entraroles_principaltypes',indexAxis: 'y', showLegend: false },

        // ============ Azure Roles ============
        { id: 'azureroles_chart1', title: 'Eligible vs Active Role Assignments', type: 'doughnut', dataset: 'azureroles_general' },
        { id: 'azureroles_chart2', title: 'Built-In vs Custom Role Assignments', type: 'bar', dataset: 'azureroles_builtin', showLegend: false },
        { id: 'azureroles_chart3', title: 'Assignments per Principal Type', type: 'bar', dataset: 'azureroles_principaltypes',indexAxis: 'y', showLegend: false }
    ];

    // === 4. Render all charts ===
    function renderCharts() {
        chartInstances.forEach(chart => chart.destroy());
        chartInstances.length = 0;

        chartConfigs.forEach(config => {
            const ctx = document.getElementById(config.id);
            if (ctx) {
                const chart = new Chart(
                    ctx,
                    getChartOptions(config.title, config.type, config.dataset, config.indexAxis || 'x', config.showLegend !== false)
                );
                chartInstances.push(chart);
            }
        });
    }

    renderCharts(); // Initial load

    // === 5. Re-render on theme change ===
    const observer = new MutationObserver(() => renderCharts());
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
});
</script>

"@
$CustomCss = @"
<style>
.chart-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 20px;
    max-width: 1100px;
    margin-bottom: 30px;
}
.chart-box {
    width: 100%;
    max-width: 500px;
    height: 250px;
}
</style>
"@


$OutputCLI = @"
Execution Information:
    - Tenant Name:    $($GlobalAuditSummary.Tenant.Name)
    - Tenant ID:      $($GlobalAuditSummary.Tenant.ID)
    - Tenant License: $($GlobalAuditSummary.TenantLicense.Name)
    - Subscriptions:  $SubscriptionCount
    - Start:          $($GlobalAuditSummary.Time.Start)
    - End:            $($GlobalAuditSummary.Time.End)
    - EntraFalcon:    $($GlobalAuditSummary.EntraFalcon.Version)
    - PowerShell:     $powerShellDisplay
    - UserAgent:      $($GlobalAuditSummary.UserAgent.Name)

Enhanced Checks:
    - Enumerate Azure IAM:                  $GLOBALAzurePsChecks
    - Enumerate PIM for Entra/Azure Roles:  $GLOBALGraphExtendedChecks
    - Enumerate PIM for Groups:             $GLOBALPimForGroupsChecked
    - Enumerate Default Microsoft SP:       $MsAppsEnumerated

Enumeration Results:
    - Users:                       $($GlobalAuditSummary.Users.Count) ($($GlobalAuditSummary.Users.Guests) Guests)
    - Groups:                      $($GlobalAuditSummary.Groups.Count)
    - App Registrations:           $($GlobalAuditSummary.AppRegistrations.Count)
    - Enterprise Applications:     $($GlobalAuditSummary.EnterpriseApps.Count) ($($GlobalAuditSummary.EnterpriseApps.Foreign) Foreign)
    - Managed Identities:          $($GlobalAuditSummary.ManagedIdentities.Count)
    - Administrative Units:        $($GlobalAuditSummary.AdministrativeUnits.Count)
    - Conditional Access Policies: $($GlobalAuditSummary.ConditionalAccess.Count) ($($GlobalAuditSummary.ConditionalAccess.Enabled) Enabled)
    - Entra Role Assignments:      $($GlobalAuditSummary.EntraRoleAssignments.Count) ($($GlobalAuditSummary.EntraRoleAssignments.Eligible) Eligible)
    - Azure Role Assignments:      $($GlobalAuditSummary.AzureRoleAssignments.Count) ($($GlobalAuditSummary.AzureRoleAssignments.Eligible) Eligible)
    - PIM Settings:                $($GlobalAuditSummary.PimSettings.Count)
    - Findings:                    $findingsStatusLine
"@

    # Set generic information hich gets injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'Summary' -CurrentReportName 'EntraFalcon Enumeration Summary'

    # Build header section
    $headerHTML = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><h2>General</h2>" -As List -PostContent "<h2>Enumerated Objects</h2>"
  
    #Write HTML
    $PostContentCombined =  $Chartsection + "`n" + $GLOBALJavaScript
    $CssCombined = $GLOBALcss + $CustomCss + $global:GLOBALReportManifestScript
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title" -Head $CssCombined -PostContent $PostContentCombined
    $summaryHtmlPath = "$outputFolder\_EntraFalconEnumerationSummary_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"
    $summaryTxtPath = "$outputFolder\_EntraFalconEnumerationSummary_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt"
    $Report | Out-File $summaryHtmlPath
    $OutputCLI | Out-File -Width 512 -FilePath $summaryTxtPath

    # Print to console
    Write-Host "`n`n========================================= Summary =========================================" -ForegroundColor Cyan
    Write-Host $OutputCLI
    Write-Host "===========================================================================================" -ForegroundColor Cyan
    write-host "[+] Enumeration summary stored at: $summaryHtmlPath"
    write-host "[+] Enumeration summary (txt) stored at: $summaryTxtPath"
    write-host "[+] Run completed successfully"
}

