<#
Copyright 2014 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>

$hvassembly = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.HyperV.PowerShell")

function Set-VMNetworkAdapterOVSPort
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$VMNetworkAdapter,

        [parameter(Mandatory=$true)]
        [string]$OVSPortName
    )
    process
    {
        $ns = "root\virtualization\v2"
        $EscapedId = $VMNetworkAdapter.Id.Replace('\', '\\')
        $sd = gwmi -namespace $ns -class Msvm_EthernetPortAllocationSettingData -Filter "InstanceId like '$EscapedId%'"

        if($sd)
        {
            $sd.ElementName = $OVSPortName

            $vsms = gwmi -namespace $ns -class Msvm_VirtualSystemManagementService
            $retVal = $vsms.ModifyResourceSettings(@($sd.GetText(1)))
            try
            {
                Check-WMIReturnValue $retVal
            }
            catch
            {
                throw "Assigning OVS port '$OVSPortName' failed"
            }
        }
    }
}

function Check-WMIReturnValue($retVal)
{
    if ($retVal.ReturnValue -ne 0)
    {
        if ($retVal.ReturnValue -eq 4096)
        {
            do
            {
                $job = [wmi]$retVal.Job
            }
            while ($job.JobState -eq 4)

            if ($job.JobState -ne 7)
            {
                throw "Job Failed"
            }
        }
        else
        {
            throw "Job Failed"
        }
    }
}
