# script to export  windows environment variables to bash shell
# This is useful to create bash environments from vcvars64.bat
# based on the solution from this article https://anadoxin.org/blog/bringing-visual-studio-compiler-into-msys2-environment.html/

if((Test-Path "snapshot.env") -eq $false){

    Get-ChildItem env: | Select-Object Key,Value | ConvertTo-Json | Set-Content "snapshot.env"
    Write-Host "Stored snapshot.env"    
    return
}

$snapshotEnv = Get-Content "snapshot.env" | ConvertFrom-Json

foreach($e in Get-ChildItem env:){
    if($e.Key -contains '/') {
        # Sometimes Windows uses environment variables like i.e.
        # ProgramFiles(x86)=c:\...
        # but let's just skip this.
        continue;
    }
    $key = $e.Key
    $keyUpperCase = $e.Key.ToUpperInvariant()

    if($keyUpperCase -eq "PATH") {
        $path = $e.Value.Replace("c:", "/c").Replace("C:", "/c").Replace("\", "/").Replace(";", ":")
        Write-Output "export PATH=""`$PATH:$path"""
        continue
    }
    $valueEscaped = $e.value.replace("\", "\\");

    $snapShotEntry = $snapshotEnv | Where-Object -Property Key -eq $key | Select-Object -First 1
    
    if($null -ne $snapShotEntry){
        Write-Output "# debug: key=$keyUpperCase"
        $oldValue = $snapShotEntry.Value
        if($oldValue -ne $e.Value) {
            Write-Output "export $key=""$valueEscaped"" #changed"
        }    
    }
    else{
        Write-Output "export $key=""$valueEscaped"" #new"

    }
}