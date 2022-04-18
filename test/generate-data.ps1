param
(
  [parameter(Mandatory=$true)]
  [string]$OpenSSL,
  [string]$WorkingDirectory
)
# Prepare
New-Item -ErrorAction SilentlyContinue -ItemType Directory "${WorkingDirectory}/data/"
# make a random key
$key = new-object byte[] 16
(new-object Random).NextBytes($key)
$key_str = [System.BitConverter]::ToString($key) -replace "-",""
[IO.File]::WriteAllBytes("${WorkingDirectory}/data/key.bin", $key)

$iv = new-object byte[] 16
(new-object Random).NextBytes($iv)
$iv_str = [System.BitConverter]::ToString($iv) -replace "-",""
[IO.File]::WriteAllBytes("${WorkingDirectory}/data/iv.bin", $iv)

# Make a digital signature key pair
#openssl genrsa -out rsa.private 2048
#openssl rsa -in rsa.private -out rsa.public -pubout -outform PEM
Start-Process -FilePath $OpenSSL -PassThru -NoNewWindow -Wait -ArgumentList 'genrsa','-out',"${WorkingDirectory}\\data\\rsa.private.pem",'2048'
Start-Process -FilePath $OpenSSL -PassThru -NoNewWindow -Wait -ArgumentList 'rsa','-in',"${WorkingDirectory}\\data\\rsa.private.pem",'-out',"${WorkingDirectory}\\data\\rsa.public.pem",'-pubout','-outform','PEM'

$block = 
{
    Param(
        [string] $i,
        [string] $root_dir,
        [string] $OpenSSL,
        [string] $key,
        [string] $iv
    )
    $plain = "${root_dir}\\data\\plain-${i}.bin"
    $cypher = "${root_dir}\\data\\cypher-${i}.bin"
    $sign = "${root_dir}\\data\\old-sign-${i}.bin"
    $rsaPrivate = "${root_dir}\\data\\rsa.private.pem"
    $rsaPublic = "${root_dir}\\data\\rsa.public.pem"
    # Generate random data
    $file_size = Get-Random -Minimum 10 -Maximum 4096
    $out = new-object byte[] $file_size
    (new-object Random).NextBytes($out)
    [IO.File]::WriteAllBytes($plain, $out)
    Start-Process -FilePath $OpenSSL -PassThru -NoNewWindow -Wait -ArgumentList 'enc','-e','-K',$key,'-iv',$iv,'-aes-128-cbc','-in',$plain,'-out',$cypher
    Start-Process -FilePath $OpenSSL -PassThru -NoNewWindow -Wait -ArgumentList 'dgst','-sha256','-sign',$rsaPrivate,'-out',$sign,$plain
}

# Remove all jobs
Get-Job | Remove-Job

$MaxThreads = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

# Start the jobs.
ForEach ($i in 1..10)
{
    While ($(Get-Job -state running).count -ge $MaxThreads)
    {
        Start-Sleep -Milliseconds 300
    }
    Start-Job -Scriptblock $block -ArgumentList $i,$WorkingDirectory,$OpenSSL,$key_str,$iv_str
}

# Wait for all jobs to finish.
While ($(Get-Job -State Running).count -gt 0)
{
    Start-Sleep 1
}

# Remove all jobs created.
Get-Job | Remove-Job