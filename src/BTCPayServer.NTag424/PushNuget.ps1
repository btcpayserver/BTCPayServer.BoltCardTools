rm "bin\release\" -Recurse -Force
dotnet pack --configuration Release --include-symbols -p:SymbolPackageFormat=snupkg
$package=(ls .\bin\Release\*.nupkg).FullName
dotnet nuget push $package --source "https://api.nuget.org/v3/index.json"
$ver = ((ls .\bin\release\*.nupkg)[0].Name -replace 'BTCPayServer\.NTag424\.(\d+(\.\d+){1,3}).*', '$1')
git tag -a "NTag424/v$ver" -m "NTag424/$ver"
git push origin "NTag424/v$ver"
