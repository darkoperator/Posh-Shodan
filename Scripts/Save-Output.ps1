#
# Sample scripts for 'Posh-Shodan'
#
# Generated by: Dan Borges <ahhh.db@gmail.com>
#
# Generated on: 11/29/2015
#
# Description: Sample output for saving and manipulating data pulled from Shodan
#

## Functions
# Save output in different formats

# Save Results as Json
function save_json($results, $filename)
{
  $results.matches | ConvertTo-Json > "$(echo $filename).json"
  Write-Host "Full result set saved to: $(echo $filename).json"
}

function save_xml($results, $filename)
{
  $results.matches | Export-Clixml "$(echo $filename).xml"
  Write-Host "Full result set saved to: $(echo $filename).xml"
}

function save_csv($results, $filename)
{
  $results.matches | ConvertTo-Csv > "$(echo $filename).csv"
  Write-Host "Full result set saved to: $(echo $filename).csv"
}

function save_text($results, $filename)
{
  $results.matches > "$(echo $filename).txt"
  Write-Host "Full result set saved to: $(echo $filename).txt"
}

function save_html($results, $filename)
{
  $results.matches | ConvertTo-Html > "$(echo $filename).html"
  Write-Host "Full result set saved to: $(echo $filename).html"
}

function save_table($results, $filename)
{
  $results.matches | Format-Table > "$(echo $filename).txt"
  Write-Host "Full result set saved to: $(echo $filename).txt"
}

$Query = Read-Host -Prompt 'Enter a simple query: '
$filename = Read-Host -Prompt 'Name of output file: '
Write-Host 'Select the file output format:'
Write-Host '1) JSON'
Write-Host '2) XML'
Write-Host '3) CSV'
Write-Host '4) TEXT'
Write-Host '5) HTML'
Write-Host '6) Table'
$Output = Read-Host -Prompt 'Your output selection: '

# Make query
$results = Search-ShodanHost -Query "$(echo $Query)"

# Switch on way to save results
switch($Output){
1{save_json $results $filename}
2{save_xml $results $filename}
3{save_csv $results $filename}
4{save_text $results $filename}
5{save_html $results $filename}
6{save_table $results $filename}
}