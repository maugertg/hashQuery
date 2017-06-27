# hashQuery

This script takes a file as input. The file should contain one hash (MD5, SHA1, or SHA256) per line.
The script does the following:
1- Query Threat Grid for the existance of a hash
2- If the hash exists fetch the network streams for each sample
3- Extract the unique IPs and Domains from the samples
4- Output the informaiton to a file in a RESULTS directory
