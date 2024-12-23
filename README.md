# 👀 whoAMI-scanner 👀
whoAMI-scanner helps you detect the use of untrusted AMIs in your AWS account(s). It's a command line tool that was released along with blog post [whoAMI: A cloud naming confusion attack](), which highlights a novel way to get malicious AMIs to run in victim AWS accounts. The best protection for the whoAMI attack is to use AWS's [Allowed AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-allowed-amis.html) feature, released December 1, 2024. However, we created `whoAMI-scanner` so you could quickly scan all of the instances running in your AWS account and find you which ones were created from **Unverified Community AMIs**.   

# Sample Run
```
❯ whoAMI-scanner --profile cfdeploy 
```



# Install

## Using Binary Release

1. Download the latest binary release from the [releases page](https://github.com/Datadog/whoAMI-scanner/releases).
2. Extract the binary and place it in your PATH.

## Using `go install`

1. [Install Go](https://golang.org/doc/install), use `go install github.com/Datadog/whoAMI-scanner.git
2. Use `go install github.com/Datadog/whoAMI-scanner@latest` to install from the remote source

## Using go clone and go build

```
git clone https://github.com/Datadog/whoAMI-scanner.git
cd whoAMI-scanner
go build .
./whoAMI-scanner
```

# Prerequisites
Supports AWS profiles, AWS environment variables, or metadata retrieval (on an ec2 instance)

## Required Permissions
* `ec2:DescribeInstances`
* `ec2:DescribeImages`

## Optional but recommended permissions:
* `ec2:GetAllowedImagesSettings`

# Details
The whoAMI-scanner tool provides several options to customize its behavior:  
```
    --profile: Specify the AWS profile to use. [Default: uses AWS CLI defaults (Checks default profile, then environment variables, then IMDS)]
    --region: Specify one specific AWS region to scan. [Default: all regions]
    --trusted-accounts: Specify a list of trusted AWS accounts to compare against. [Default: No trusted accounts]
    --output: Specify the output file for the CSV results. [Default: No output file]
    --verbose: Enable verbose mode to display more detailed information. [Default: false]
```

For a complete list of options, run:
`whoAMI-scanner --help`

# Contributing
Contributions are welcome! Please fork the repository and submit a pull request.  

# FAQ
Q: What is the purpose of this tool?  
A: The whoAMI-scanner helps you detect the use of untrusted AMIs in your AWS environment.  

Q: How do I specify multiple regions?  
A: Currently you can only specify one region at a time or run the tool against all regions (default).  

Q: What is meant by trusted accounts?
A: For companies using AWS organizations, a common practice is to have one account that shares trusted AMIs 
   with other accounts in the organization without making the AMIs public. The --trusted-accounts option in 
   whoAMI-scanner allows you to specify those accounts.

Q: What is mean by allowed accounts?
A: AWS's "Allowed AMIs" is a guardrail that AWS introduced to clearly define the accounts you are allowed to use 
   AMIs from. The whoAMI-scanner tool checks to see if this guardrail is enabled in your account and if it is, it
   uses that information to determine if the AMIs in use are from allowed accounts.

Q: How can I contribute to this project?  
A: Fork the repository, make your changes, and submit a pull request.