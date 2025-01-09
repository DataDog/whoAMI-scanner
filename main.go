package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
	"os"
	"path/filepath"
	"strings"
)

var (
	verbose                    bool
	version                    = "0.0.4"
	cyan                       = color.New(color.FgCyan).SprintFunc()
	green                      = color.New(color.FgGreen).SprintFunc()
	yellow                     = color.New(color.FgYellow).SprintFunc()
	red                        = color.New(color.FgRed).SprintFunc()
	amiToInstanceMap           = make(map[string][]Instance)
	allowedAMIPermissionDenied = false
)

type AMI struct {
	ID          string
	Region      string
	OwnerAlias  string
	OwnerID     string
	Name        string
	Description string
	Public      string
}

type Instance struct {
	ID     string
	Region string
	Name   string
}

func main() {
	// Parse command-line arguments
	var profile string
	var region string
	var output string
	var trustedAccountsInput string
	flag.StringVar(&profile, "profile", "", "AWS profile name [Default: Default profile, IMDS, or environment variables]")
	flag.StringVar(&region, "region", "", "AWS region [Default: All regions]")
	flag.StringVar(&trustedAccountsInput, "trusted-accounts", "", "Comma-separated list of AWS account IDs that are allowed to share AMIs")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output for detailed status updates")
	flag.StringVar(&output, "output", "", "Specify file path/name for csv report)")
	flag.Parse()

	// Print tool name and version in a bit of a fancy way
	//color.Cyan(emoji.Sprintf(":eyes:whoAMI-scanner v%s :eyes:\n", version))

	if output != "" {
		PreparePath(output)
	}

	var trustedAccounts []string
	if trustedAccountsInput != "" {
		// Split the comma-separated list of allowed accounts and trim any whitespace
		trustedAccounts = strings.Split(trustedAccountsInput, ",")
		for i, account := range trustedAccounts {
			trustedAccounts[i] = strings.TrimSpace(account)
		}
		if verbose {
			fmt.Printf("[*] User provided trusted accounts: %v\n", trustedAccounts)
		}
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(profile), config.WithRegion("us-east-1"))
	if err != nil {
		color.Red("Error loading AWS config: %v", err)
		os.Exit(1)
	}

	if region != "" {
		cfg.Region = region
	}

	ec2Client := ec2.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)

	// Get account ID
	callerIdentity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		color.Red("Error fetching account ID: %v", err)
		os.Exit(1)
	}
	_ = *callerIdentity.Account

	fmt.Printf("[%s] %s", cyan(emoji.Sprintf(":eyes:whoAMI-scanner v%s :eyes:", version)), fmt.Sprintf("AWS Caller Identity: %s\n", aws.ToString(callerIdentity.Arn)))

	if verbose {
		fmt.Println("[*] Verbose mode enabled.")
	} else {
		fmt.Println("[*] Verbose mode disabled. Only unknown and unverified AMIs will be displayed.")
	}

	// Fetch regions
	var regions []string
	if region == "" {
		describeRegionsOutput, err := ec2Client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})
		if err != nil {
			color.Red("Error fetching regions: %v", err)
			os.Exit(1)
		}
		for _, r := range describeRegionsOutput.Regions {
			regions = append(regions, *r.RegionName)
		}
	} else {
		regions = []string{region}
	}

	processedAMIs := make(map[string]bool)
	verifiedAMIs := make(map[string]AMI)
	unverifiedAMIs := make(map[string]AMI)
	unknownAMIs := make(map[string]AMI)
	selfHostedAMIs := make(map[string]AMI)
	alllowedAMIs := make(map[string]AMI)
	trustedAMIs := make(map[string]AMI)
	privateSharedAMIs := make(map[string]AMI)
	allowedAMIAccountsByRegion := make(map[string][]string)
	allowedAMIStateByRegion := make(map[string]string)
	totalInstances := 0

	fmt.Println("[*] Starting AMI analysis...")
	// Loop through regions
	for _, region := range regions {
		//if verbose {
		//	fmt.Printf("[*] Checking region %s\n", region)
		//}
		cfg.Region = region
		ec2Client := ec2.NewFromConfig(cfg)

		allowedAMIsState, allowedAMIAccounts, err := CheckAllowedAMIs(ec2Client)
		allowedAMIStateByRegion[region] = allowedAMIsState
		allowedAMIAccountsByRegion[region] = allowedAMIAccounts
		if err != nil {
			if strings.Contains(err.Error(), "UnauthorizedOperation") {
				if !allowedAMIPermissionDenied {
					color.Red("[!] Error calling ec2:GetAllowedImagesSettings. Check to see if %s has this permission", aws.ToString(callerIdentity.Arn))
					color.Red("[!] Skipping allowed AMI checks for all regions.")
					allowedAMIPermissionDenied = true
					allowedAMIsState = "Permission Denied"
				}
			} else {
				color.Red("[!] [%s] Error calling ec2:GetAllowedImagesSettings: %v", region, err)
			}
		} else if allowedAMIsState == "enabled" {
			if verbose {
				fmt.Printf("[*] [%s] Allowed AMI Accounts status: %s\n", region, green("Enabled"))
			}
		} else if allowedAMIsState == "audit-mode" {
			if verbose {
				fmt.Printf("[*] [%s] Allowed AMI Accounts status: %s\n", region, yellow("Audit mode"))
			}
		} else {
			if verbose {
				fmt.Printf("[*] [%s] Allowed AMI Accounts status: %s\n", region, red(("Disabled")))
			}
		}
		//if allowedAMIsState == "enabled" || allowedAMIsState == "audit-mode" {
		//
		//	if len(allowedAMIAccounts) > 0 {
		//		if verbose {
		//			fmt.Printf("[*] [%s] Allowed AMI accounts found in region\n", region)
		//		}
		//	} else {
		//		if verbose {
		//			fmt.Printf("[*] [%s] No allowed AMIs found in region\n", region)
		//		}
		//	}
		//
		//}

		// Fetch instances
		instancesOutput, err := ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
		if err != nil {
			color.Red("Error fetching instances for region %s: %v", region, err)
			continue
		}

		instanceIDs := []string{}
		for _, reservation := range instancesOutput.Reservations {
			for _, instance := range reservation.Instances {
				instanceIDs = append(instanceIDs, *instance.InstanceId)
				amiID := *instance.ImageId
				name := ""
				// Get the name of the instance if it exists from the tags
				for _, tag := range instance.Tags {
					if *tag.Key == "Name" {
						name = aws.ToString(tag.Value)
					}
				}
				// Check if the instance already exists in the map
				exists := false
				for _, inst := range amiToInstanceMap[amiID] {
					if inst.ID == aws.ToString(instance.InstanceId) {
						exists = true
						break
					}
				}
				if !exists {
					amiToInstanceMap[amiID] = append(amiToInstanceMap[amiID], Instance{
						ID:     aws.ToString(instance.InstanceId),
						Region: region,
						Name:   name,
					})
				}
			}
		}

		totalInstances += len(instanceIDs)
		if len(instanceIDs) == 0 {
			continue
		}

		for i, instanceID := range instanceIDs {
			var publicString string
			// Fetch instance details
			instanceDetail, err := ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
				InstanceIds: []string{instanceID},
			})
			if err != nil {
				color.Red("Error fetching details for instance %s: %v", instanceID, err)
				continue
			}

			for _, reservation := range instanceDetail.Reservations {
				for _, instance := range reservation.Instances {
					amiID := *instance.ImageId

					if processedAMIs[amiID] {
						if verbose {
							color.Cyan("[%d/%d][%s] %s already processed. Skipping.", i+1, len(instanceIDs), region, amiID)
						}
						continue
					}
					processedAMIs[amiID] = true
					var ami AMI

					if verbose {
						fmt.Printf("[%d/%d][%s] %s being analyzed (Instance: %s)\n", i+1, len(instanceIDs), region, amiID, instanceID)
					}
					// Fetch AMI details
					imageOutput, err := ec2Client.DescribeImages(context.TODO(), &ec2.DescribeImagesInput{
						ImageIds: []string{amiID},
					})
					if err != nil {
						if verbose {
							color.Red("Error fetching AMI details for %s: %v", amiID, err)
						}
						continue
					}

					if len(imageOutput.Images) > 0 {
						for _, image := range imageOutput.Images {
							if *image.Public {
								publicString = "Public"
							} else {
								publicString = "Private"
							}
							ami = AMI{
								ID:          amiID,
								Region:      region,
								OwnerAlias:  ptr.ToString(image.ImageOwnerAlias),
								OwnerID:     ptr.ToString(image.OwnerId),
								Name:        ptr.ToString(image.Name),
								Description: ptr.ToString(image.Description),
								Public:      publicString,
							}
						}
					} else {
						// try to get the info via the instance metadata instead
						instanceImageOutput, err := ec2Client.DescribeInstanceImageMetadata(context.TODO(),
							&ec2.DescribeInstanceImageMetadataInput{
								InstanceIds: []string{aws.ToString(instance.InstanceId)},
							})
						if err != nil {
							color.Red("An AMI was found that is not public. "+
								"We tried `ec2:DescribeInstanceImageMetadata` but did not have permission. "+
								"AMI ID: %s: Error: %v", amiID, err)
							continue
						}
						for _, instance := range instanceImageOutput.InstanceImageMetadata {
							if *instance.ImageMetadata.IsPublic {
								publicString = "Public"
							} else {
								publicString = "Private"
							}

							ami = AMI{
								ID:          amiID,
								Region:      region,
								OwnerAlias:  ptr.ToString(instance.ImageMetadata.ImageOwnerAlias),
								OwnerID:     ptr.ToString(instance.ImageMetadata.OwnerId),
								Name:        ptr.ToString(instance.ImageMetadata.Name),
								Description: "Unable to find description. AMI has been deleted or made private",
							}
						}
					}

					if ami.OwnerAlias != "" {
						if ami.OwnerAlias == "amazon" {
							if verbose {
								color.Green("[%d/%d][%s] %s is a community AMI from an AWS verified account.", i+1, len(instanceIDs), region, amiID)
							}
							verifiedAMIs[amiID] = ami
						} else if ami.OwnerAlias == "aws-marketplace" {
							if verbose {
								color.Green("[%d/%d][%s] %s is a AWS marketplace AMI from a verified account.", i+1, len(instanceIDs), region, amiID)
							}
							verifiedAMIs[amiID] = ami
						} else if ami.OwnerAlias == "self" {
							if verbose {
								color.Green("[%d/%d][%s] %s is hosted from this account.", i+1, len(instanceIDs), region, amiID)
							}
							selfHostedAMIs[amiID] = ami
						}
					} else {
						// The AMI has no OwnerAlias specified which means it is a community AMI or shared directly with this account.

						// check if the AMI is from an allowed account
						if allowedAMIsState == "enabled" || allowedAMIsState == "audit-mode" {
							if contains(allowedAMIAccounts, ami.OwnerID) {
								if verbose {
									color.Green("[%d/%d][%s] %s is from an allowed account.", i+1, len(instanceIDs), region, amiID)
								}
								alllowedAMIs[amiID] = ami
								continue // skip the rest of the checks
							}
						}

						// check to see if the AMI is from a trusted account that the user has specified
						if contains(trustedAccounts, ami.OwnerID) {
							if verbose {
								color.Green("[%d/%d][%s] %s is from a trusted account.", i+1, len(instanceIDs), region, amiID)
							}
							trustedAMIs[amiID] = ami
							continue
						}

						// check to see if the AMI is shared privately with this account (but not trusted or allowed)
						if ami.Public == "Private" {
							if verbose {
								color.Yellow("[%d/%d][%s] %s is privately shared with me but not from a trusted or allowed account.", i+1, len(instanceIDs), region, amiID)
							}
							privateSharedAMIs[amiID] = ami
							continue
						}

						color.Red("[%d/%d][%s] %s is from an unverified account.", i+1, len(instanceIDs), region, amiID)

						unverifiedAMIs[amiID] = ami
					}
				}

			}
		}
	}

	var enabledCount, auditModeCount, disabledCount int
	if !allowedAMIPermissionDenied {
		enabledCount, auditModeCount, disabledCount = countRegionsWithAllowedAmisEnabled(regions, allowedAMIStateByRegion)
	}

	// Print a summary key before the summary that defines the terms:
	fmt.Println("\nSummary Key:")
	fmt.Println("+--------------------------+-----------------------------------------------------------+")
	fmt.Println("| Term                     | Definition                                                |")
	fmt.Println("+--------------------------+-----------------------------------------------------------+")
	color.Green("| Self hosted              | AMIs from this account                                    |")
	color.Green("| Allowed AMIs             | AMIs from an allowed account per the AWS Allowed AMIs API |")
	color.Green("| Trusted AMIs             | AMIs from an trusted account per user input to this tool  |")
	color.Green("| Verified AMIs            | AMIs from Verified Accounts (Verified by Amazon)          |")
	color.Yellow("| Shared with me (Private) | AMIs shared privately with this account but NOT from a    |")
	color.Yellow("|                          | verified, trusted or allowed account. If you trust this   |")
	color.Yellow("|                          | account, add it to your Allowed AMIs API or specify it as |")
	color.Yellow("|                          | trusted in the whoAMI-scanner command line.               |")
	//color.Yellow("| Unknown                  | AMIs in use that are no longer available. The AMI may     |")
	//color.Yellow("|                          | have been deleted or made private. We can not determine   |")
	//color.Yellow("|                          | if these were served from a verified account              |")
	color.Red("| Public & Unverified      | AMIs from unverified accounts. Be cautious with these     |")
	color.Red("|                          | unless they are from accounts you control. If not from    |")
	color.Red("|                          | your accounts, look to replace these with AMIs from       |")
	color.Red("|                          | verified accounts                                         |")
	fmt.Println("+--------------------------+-----------------------------------------------------------+")

	// Output results
	fmt.Println("\nSummary:")

	if allowedAMIPermissionDenied {
		color.Cyan("    AWS's \"Allowed AMI\" config status unknown (permission denied)")
	} else {
		color.Cyan(" AWS's \"Allowed AMI\" config status by region")
		color.Cyan("                 Enabled/Audit-mode/Disabled: %d/%d/%d", enabledCount, auditModeCount, disabledCount)
	}
	color.Cyan("                             Total Instances: %d", totalInstances)
	color.Cyan("                                  Total AMIs: %d", len(processedAMIs))
	color.Green("                            Self hosted AMIs: %d", len(selfHostedAMIs))
	color.Green("                                Allowed AMIs: %d", len(alllowedAMIs))
	color.Green("                                Trusted AMIs: %d", len(trustedAMIs))
	color.Green("                               Verified AMIs: %d", len(verifiedAMIs))
	color.Yellow("               Shared with me (Private) AMIs: %d", len(privateSharedAMIs))
	//color.Yellow("                      AMIs w/ Unknown status: %d", len(unknownAMIs))
	color.Red("                    Public & Unverified AMIs: %d", len(unverifiedAMIs))

	if len(privateSharedAMIs) > 0 {
		color.Yellow("\nInstances running private shared AMIs:")
		for amiID := range privateSharedAMIs {
			for _, instance := range amiToInstanceMap[amiID] {
				fmt.Printf(" %s | %s | %s | Account: %s | Instance Name: %s | AMI Name: %s\n", amiID,
					instance.Region, instance.ID, privateSharedAMIs[amiID].OwnerID, instance.Name, privateSharedAMIs[amiID].Name)
			}
		}
	}

	if len(unknownAMIs) > 0 {
		color.Yellow("\nInstances running unknown AMIs:")
		for amiID := range unknownAMIs {
			for _, instance := range amiToInstanceMap[amiID] {
				fmt.Printf(" %s | %s | %s | Account: %s | Name: %s\n", amiID, instance.Region, instance.ID, unknownAMIs[amiID].OwnerID, instance.Name)
			}
		}
	}

	if len(unverifiedAMIs) > 0 {
		color.Red("\nInstances running AMIs from public unverified accounts:")
		for amiID := range unverifiedAMIs {
			for _, instance := range amiToInstanceMap[amiID] {
				fmt.Printf(" %s | %s | %s | Account: %s | Instance Name: %s | AMI Name: %s\n", amiID, instance.Region,
					instance.ID,
					unverifiedAMIs[amiID].OwnerID, instance.Name, unverifiedAMIs[amiID].Name)
			}
		}
	}

	if output != "" {

		file, err := os.Create(output)
		if err != nil {
			color.Red("Error creating output file: %v", err)
			os.Exit(1)
		}
		defer file.Close()

		_, err = file.WriteString("AMI ID|Region|whoAMI status|Public|Owner Alias|Owner ID|Name|Description\n")
		for _, ami := range verifiedAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Verified|%s|%s|%s|%s|%s\n", ami.ID, ami.Region, ami.Public, ami.OwnerAlias, ami.OwnerID, ami.Name, ami.Description))
		}
		for _, ami := range selfHostedAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Self hosted|%s|%s|%s|%s|%s\n", ami.ID, ami.Region, ami.Public, ami.OwnerAlias, ami.OwnerID, ami.Name, ami.Description))
		}
		for _, ami := range alllowedAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Allowed|%s|%s|%s|%s|%s\n", ami.ID, ami.Region, ami.Public, ami.OwnerAlias, ami.OwnerID, ami.Name, ami.Description))
		}
		for _, ami := range trustedAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Trusted|%s|%s|%s|%s|%s\n", ami.ID, ami.Region, ami.Public, ami.OwnerAlias, ami.OwnerID, ami.Name, ami.Description))
		}
		for _, ami := range privateSharedAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Private Shared|%s|%s|%s|%s|%s\n", ami.ID, ami.Region, ami.Public, ami.OwnerAlias, ami.OwnerID, ami.Name, ami.Description))
		}
		for _, ami := range unknownAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Unknown|Unknown|Unknown|Unknown|Unknown\n", ami.ID, ami.Region))
		}
		for _, ami := range unverifiedAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Unverified|%s|%s|%s|%s|%s\n", ami.ID, ami.Region, ami.Public, ami.OwnerAlias, ami.OwnerID, ami.Name, ami.Description))
		}
		// let the user know the file was written, but give them the full path. If the user have a full path print that, if they just gave a file name, print the full path using hte current direcotry
		// this is to make it easier for the user to know where the file was written
		if output[0] == '/' {
			color.Green("Output written to %s", output)
		} else {
			wd, _ := os.Getwd()
			color.Green("Output written to %s/%s", wd, output)
		}
	}
	// Unless all regions are enabled or in audit mode, print a message telling the user to visit https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-allowed-amis.html
	if enabledCount+auditModeCount == 0 {
		color.Red("\n[!] No regions have AWS's \"Allowed AMIs\" feature enabled or in audit mode.")
		color.Red("\tEnabling Allowed AMIs protects you against the whoAMI attack.")
		color.Red("\tVisit https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-allowed-amis.html for more information.")
	} else if enabledCount < len(regions) {
		color.Yellow("\n[!] Looks like you have started to use AWS's \"Allowed AMIs\" feature.")
		color.Yellow("\tOnly configuring \"Allowed AMIs\" in \"enabled\" mode protects you against the whoAMI attack.")
		color.Yellow("\tVisit https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-allowed-amis.html for more information.")
	}
}

// PreparePath ensures the output path is valid and all directories exist.
func PreparePath(outputPath string) (string, error) {
	var fullPath string

	// Determine if the path is absolute, relative, or just a file name
	if filepath.IsAbs(outputPath) {
		fullPath = outputPath
	} else if strings.Contains(outputPath, string(os.PathSeparator)) {
		// It's a relative path
		absPath, err := filepath.Abs(outputPath)
		if err != nil {
			return "", fmt.Errorf("failed to get absolute path: %v", err)
		}
		fullPath = absPath
	} else {
		// Just a file name; write to the current working directory
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %v", err)
		}
		fullPath = filepath.Join(cwd, outputPath)
	}

	// Ensure all directories in the path exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return "", fmt.Errorf("failed to create directories for path %s: %v", dir, err)
	}

	return fullPath, nil
}

func CheckAllowedAMIs(client *ec2.Client) (string, []string, error) {
	// Check if the region supports allowedAMIs
	GetAllowedImagesOutput, err := client.GetAllowedImagesSettings(context.TODO(), &ec2.GetAllowedImagesSettingsInput{})

	if err != nil {
		return "", nil, fmt.Errorf("failed to get allowed AMIs settings: %v", err)

	}
	var ImageCriteria []types.ImageCriterion
	var ImageProviders []string

	ImageCriteria = GetAllowedImagesOutput.ImageCriteria
	for _, ImageCriteria := range ImageCriteria {
		ImageProviders = append(ImageProviders, ImageCriteria.ImageProviders...)
	}

	return *GetAllowedImagesOutput.State, ImageProviders, nil
}

// Returns true of a string is in the given list of strings. Else false
func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

func countRegionsWithAllowedAmisEnabled(regions []string, allowedAMIStateByRegion map[string]string) (int, int, int) {
	var enabledCount, auditModeCount, disabledCount int
	for _, region := range regions {
		switch allowedAMIStateByRegion[region] {
		case "enabled":
			enabledCount++
		case "audit-mode":
			auditModeCount++
		default:
			disabledCount++
		}
	}
	return enabledCount, auditModeCount, disabledCount
}
