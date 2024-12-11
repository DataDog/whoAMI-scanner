package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"os"
	"path/filepath"
	"strings"
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

var verbose bool

func main() {
	// Parse command-line arguments
	var profile string
	var region string
	var output string
	flag.StringVar(&profile, "profile", "", "AWS profile name [Default: Default profile, IMDS, or environment variables]")
	flag.StringVar(&region, "region", "", "AWS region [Default: All regions]")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output for detailed status updates")
	flag.StringVar(&output, "output", "", "Specify file path/name for csv report)")
	flag.Parse()

	if output != "" {
		PreparePath(output)
	}

	if verbose {
		fmt.Println("[*] Verbose mode enabled.")
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
	privateAMIs := make(map[string]AMI)
	totalInstances := 0

	fmt.Println("\nStarting AMI analysis...")
	// Loop through regions
	for _, region := range regions {
		if verbose {
			fmt.Printf("[*] Checking region %s\n", region)
		}
		cfg.Region = region
		ec2Client := ec2.NewFromConfig(cfg)

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
			}
		}

		totalInstances += len(instanceIDs)
		if len(instanceIDs) == 0 {
			continue
		}

		for i, instanceID := range instanceIDs {
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
					if len(imageOutput.Images) == 0 {
						color.Yellow("[%d/%d][%s] %s has been deleted or made private.", i+1, len(instanceIDs), region, amiID)
						unknownAMIs[amiID] = AMI{
							ID:          amiID,
							Region:      region,
							OwnerAlias:  "Unknown",
							Public:      "Unknown",
							OwnerID:     "Unknown",
							Name:        "Unknown",
							Description: "Unknown",
						}
						continue
					}
					var publicString string
					for _, image := range imageOutput.Images {

						if *image.Public {
							publicString = "Public"
						} else {
							publicString = "Private"
						}
						ami := AMI{
							ID:          amiID,
							Region:      region,
							OwnerAlias:  ptr.ToString(image.ImageOwnerAlias),
							OwnerID:     ptr.ToString(image.OwnerId),
							Name:        ptr.ToString(image.Name),
							Description: ptr.ToString(image.Description),
							Public:      publicString,
						}

						if *image.Public {
							if ami.OwnerAlias != "" {
								if ami.OwnerAlias == "amazon" {
									if verbose {
										color.Green("[%d/%d][%s] %s is a community AMI from a verified account.", i+1, len(instanceIDs), region, amiID)
									}
									verifiedAMIs[amiID] = ami
								} else if ami.OwnerAlias == "self" {
									if verbose {
										color.Green("[%d/%d][%s] %s is private.", i+1, len(instanceIDs), region, amiID)
									}
									ami.OwnerAlias = "self"
									privateAMIs[amiID] = ami
								}
							} else {
								color.Red("[%d/%d][%s] %s is a community AMI from an unverified account.", i+1, len(instanceIDs), region, amiID)
								unverifiedAMIs[amiID] = ami
							}
						} else {
							if verbose {
								color.Green("[%d/%d][%s] %s is private.", i+1, len(instanceIDs), region, amiID)
							}
							privateAMIs[amiID] = ami
						}
					}
				}
			}
		}
	}

	// Print a summary key before the summary that defines the terms:
	fmt.Println("\nSummary Key:")
	fmt.Println("+--------------------+-----------------------------------------------------------+")
	fmt.Println("| Term               | Definition                                                |")
	fmt.Println("+--------------------+-----------------------------------------------------------+")
	color.Green("| Private            | AMIs that are served from this account that are private   |")
	color.Green("| Public & Verified  | AMIs from Verified Accounts (Verified from Amazon)        |")
	color.Yellow("| Unknown            | AMIs in use that are no longer available. The AMI may     |")
	color.Yellow("|                    | have been deleted or made private. We can not determine   |")
	color.Yellow("|                    | if these were served from a verified account              |")
	color.Red("| Public & Unverified| AMIs from unverified accounts. Be cautious with these     |")
	color.Red("|                    | unless they are from accounts you control. If not from    |")
	color.Red("|                    | your accounts, look to replace these with AMIs from       |")
	color.Red("|                    | verified accounts                                         |")
	fmt.Println("+------------------+-------------------------------------------------------------+")

	// Output results
	fmt.Println("\nSummary:")
	color.Cyan("          Total Instances: %d", totalInstances)
	color.Cyan("               Total AMIs: %d", len(processedAMIs))
	color.Green("            Private AMIs: %d", len(privateAMIs))
	color.Green("  Public & Verified AMIs: %d", len(verifiedAMIs))
	color.Yellow("  AMIs w/ Unknown status: %d", len(unknownAMIs))
	color.Red("Public & Unverified AMIs: %d", len(unverifiedAMIs))

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
		for _, ami := range privateAMIs {
			_, err = file.WriteString(fmt.Sprintf("%s|%s|Private|%s|%s|%s|%s|%s\n", ami.ID, ami.Region, ami.Public, ami.OwnerAlias, ami.OwnerID, ami.Name, ami.Description))
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
